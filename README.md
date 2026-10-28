# Static-Decryptor
Exploring ways to decrypt Roblox, at disk.

Made By: mx and pibbly <3

---

In Roblox there are two very important files: `RobloxPlayerBeta.exe` and `RobloxPlayerBeta.dll`.
`RobloxPlayerBeta.dll` is where decryption happens and at runtime it is reached through an exception type control flow that ends up in `KiUserExceptionDispatcher`

We will be studying **static decryption**: reading the file on disk and decrypting it without ever launching the game.

---

## 1. Sections

To begin, the binary is split into **sections**. You get offsets, structs and encrypted data out of these. Most of the import memory lives in `.text`.

`.text` is the code section. It is split into **pages** and most of those pages are protected and encrypted

`.text` is also split into **2 MB chunks** which I call **BANDS**

So the layout looks like this:

```
RobloxPlayerBeta.dll
│
├── .text              ← the code, encrypted
│   ├── band 0         ← 2 MB
│   ├── band 1         ← 2 MB
│   ├── band 2         ← 2 MB
│   ├── ...
│   └── band 49        ← 2 MB (last one is a bit short)
│
└── other sections     ← .rdata, .data, .reloc, ...
```

---

## 2. Dictionary

wrote this up so you know my definitions and meanings on things

| Term | Means |
| --- | --- |
| **section** | one big section of the file. `.text` is one, `.rdata` is another |
| **`.text`** | section that holds the code |
| **page** | 4 KB (`0x1000`) of mem |
| **band** | 2 MB (`0x200000`) of `.text` just needed a word for a chunk that shares a handler and then the set of frame values |
| **band index** (`k`) | which number band were using |
| **band base** | location of where the band begins |
| **band span** | how long each band is and the last band is slightly different |
| **RVA** | relative virtual mem address |
| **VA** | virtual address mem |
| **image base** | dll image address |
| **`vs`** | virtual size how many bytes in mem |
| **`raw_size`** | how much size it takes up on physical mem |
| **handler** | function that does the actual decrypting each band uses it |
| **dispatch** | the chain of cmp (compare) values that work out page decryption |
| **frame** | area where the per band values are |
| **encrypted / protected** | code isnt readable roblox is protecting that |
| **ceil** | ceiling we use that in python to round up |

```
text.va   = 0x1000
text.vs   = 0x63E4000 <- real size
raw_size  = 0x63E4000
```

---

## 3. The band formula

```
BAND_STRIDE = 0x200000     ; 2 MB distance from one band to the next
TEXT_BASE   = 0x1000       ; where .text starts

band_k_lo   = TEXT_BASE + k * BAND_STRIDE
band_k_hi   = TEXT_BASE + (k + 1) * BAND_STRIDE
band_count  = ceil(text.vs / BAND_STRIDE)
```
`k` is zero-based, so band 0 is the first one.

The formula also runs backwards. Give it an address, get the band index back:

```
k = (rva - TEXT_BASE) / BAND_STRIDE        ; integer division, throw the remainder away
```

real addresses usage:

```
0x1000     -> (0x1000    - 0x1000) / 0x200000 = 0    -> band 0
0x200000   -> (0x200000  - 0x1000) / 0x200000 = 0    -> still band 0
0x201000   -> (0x201000  - 0x1000) / 0x200000 = 1    -> band 1
0x5C01000  -> (0x5C01000 - 0x1000) / 0x200000 = 46   -> band 46
0x63E5000  -> (0x63E5000 - 0x1000) / 0x200000 = 49   -> band 49 the last one
```

For this build:

```
text.va     = 0x1000
text.vs     = 0x63E4000 (how many bytes)
band_count  = ceil(0x63E4000 / 0x200000) = 50
last band   = band 49 base 0x6201000
```

remember: start band 1 at 0x201000 not 0x200000 when going up

---

## 4. Selecting a band

The dispatcher looks at the addr of a page and asks: is this inside this band?

```
offset = rva - band_base
if offset <= band_span - 1:
    goto band_handler
```

In words:

1. Take the page addr
2. Subtract the bands base.
3. If whats left is smaller than the band's size it's in that band 🤑

Which assembly turns into:

```asm
add rdx, -band_base        ; the band base (negative constant)
cmp rdx, band_span - 1     ; compare against the last offset inside the band
jbe band_handler           ; inside jump to that band
```

example assembly <3

```asm
0x4CF784  48 8B 95 B0 0C 00 00   mov rdx, qword ptr [rbp + 0xcb0]   ; load the page RVA from the frame
0x4CF78B  48 81 C2 00 F0 DF FF   add rdx, -0x201000                 ; subtract band 1 base
0x4CF792  48 81 FA FF FF 1F 00   cmp rdx, 0x1fffff                  ; is this inside the band
0x4CF799  0F 86 29 0C 00 00      jbe 0x4d03c8                       ; yes (then boom you got the handler)
```

---

## 5. The two span values

Only two span values there called show up throughout most of robloxs builds but:

```
0x1FFFFF    ; full band
0x1E3FFF    ; final band thats just partial (happens because the final isnt 2MB exactly it changes)
```
---

## 6. Not every band is readable

most bands you cant get simply and there build out of the overall frames

```asm
0x4CF79F  B8 56 62 B0 EC         mov eax, 0xecb06256                ; seed value
0x4CF7A4  03 85 58 0D 00 00      add eax, dword ptr [rbp + 0xd58]   ; mix to a frame value
0x4CF7AA  48 8B 8D 68 10 00 00   mov rcx, qword ptr [rbp + 0x1068]  ; rotation amount comes from the frame
0x4CF7B1  D3 C8                  ror eax, cl                        ; rotate by it
0x4CF7B3  69 C0 CB 3F 14 3E      imul eax, eax, 0x3e143fcb          ; multiply
0x4CF7B9  05 0F 0F 3A 6F         add eax, 0x6f3a0f0f                ; add a constant value
0x4CF7BE  48 63 D0               movsxd rdx, eax                    ; widen to 64-bit signed
0x4CF7C1  48 03 95 B0 0C 00 00   add rdx, qword ptr [rbp + 0xcb0]   ; add the page RVA back
0x4CF7C8  48 81 FA FF FF 1F 00   cmp rdx, 0x1fffff                  ; same band test as before (look for this pls)
0x4CF7CF  0F 86 4A 23 00 00      jbe 0x4d1b1f                       ; yes then once again we got this band's handler
```

thats the full lesson for bands atleast heres more formulas as well you can use for reference I will only leak a few as I dont feel like leaking all the methods:

lets move onto getting more information

---

## 7. Keys

every page gets its own 32 byte key

```
key_count       = how many keys there are (8196 in this build)
key_index(rva)  = (rva >> 12) % key_count
key_offset(rva) = key_index * 32
```

`rva >> 12` is the page number not the band number

the keys just keep counting up they dont start over when a new band starts

```
band 0    pages    1 .. 512      uses keys    1 .. 512
band 1    pages  513 .. 1024     uses keys  513 .. 1024
band 49   pages 25089 .. 25572   uses keys  501 .. 984
```

to find how many keys there are you look for the wrap being done as a multiply

```asm
48 B9 AB AA AA AA AA AA AA AA   movabs rcx, 0xAAAAAAAAAAAAAAAB
48 0F AF C1                     imul   rax, rcx
48 F7 E2                        mul    rdx
48 C1 E2 05                     shl    rdx, 5          ; * 32 so rdx was a key number
```

that multiply by 32 at the end tells you the value before it was a key number

you can turn the magic number back into a count like this

```
lower = ceil(2^64 / value)
upper = floor((2^64 - 1) / (value - 1))
answer = lower if lower == upper and 1024 <= lower <= 65536 else none
```

0xAAAAAAAAAAAAAAAB comes back as 3 which is only part of a fraction not the real count so keep following where it gets used

reading the key itself

```asm
66 0F 6F 08            movdqa xmm1, xmmword ptr [rax]
66 0F 6F 50 10         movdqa xmm2, xmmword ptr [rax + 0x10]
```

two loads of 16 bytes sitting 16 bytes apart thats how you spot which two xmm registers the handler reads

---

## 8. The frame

the frame is where the handler keeps its numbers for each band

```
page number goes here        0xcb0
page address goes here       0x15f0
second copy of the number    0x15f8

frame has to be at least 0x1600 bytes
```

```asm
48 8B 95 B0 0C 00 00   mov rdx, qword ptr [rbp + 0xcb0]   ; page number
48 8B 8D F0 15 00 00   mov rcx, qword ptr [rbp + 0x15f0]   ; page address
48 8B 85 F8 15 00 00   mov rax, qword ptr [rbp + 0x15f8]   ; second copy
```

those two sit right at the top of a 0x1600 frame so anything smaller and the handler reads past the end

picking which bands numbers to use

```
start with the basic set
find the biggest band start that is still at or below the page
if the page is less than 0x200000 past it use that bands numbers
```

---

## 9. Pages and records

```
page            = rva >> 12
where in page   = rva & 0xfff
total pages     = ceil(text.vs / 0x1000)     ; 25572
pages per band  = 0x200000 / 0x1000          ; 512
pages in last   = ceil(0x1E4000 / 0x1000)    ; 484
```

49 * 512 + 484 should come to 25572 if it dont then the sizes got worked out wrong somewhere

some versions keep 384 bytes of record for every page

```asm
48 C1 E8 0C               shr    rax, 0xc         ; page number
25 FF 0F 00 00            and    eax, 0xfff       ; where in the page
48 69 C0 80 01 00 00      imul   rax, rax, 0x180  ; * 384
```

---

## 10. The start record

before the handler runs it reads a starting number out of a small record

```
which slot  = record[0x96]
encoded[i]  = record[0xA4 + which slot*4 + i]        i = 0..3

start value = LE32( ROL8(NOT encoded[i], 4) for i = 0..3 )
```

if all four encoded bytes are 0xFF the start value comes out as 0 because NOT 0xFF gives 0x00

the code that fills the record in always leaves it that way

```
new slot = (old slot + 1) % 7
fills in = 0xFFFFFFFF
```

```asm
41 0F B6 87 96 00 00 00         movzx  eax, byte ptr [r15 + 0x96]        ; which slot
41 0F B6 84 07 A4 00 00 00      movzx  eax, byte ptr [r15 + rax + 0xa4]  ; encoded byte
F7 D0                            not    eax
C0 C0 04                         rol    al, 4                              ; swap the two halves
41 88 44 07 01                   mov    byte ptr [r15 + rax + 1], al       ; decoded byte
```

---

## 11. One page start to finish

```
page   = 0x100001000
frame  = 0x110004000
stack  = 0x110000000
gs     = 0x120000000
```

```asm
49 B9 00 10 00 00 01 00 00 00   movabs r9, 0x100001000     ; page
```

```
1  put the encrypted page at          page
2  write the page number to           frame + 0xcb0
3  write the page address to          frame + 0x15f0
4  load the key halves into           xmm[key0] and xmm[key1]
5  jump to the band handler
6  run until all 4096 bytes of page are written
```
