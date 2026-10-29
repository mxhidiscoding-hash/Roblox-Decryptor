# Static-Decryptor

Exploring ways to decrypt Roblox, at disk.

Made By: mxhid

pibbly <3

---

In Roblox there are two very important files: `RobloxPlayerBeta.exe` and `RobloxPlayerBeta.dll`.

The DLL is where the decryption code lives. The EXE's `.text` section is the encrypted code we want to decrypt. We pull what we need out of the DLL, then use it to decrypt the `.text` pages in the EXE, all from disk, without launching the game.

---

## 1. Two sections that matter

```
RobloxPlayerBeta.dll              RobloxPlayerBeta.exe
│                                 │
└── .byfron   <- SOURCE           └── .text   <- TARGET
    cipher routine                    encrypted code, split into
    band dispatch                     pages (4 KB) and bands (2 MB)
    band frame values
    key blob
    start record
```

Everything we need comes from `.byfron` in the DLL. Everything we act on is `.text` in the EXE. Do not hardcode any of it. Find it in the DLL and read it out.

---

## 2. Words

| Term | Means |
| --- | --- |
| **source DLL** | `RobloxPlayerBeta.dll`, where `.byfron` lives |
| **target EXE** | `RobloxPlayerBeta.exe`, its `.text` is what we decrypt |
| **page** | 4 KB (`0x1000`) of the EXE's `.text` |
| **band** | 2 MB (`0x200000`) of the EXE's `.text`, shares one handler and one set of frame values |
| **handler** | a function in the DLL that decrypts one page |
| **frame** | a buffer the handler reads its per band values from |
| **key blob** | 32 byte keys, stored in the DLL |

---

## 3. Bands

Cut `.text` into 2 MB chunks and you have bands:

```
band starts at  text.va + k * 0x200000
```

To go the other way, from an RVA to a band index:

```
k = (rva - text.va) / 0x200000     (integer division)
```

The last band is shorter, because `.text` does not end on a clean 2 MB boundary.

Do not hardcode `0x1000` or `0x200000`. Read them from the EXE's `.text` section header (`va`, `vs`) and compute the rest.

---

## 4. Finding the dispatch chain in the DLL

Open `.byfron` and look for a long sequence of `cmp`/`jbe` pairs. Each pair is one band. The pattern is always the same shape:

```asm
add rdx, <negative band base>      ; subtract the band's start RVA
cmp rdx, <band span 1>           ; is the page inside this band?
jbe <handler address>              ; yes → this band's handler
```

In bytes:

```asm
48 81 C2 XX XX XX XX     add    rdx, <imm32>       ; band base, negated
48 81 FA XX XX XX XX     cmp    rdx, <imm32>       ; span 1
0F 86 XX XX XX XX        jbe    <handler>
```

Scan `.byfron` for that byte pattern repeated back to back. The imm32 in the `add` is `band_base` negated, so `band_base = imm32 negated`. The imm32 in the `cmp` is `span` minus 1. The `jbe` target is the handler RVA for that band.

You should see one such block per band. Count them, that is your band count. The band with `span 1 == 0x1FFFFF` is a full band; the one with a smaller value is the last one.

---

## 5. Finding the frame slots in the DLL

Inside the handler, look for loads of the form `mov reg, [rbp + disp32]`:

```asm
48 8B 95 B0 0C 00 00     mov    rdx, qword ptr [rbp + 0xCB0]   ; page RVA
48 8B 8D F0 15 00 00     mov    rcx, qword ptr [rbp + 0x15F0]  ; page buffer address
48 8B 85 F8 15 00 00     mov    rax, qword ptr [rbp + 0x15F8]  ; second copy of page RVA
```

The (`0xCB0`, `0x15F0`, `0x15F8`) are the frame slots you fill in before calling the handler. Do not assume those numbers. Extract them from the handler's disassembly each time. They change between builds.

The frame buffer must be at least `0x15F8 + 8` bytes; round up to a page.

---

## 6. Finding the keys in the DLL

Look for the wrap then multiply that turns a page number into a key offset:

```asm
48 B9 AB AA AA AA AA AA AA AA   movabs rcx, 0xAAAAAAAAAAAAAAAB
48 0F AF C1                     imul   rax, rcx
48 F7 E2                        mul    rdx
48 C1 E2 05                     shl    rdx, 5          ; * 32 → key offset
```

The final `shl rdx, 5` confirms the value before it was a key index. Recover the key count from the magic multiply:

```
lower  = ceil(2^64 / value)
upper  = floor((2^64 1) / (value 1))
count  = lower if lower == upper and 1024 <= lower <= 65536 else none
```

Then immediately after, the two `movdqa` loads of the key halves tell you which XMM registers the handler uses:

```asm
66 0F 6F 08            movdqa xmm1, xmmword ptr [rax]
66 0F 6F 50 10         movdqa xmm2, xmmword ptr [rax + 0x10]
```

Here the two registers are `xmm1` and `xmm2`. Read them from the bytes. The ModRM byte after `0F 6F` encodes which register.

Locate the key blob base: it is the `rax` the index is added to just before these loads. Its file offset minus the section's `raw` gives you the key blob RVA.

---

## 7. The start record

The start record is a small table the handler reads a slot from before decrypting:

```asm
41 0F B6 87 96 00 00 00         movzx  eax, byte ptr [r15 + 0x96]        ; slot index
41 0F B6 84 07 A4 00 00 00      movzx  eax, byte ptr [r15 + rax + 0xa4]  ; encoded byte
F7 D0                            not    eax
C0 C0 04                         rol    al, 4
41 88 44 07 01                   mov    byte ptr [r15 + rax + 1], al
```

The base register here (`r15`) points at the start record. The displacements `0x96` and `0xA4` are read from this instruction. Do not guess them. Decode the record the same way the instruction does: `NOT` the byte, `ROL` by 4, assemble four bytes little endian.

---

## 8. Decrypting one page

For each page in the EXE's `.text`:

```
rva    = page RVA
band   = (rva - text.va) / 0x200000
frame  = lookup frame values for band
key    = (rva >> 12) % count * 32
```

Then set up and call the handler:

```asm
mov     qword ptr [frame + RVA],      rva
mov     qword ptr [frame + Page],     buffer
mov     qword ptr [frame + PageSlot], rva
movdqa  xmm[low],  [Key + Slot]
movdqa  xmm[high], [Key + Slot + 0x10]

; fill remaining frame slots from the band's row in the DLL
; (a lot of junk and opaque predicates happen in here)

call DecryptEntry
; run until all 4096 bytes of buffer are written
```

---

## 9. Putting it together

```
parse DLL → find .byfron
extract: cipherEntry, band dispatch table (base, span, handler RVA per band),
         frame slots, key blob, key count, key XMM regs, start record

parse EXE → find .text

for each page in .text:
    rva   = text.va + page_offset
    band  = (rva - text.va) / 0x200000
    key   = keys[(rva >> 12) % key_count]
    run handler with band values + key + page

write decrypted .text back to disk
```

That is static decryption.

---

## 10. What is left

To make it fully runnable you still need to handle int3 branches, imports and exports. But the page decryption loop above is the core of it.
e.g this explains just a part of the encryption, SIMD128, other then that and everything will not be explained.

justmagic and bitdancer, please update the encryption, this is getting boring.

Discord: mxhidk, Mxhid
