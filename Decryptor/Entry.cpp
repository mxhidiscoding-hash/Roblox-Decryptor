#define NOMINMAX
#define WIN32_LEAN_AND_MEAN

#include "Logger.hpp"
#include "Offsets.h"
#include "Common.h"
// #include "JccResolver.h"
// #include "Pdata.h"
// #include "Rebuild.h"

#include <unicorn/unicorn.h>

#include <Windows.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#define Version "v3"

namespace
{
    bool Read(const std::string& Path, std::vector<uint8_t>& Out)
    {
        std::ifstream Stream
        (
            Path,
            std::ios::binary
        );

        if (!Stream)
            return false;

        Stream.seekg
        (
            0,
            std::ios::end
        );

        const std::streamoff Length = Stream.tellg();

        if (Length <= 0)
            return false;

        Out.resize
        (
            static_cast<size_t>(Length)
        );

        Stream.seekg
        (
            0,
            std::ios::beg
        );

        Stream.read
        (
            reinterpret_cast<char*>(Out.data()),
            Length
        );

        return Stream.gcount() == Length;
    }

    bool Sections(MX::PE& Image)
    {
        const std::vector<uint8_t>& File = Image.File;

        if (File.size() < 0x40)
            return false;

        uint16_t Mz = 0;

        std::memcpy
        (
            &Mz,
            File.data(),
            2
        );

        if (Mz != IMAGE_DOS_SIGNATURE)
            return false;

        uint32_t Offset = 0;

        std::memcpy
        (
            &Offset,
            File.data() + 0x3C,
            4
        );

        if (static_cast<size_t>(Offset) + 24 > File.size())
            return false;

        uint32_t Signature = 0;

        std::memcpy
        (
            &Signature,
            File.data() + Offset,
            4
        );

        if (Signature != IMAGE_NT_SIGNATURE)
            return false;

        const size_t Header = static_cast<size_t>(Offset) + 24;

        Image.NT = Offset;
        Image.OPT = Header;

        uint16_t Magic = 0;

        std::memcpy
        (
            &Magic,
            File.data() + Header,
            2
        );

        if (Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            std::memcpy
            (
                &Image.Base,
                File.data() + Header + 24,
                8
            );

            std::memcpy
            (
                &Image.Headers,
                File.data() + Header + 60,
                4
            );

            std::memcpy
            (
                &Image.Dirs,
                File.data() + Header + 108,
                4
            );

            Image.DirOff = Header + 112;
        }
        else if (Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        {
            uint32_t Base32 = 0;

            std::memcpy
            (
                &Base32,
                File.data() + Header + 28,
                4
            );

            Image.Base = Base32;

            std::memcpy
            (
                &Image.Headers,
                File.data() + Header + 56,
                4
            );

            std::memcpy
            (
                &Image.Dirs,
                File.data() + Header + 92,
                4
            );

            Image.DirOff = Header + 96;
        }
        else
        {
            return false;
        }

        if (!Image.Headers)
            return false;

        uint16_t Count = 0;
        uint16_t Optional = 0;

        std::memcpy
        (
            &Count,
            File.data() + Offset + 6,
            2
        );

        std::memcpy
        (
            &Optional,
            File.data() + Offset + 20,
            2
        );

        size_t Cursor = Header + Optional;

        Image.Sections.clear();

        for (uint16_t Index = 0; Index < Count; ++Index)
        {
            if (Cursor + 40 > File.size())
                return false;

            MX::Section Section;

            std::memcpy
            (
                Section.Name,
                File.data() + Cursor,
                8
            );

            Section.Name[8] = '\0';

            std::memcpy
            (
                &Section.VSize,
                File.data() + Cursor + 8,
                4
            );

            std::memcpy
            (
                &Section.VA,
                File.data() + Cursor + 12,
                4
            );

            std::memcpy
            (
                &Section.RawSize,
                File.data() + Cursor + 16,
                4
            );

            std::memcpy
            (
                &Section.Raw,
                File.data() + Cursor + 20,
                4
            );

            std::memcpy
            (
                &Section.Flags,
                File.data() + Cursor + 36,
                4
            );

            Image.Sections.push_back
            (
                Section
            );

            Cursor += 40;
        }

        return !Image.Sections.empty();
    }

    bool Map(MX::PE& Image)
    {
        size_t Largest = 0;

        for (const MX::Section& Section : Image.Sections)
        {
            Largest = (std::max)
                (
                    Largest,
                    static_cast<size_t>(Section.VA) +
                    (std::max)
                    (
                        static_cast<size_t>(Section.VSize),
                        static_cast<size_t>(Section.RawSize)
                        )
                    );
        }

        Image.Image.assign
        (
            Largest,
            0
        );

        const size_t HeaderBytes = (std::min)
            (
                Image.File.size(),
                static_cast<size_t>(Image.Headers)
                );

        std::memcpy
        (
            Image.Image.data(),
            Image.File.data(),
            HeaderBytes
        );

        for (const MX::Section& Section : Image.Sections)
        {
            size_t CopyLength = static_cast<size_t>(Section.RawSize);

            if (static_cast<size_t>(Section.Raw) < Image.File.size())
                CopyLength = (std::min)(CopyLength, Image.File.size() - Section.Raw);

            if (static_cast<size_t>(Section.VA) < Image.Image.size())
                CopyLength = (std::min)(CopyLength, Image.Image.size() - Section.VA);

            if (!CopyLength)
                continue;

            std::memcpy
            (
                Image.Image.data() + Section.VA,
                Image.File.data() + Section.Raw,
                CopyLength
            );
        }

        return true;
    }

    bool EmuImage(const MX::PE& Loader, std::vector<uint8_t>& Out)
    {
        Out.assign
        (
            static_cast<size_t>(Offsets::ImageSize),
            0
        );

        for (const MX::Section& Section : Loader.Sections)
        {
            if (Section.VA >= Offsets::ImageSize)
                continue;

            size_t CopyLength = Section.RawSize;

            if (CopyLength > Offsets::ImageSize - Section.VA)
                CopyLength = static_cast<size_t>(Offsets::ImageSize - Section.VA);

            if (static_cast<size_t>(Section.Raw) < Loader.File.size())
                CopyLength = (std::min)(CopyLength, Loader.File.size() - Section.Raw);

            if (!CopyLength)
                continue;

            std::memcpy
            (
                Out.data() + Section.VA,
                Loader.File.data() + Section.Raw,
                CopyLength
            );
        }

        return true;
    }

    const MX::Section* Code(const MX::PE& Image)
    {
        const MX::Section* Code = nullptr;

        for (const MX::Section& Section : Image.Sections)
        {
            if (Section.VSize < 0x10000 || !(Section.Flags & IMAGE_SCN_CNT_CODE))
                continue;

            if (!Code || Section.VSize > Code->VSize)
                Code = &Section;
        }

        return Code;
    }

    double Entropy(const uint8_t* Data, size_t Length)
    {
        if (!Data || !Length)
            return 0.0;

        size_t Histogram[256] = {};

        for (size_t Index = 0; Index < Length; ++Index)
            ++Histogram[Data[Index]];

        double Result = 0.0;

        for (int Byte = 0; Byte < 256; ++Byte)
        {
            if (!Histogram[Byte])
                continue;

            const double Weight = static_cast<double>(Histogram[Byte]) / static_cast<double>(Length);

            Result -= Weight * std::log2
            (
                Weight
            );
        }

        return Result;
    }

    bool Pdata(const MX::PE& Image, const MX::Section* Section, const MX::Section* Code)
    {
        if (!Section || !Code || Section->VSize < 12 || (Section->VSize % 12) != 0)
            return false;

        if (static_cast<size_t>(Section->VA) + Section->VSize > Image.Image.size())
            return false;

        const uint8_t* Data = Image.Image.data() + Section->VA;
        const size_t Count = Section->VSize / 12;
        const uint32_t Low = Code->VA;
        const uint32_t High = Code->VA + Code->VSize;

        uint32_t Previous = 0;

        for (size_t Index = 0; Index < Count; ++Index)
        {
            uint32_t Begin = 0;
            uint32_t End = 0;
            uint32_t Unwind = 0;

            std::memcpy
            (
                &Begin,
                Data + Index * 12,
                4
            );

            std::memcpy
            (
                &End,
                Data + Index * 12 + 4,
                4
            );

            std::memcpy
            (
                &Unwind,
                Data + Index * 12 + 8,
                4
            );

            if (Begin >= End || Begin < Low || End > High || !Unwind || Unwind >= Image.Image.size())
                return false;

            if (Index && Begin < Previous)
                return false;

            Previous = End;
        }

        return true;
    }

    struct Emulator
    {
        uc_engine* Cpu = nullptr;
        uc_context* Snapshot = nullptr;
        std::vector<uint8_t> Original;
        std::vector<uint8_t> Used;
        uint64_t Bad = 0;
    };

    Emulator Engine;

    void OnStop(uc_engine* Cpu, uint64_t Address, uint32_t, void*)
    {
        if
            (
                Address == Offsets::Image + Offsets::End ||
                Address < Offsets::Image + Offsets::Start ||
                Address > Offsets::Image + Offsets::Guard
                )
        {
            uc_emu_stop
            (
                Cpu
            );
        }
    }

    bool OnFault(uc_engine* Cpu, uc_mem_type, uint64_t, int, int64_t, void*)
    {
        uc_emu_stop
        (
            Cpu
        );

        return false;
    }

    void OnWrite(uc_engine* Cpu, uc_mem_type, uint64_t Address, int Length, int64_t, void*)
    {
        if (Length <= 0 || !Engine.Cpu)
            return;

        uint64_t End = Address + static_cast<uint64_t>(Length);

        if (End > Offsets::Image + Offsets::ImageSize)
            End = Offsets::Image + Offsets::ImageSize;

        uint64_t Page = Address & ~0xFFFull;

        if (Page < Offsets::Image)
            Page = Offsets::Image;

        for (; Page < End; Page += Offsets::Size)
        {
            const size_t Index = static_cast<size_t>((Page - Offsets::Image) >> 12);

            if (Index < Engine.Used.size())
                Engine.Used[Index] = 1;
        }
    }

    bool Open(std::vector<uint8_t>&& Data)
    {
        Engine.Original = std::move
        (
            Data
        );

        Engine.Used.assign
        (
            static_cast<size_t>(Offsets::ImageSize / Offsets::Size),
            0
        );

        uc_err Error = uc_open
        (
            UC_ARCH_X86,
            UC_MODE_64,
            &Engine.Cpu
        );

        if (Error != UC_ERR_OK || !Engine.Cpu)
        {
            Logger::Error
            (
                "uc_open failed: %s",
                uc_strerror(Error)
            );

            return false;
        }

        if
            (
                uc_context_alloc
                (
                    Engine.Cpu,
                    &Engine.Snapshot
                ) != UC_ERR_OK ||
                uc_context_save
                (
                    Engine.Cpu,
                    Engine.Snapshot
                ) != UC_ERR_OK
                )
        {
            Logger::Error
            (
                "uc_context baseline failed"
            );

            return false;
        }

        const bool Mapped =
            uc_mem_map
            (
                Engine.Cpu,
                Offsets::Image,
                Offsets::ImageSize,
                UC_PROT_ALL
            ) == UC_ERR_OK &&
            uc_mem_map
            (
                Engine.Cpu,
                Offsets::Buffer,
                0x3000,
                UC_PROT_ALL
            ) == UC_ERR_OK &&
            uc_mem_map
            (
                Engine.Cpu,
                Offsets::MaxFrame,
                Offsets::Frame::Size,
                UC_PROT_ALL
            ) == UC_ERR_OK &&
            uc_mem_map
            (
                Engine.Cpu,
                Offsets::Thread,
                0x3000,
                UC_PROT_ALL
            ) == UC_ERR_OK;

        if
            (
                !Mapped ||
                uc_mem_write
                (
                    Engine.Cpu,
                    Offsets::Image,
                    Engine.Original.data(),
                    Offsets::ImageSize
                ) != UC_ERR_OK
                )
        {
            Logger::Error
            (
                "uc_mem_map/write(image) failed"
            );

            return false;
        }

        uc_hook FaultHook = 0;
        uc_hook WriteHook = 0;
        uc_hook UntilHook = 0;
        uc_hook BelowHook = 0;
        uc_hook AboveHook = 0;

        uc_hook_add
        (
            Engine.Cpu,
            &FaultHook,
            UC_HOOK_MEM_UNMAPPED,
            (void*)&OnFault,
            nullptr,
            1,
            0
        );

        uc_hook_add
        (
            Engine.Cpu,
            &WriteHook,
            UC_HOOK_MEM_WRITE,
            (void*)&OnWrite,
            nullptr,
            Offsets::Image,
            Offsets::Image + Offsets::ImageSize - 1
        );

        uc_hook_add
        (
            Engine.Cpu,
            &UntilHook,
            UC_HOOK_CODE,
            (void*)&OnStop,
            nullptr,
            Offsets::Image + Offsets::End,
            Offsets::Image + Offsets::End
        );

        uc_hook_add
        (
            Engine.Cpu,
            &BelowHook,
            UC_HOOK_CODE,
            (void*)&OnStop,
            nullptr,
            Offsets::Image,
            Offsets::Image + Offsets::Start - 1
        );

        uc_hook_add
        (
            Engine.Cpu,
            &AboveHook,
            UC_HOOK_CODE,
            (void*)&OnStop,
            nullptr,
            Offsets::Image + Offsets::Guard,
            Offsets::Image + Offsets::ImageSize - 1
        );

        return true;
    }

    void Close()
    {
        if (Engine.Snapshot)
        {
            uc_context_free
            (
                Engine.Snapshot
            );
        }

        Engine.Snapshot = nullptr;

        if (Engine.Cpu)
        {
            uc_close
            (
                Engine.Cpu
            );
        }

        Engine.Cpu = nullptr;
    }

    bool Decrypt(uint64_t Rva, const uint8_t* Key, std::vector<uint8_t>& Image, uint64_t& Errors)
    {
        uc_engine* Cpu = Engine.Cpu;

        if (Engine.Snapshot)
        {
            uc_context_restore
            (
                Cpu,
                Engine.Snapshot
            );
        }

        for (size_t Index = 0; Index < Engine.Used.size(); ++Index)
        {
            if (!Engine.Used[Index])
                continue;

            const uint64_t Address = Offsets::Image + (static_cast<uint64_t>(Index) << 12);

            uc_mem_write
            (
                Cpu,
                Address,
                Engine.Original.data() + (Index << 12),
                Offsets::Size
            );

            Engine.Used[Index] = 0;
        }

        static const uint8_t Zeroes[0x10000] = {};

        uc_mem_write
        (
            Cpu,
            Offsets::Buffer,
            Zeroes,
            0x3000
        );

        uc_mem_write
        (
            Cpu,
            Offsets::Thread,
            Zeroes,
            0x3000
        );

        uint8_t InputPage[Offsets::Size] = {};

        if (Rva < Image.size())
        {
            const size_t Take = (std::min)
                (
                    static_cast<size_t>(Offsets::Size),
                    Image.size() - static_cast<size_t>(Rva)
                    );

            std::memcpy
            (
                InputPage,
                Image.data() + Rva,
                Take
            );
        }

        uc_mem_write
        (
            Cpu,
            Offsets::Buffer + Offsets::Size,
            InputPage,
            Offsets::Size
        );

        uint8_t Frame[Offsets::Frame::Size] = {};

        const auto Write = [&Frame](uint64_t Offset, uint64_t Value)
            {
                std::memcpy
                (
                    Frame + Offsets::Frame::Base + Offset,
                    &Value,
                    8
                );
            };

        uint64_t Band = 0;

        if (Rva >= Offsets::Size)
            Band = ((Rva - Offsets::Size) & Offsets::Band::Mask) + Offsets::Band::Step;

        Write(Offsets::RVA, Rva);
        Write(Offsets::Page, Offsets::Buffer + Offsets::Size);
        Write(Offsets::Frame::KX, Offsets::Frame::VX);
        Write(Offsets::Frame::KW, Offsets::Frame::VW);
        Write(Offsets::Frame::KS, Offsets::Frame::VS);
        Write(Offsets::Frame::KY, Offsets::Frame::VY);
        Write(Offsets::Frame::KT, Offsets::Frame::VT);

        uint64_t KeyH = 0;

        if (Band == Offsets::Band::First)
            KeyH = Offsets::Band::Value;
        else if (Band == Offsets::Band::Seed)
            KeyH = Offsets::Band::Seeds;

        Write(Offsets::Frame::KH, KeyH);
        Write(Offsets::Frame::KE, Offsets::Frame::VE);

        uc_mem_write
        (
            Cpu,
            Offsets::MaxFrame,
            Frame,
            Offsets::Frame::Size
        );

        uint64_t Value;

        Value = Rva << 32;
        uc_reg_write(Cpu, UC_X86_REG_RAX, &Value);

        Value = 0;
        uc_reg_write(Cpu, UC_X86_REG_RBX, &Value);
        uc_reg_write(Cpu, UC_X86_REG_RCX, &Value);
        uc_reg_write(Cpu, UC_X86_REG_RDX, &Value);
        uc_reg_write(Cpu, UC_X86_REG_RSI, &Value);

        Value = Offsets::MaxFrame;
        uc_reg_write(Cpu, UC_X86_REG_RDI, &Value);

        Value = Offsets::MaxFrame + Offsets::Frame::Base;
        uc_reg_write(Cpu, UC_X86_REG_RBP, &Value);

        Value = Offsets::MaxFrame + Offsets::Frame::Stack;
        uc_reg_write(Cpu, UC_X86_REG_RSP, &Value);

        Value = 0;
        uc_reg_write(Cpu, UC_X86_REG_R8, &Value);
        uc_reg_write(Cpu, UC_X86_REG_R9, &Value);
        uc_reg_write(Cpu, UC_X86_REG_R10, &Value);
        uc_reg_write(Cpu, UC_X86_REG_R11, &Value);
        uc_reg_write(Cpu, UC_X86_REG_R12, &Value);
        uc_reg_write(Cpu, UC_X86_REG_R13, &Value);
        uc_reg_write(Cpu, UC_X86_REG_R14, &Value);
        uc_reg_write(Cpu, UC_X86_REG_R15, &Value);

        Value = Rva;
        uc_reg_write(Cpu, UC_X86_REG_R11, &Value);

        Value = 0x202;
        uc_reg_write(Cpu, UC_X86_REG_RFLAGS, &Value);

        Value = Offsets::Thread;
        uc_reg_write(Cpu, UC_X86_REG_GS_BASE, &Value);
        uc_reg_write(Cpu, UC_X86_REG_FS_BASE, &Value);

        const uint64_t Page = Rva >> 12;
        const uint64_t Slot = (Page % Offsets::Slot) * 32;

        uint8_t Zeroes[16] = {};

        static const int Xmm[16] = {
            UC_X86_REG_XMM0,  UC_X86_REG_XMM1,  UC_X86_REG_XMM2,  UC_X86_REG_XMM3,
            UC_X86_REG_XMM4,  UC_X86_REG_XMM5,  UC_X86_REG_XMM6,  UC_X86_REG_XMM7,
            UC_X86_REG_XMM8,  UC_X86_REG_XMM9,  UC_X86_REG_XMM10, UC_X86_REG_XMM11,
            UC_X86_REG_XMM12, UC_X86_REG_XMM13, UC_X86_REG_XMM14, UC_X86_REG_XMM15
        };

        for (int Index = 0; Index < 16; ++Index)
        {
            uc_reg_write
            (
                Cpu,
                Xmm[Index],
                Zeroes
            );
        }

        uc_reg_write
        (
            Cpu,
            UC_X86_REG_XMM1,
            const_cast<uint8_t*>(Key + Slot)
        );

        uc_reg_write
        (
            Cpu,
            UC_X86_REG_XMM0,
            const_cast<uint8_t*>(Key + Slot + 16)
        );

        if (Band == Offsets::Band::XMM1 || Band == Offsets::Band::XMM2)
        {
            uint8_t Mask[16] = {};
            std::memset(Mask, 0xFF, 4);
            uc_reg_write
            (
                Cpu,
                UC_X86_REG_XMM7,
                Mask
            );
        }

        const uc_err Error = uc_emu_start
        (
            Cpu,
            Offsets::Image + Offsets::Start,
            Offsets::Image + Offsets::End,
            0,
            Offsets::Steps
        );

        if (Error != UC_ERR_OK)
        {
            ++Errors;
            ++Engine.Bad;

            if (Engine.Bad <= 8 || (Engine.Bad % 4096) == 0)
            {
                Logger::Log
                (
                    "uc_emu_start: %s (rva=0x%llx, errors=%llu)",
                    uc_strerror(Error),
                    static_cast<unsigned long long>(Rva),
                    Engine.Bad
                );
            }
        }

        uint8_t OutputPage[Offsets::Size];

        if
            (
                uc_mem_read
                (
                    Cpu,
                    Offsets::Buffer + Offsets::Size,
                    OutputPage,
                    sizeof(OutputPage)
                ) != UC_ERR_OK
                )
        {
            Logger::Error
            (
                "uc_mem_read failed rva=0x%llx",
                static_cast<unsigned long long>(Rva)
            );

            return false;
        }

        if (Rva < Image.size())
        {
            const size_t Take = (std::min)
                (
                    static_cast<size_t>(Offsets::Size),
                    Image.size() - static_cast<size_t>(Rva)
                    );

            std::memcpy
            (
                Image.data() + Rva,
                OutputPage,
                Take
            );
        }

        return true;
    }

    bool Save(const MX::PE& Image, const MX::Section* Code, const std::vector<const MX::Section*>& Extra,
        const MX::Section* Pdata, uint32_t PdataSize, const std::string& OutputPath,
        uint64_t Pages, const MX::EntryPoint& Fix)
    {
        if (!Code || static_cast<size_t>(Code->Raw) > Image.File.size())
            return false;

        std::vector<uint8_t> Output = Image.File;

        const size_t CopyLength = (std::min)
            (
                static_cast<size_t>(Code->VSize),
                static_cast<size_t>(Code->RawSize)
                );

        const size_t FileOffset = Code->Raw;

        if (FileOffset + CopyLength > Output.size())
        {
            Logger::Error
            (
                "save: %s raw range exceeds file",
                Image.Path.c_str()
            );

            return false;
        }

        if (static_cast<size_t>(Code->VA) + CopyLength > Image.Image.size())
        {
            Logger::Error
            (
                "save: %s image range exceeds image",
                Image.Path.c_str()
            );

            return false;
        }

        std::memcpy
        (
            Output.data() + FileOffset,
            Image.Image.data() + Code->VA,
            CopyLength
        );

        if (Code->RawSize > Code->VSize)
        {
            const size_t TailOffset = FileOffset + CopyLength;
            const size_t TailLength = static_cast<size_t>(Code->RawSize) - Code->VSize;

            if (TailOffset + TailLength <= Output.size())
            {
                std::memset
                (
                    Output.data() + TailOffset,
                    0,
                    TailLength
                );
            }
        }

        for (const MX::Section* Section : Extra)
        {
            if (!Section || !Section->VSize || !Section->RawSize)
                continue;

            const size_t Length = (std::min)
                (
                    static_cast<size_t>(Section->VSize),
                    static_cast<size_t>(Section->RawSize)
                    );

            if (!Length || static_cast<size_t>(Section->Raw) + Length > Output.size())
                continue;

            if (static_cast<size_t>(Section->VA) + Length > Image.Image.size())
                continue;

            std::memcpy
            (
                Output.data() + Section->Raw,
                Image.Image.data() + Section->VA,
                Length
            );
        }

        if (Pdata && Image.Dirs > 3 && Image.DirOff + 32 <= Output.size())
        {
            uint32_t Old = 0;
            uint32_t OldSize = 0;

            std::memcpy
            (
                &Old,
                Output.data() + Image.DirOff + 24,
                4
            );

            std::memcpy
            (
                &OldSize,
                Output.data() + Image.DirOff + 28,
                4
            );

            if (!Old && !OldSize)
            {
                const uint32_t New = Pdata->VA;
                const uint32_t NewSize = PdataSize ? PdataSize : Pdata->VSize;

                std::memcpy
                (
                    Output.data() + Image.DirOff + 24,
                    &New,
                    4
                );

                std::memcpy
                (
                    Output.data() + Image.DirOff + 28,
                    &NewSize,
                    4
                );

                Logger::Log
                (
                    "exception dir: rva=0x%x size=0x%x",
                    New,
                    NewSize
                );
            }
        }

        if (std::strncmp(Code->Name, ".text", 5) == 0)
        {
            if
                (
                    !Rebuild::RebuildImports
                    (
                        Image,
                        Output
                    )
                    )
            {
                Logger::Error
                (
                    "import rebuild skipped for %s",
                    Image.Path.c_str()
                );
            }
        }

        if (Fix.Changed && Image.OPT + 20 <= Output.size())
        {
            std::memcpy
            (
                Output.data() + Image.OPT + 16,
                &Fix.NewEP,
                4
            );

            Logger::Log
            (
                "entry point 0x%llx -> 0x%llx",
                static_cast<unsigned long long>(Fix.OldEP),
                static_cast<unsigned long long>(Fix.NewEP)
            );
        }

        std::ofstream Stream
        (
            OutputPath,
            std::ios::binary | std::ios::trunc
        );

        if (!Stream)
        {
            Logger::Error
            (
                "save: cannot open %s",
                OutputPath.c_str()
            );

            return false;
        }

        Stream.write
        (
            reinterpret_cast<const char*>(Output.data()),
            static_cast<std::streamsize>(Output.size())
        );

        if (!Stream)
        {
            Logger::Error
            (
                "save: write failed for %s",
                OutputPath.c_str()
            );

            return false;
        }

        Logger::Success
        (
            "Saved %llu pages -> \"%s\" (%llu bytes)",
            Pages,
            OutputPath.c_str(),
            static_cast<unsigned long long>(Output.size())
        );

        return true;
    }

    int Run(MX::PE& Image, const std::string& OutputPath, const uint8_t* Key, const std::string& DllPath)
    {
        const MX::Section* CodeSection = Code(Image);

        if (!CodeSection)
        {
            Logger::Error
            (
                "no code section in %s",
                Image.Path.c_str()
            );

            return 1;
        }

        const uint64_t First = CodeSection->VA;
        const uint64_t Last = static_cast<uint64_t>(CodeSection->VA) + CodeSection->VSize;
        const uint64_t Count = (static_cast<uint64_t>(CodeSection->VSize) + 0xFFF) / 0x1000;

        const size_t Bytes = (std::min)
            (
                static_cast<size_t>(CodeSection->VSize),
                static_cast<size_t>(CodeSection->RawSize)
                );

        const double Score = (Bytes && static_cast<size_t>(CodeSection->Raw) + Bytes <= Image.File.size())
            ? Entropy(Image.File.data() + CodeSection->Raw, Bytes)
            : 0.0;

        const bool Cipher = Score >= 7.5;

        uint64_t Errors = 0;
        uint64_t Failed = 0;
        uint64_t Done = 0;
        uint64_t Reverted = 0;

        const auto StartTime = std::chrono::steady_clock::now();

        const auto Page = [&](uint64_t Rva, size_t Raw, uint64_t End) -> bool
            {
                if (Rva >= Image.Image.size())
                    return false;

                const size_t Size = (std::min)
                    (
                        static_cast<size_t>(0x1000),
                        Image.Image.size() - static_cast<size_t>(Rva)
                        );

                const double Before = Entropy
                (
                    Image.Image.data() + Rva,
                    Size
                );

                const bool Ok = Decrypt
                (
                    Rva,
                    Key,
                    Image.Image,
                    Errors
                );

                const double After = Entropy
                (
                    Image.Image.data() + Rva,
                    Size
                );

                if (After <= Before + 0.1)
                    return Ok;

                uint64_t Limit = (std::min)
                    (
                        End,
                        static_cast<uint64_t>(Image.Image.size())
                        );

                Limit = (std::min)
                    (
                        Limit,
                        Rva + Size
                        );

                if (Limit > Rva && Raw + static_cast<size_t>(Limit - Rva) <= Image.File.size())
                {
                    std::memcpy
                    (
                        Image.Image.data() + Rva,
                        Image.File.data() + Raw,
                        static_cast<size_t>(Limit - Rva)
                    );

                    ++Reverted;
                }

                return false;
            };

        if (!Cipher)
        {
            Logger::Log
            (
                "%s %s entropy %.4f < 7.50 - not hyperion page encrypted, leaving untouched",
                Image.Path.c_str(),
                CodeSection->Name,
                Score
            );
        }
        else
        {
            Logger::Log
            (
                "Decrypting %s %s: 0x%llx-0x%llx (%llu pages)",
                Image.Path.c_str(),
                CodeSection->Name,
                static_cast<unsigned long long>(First),
                static_cast<unsigned long long>(Last),
                Count
            );

            for (uint64_t Rva = First; Rva < Last; Rva += 0x1000)
            {
                if
                    (
                        !Page
                        (
                            Rva,
                            static_cast<size_t>(CodeSection->Raw) + static_cast<size_t>(Rva - CodeSection->VA),
                            Last
                        )
                        )
                {
                    ++Failed;
                }

                ++Done;

                if (Done % 1000 == 0 || Done == Count)
                {
                    const auto Seconds = std::chrono::duration_cast<std::chrono::seconds>
                        (
                            std::chrono::steady_clock::now() - StartTime
                        ).count();

                    const double Speed = Seconds > 0
                        ? static_cast<double>(Done) / static_cast<double>(Seconds)
                        : 0.0;

                    Logger::Progress
                    (
                        "%s: page %llu/%llu (%.1f%%) %llus (~%.0f pg/s)",
                        Image.Path.c_str(),
                        Done,
                        Count,
                        100.0 * Done / Count,
                        static_cast<long long>(Seconds),
                        Speed
                    );
                }
            }

            const auto Seconds = std::chrono::duration_cast<std::chrono::seconds>
                (
                    std::chrono::steady_clock::now() - StartTime
                ).count();

            Logger::Log
            (
                "%s decrypt finished in %llus (%llu pages, %llu read errors, %llu uc errors, %llu pages restored)",
                Image.Path.c_str(),
                static_cast<long long>(Seconds),
                Done,
                Failed,
                Errors,
                Reverted
            );
        }

        std::vector<const MX::Section*> Extra;

        if (std::strncmp(CodeSection->Name, ".text", 5) == 0)
        {
            uint32_t Resources = 0;
            uint32_t ResourcesSize = 0;

            if (Image.Dirs > 2 && Image.DirOff + 24 <= Image.File.size())
            {
                std::memcpy
                (
                    &Resources,
                    Image.File.data() + Image.DirOff + 16,
                    4
                );

                std::memcpy
                (
                    &ResourcesSize,
                    Image.File.data() + Image.DirOff + 20,
                    4
                );
            }

            for (const MX::Section& Section : Image.Sections)
            {
                if (&Section == CodeSection || !Section.VSize || !Section.RawSize)
                    continue;

                if
                    (
                        Resources &&
                        ResourcesSize &&
                        Section.VA < Resources + ResourcesSize &&
                        Section.VA + Section.VSize > Resources
                        )
                {
                    continue;
                }

                const size_t Length = (std::min)
                    (
                        static_cast<size_t>(Section.VSize),
                        static_cast<size_t>(Section.RawSize)
                        );

                if (!Length || static_cast<size_t>(Section.Raw) + Length > Image.File.size())
                    continue;

                if (Entropy(Image.File.data() + Section.Raw, Length) < 7.9)
                    continue;

                uint64_t Error = 0;
                size_t Pages = 0;
                size_t Changed = 0;
                size_t Restored = 0;

                const uint64_t End = static_cast<uint64_t>(Section.VA) + Section.VSize;

                for (uint64_t Rva = Section.VA; Rva < End; Rva += 0x1000)
                {
                    if (Rva >= Image.Image.size())
                        break;

                    const size_t Size = (std::min)
                        (
                            static_cast<size_t>(0x1000),
                            Image.Image.size() - static_cast<size_t>(Rva)
                            );

                    const double Before = Entropy
                    (
                        Image.Image.data() + Rva,
                        Size
                    );

                    if
                        (
                            !Decrypt
                            (
                                Rva,
                                Key,
                                Image.Image,
                                Error
                            )
                            )
                    {
                        ++Failed;
                    }

                    const size_t Raw = static_cast<size_t>(Section.Raw) + static_cast<size_t>(Rva - Section.VA);

                    uint64_t Limit = (std::min)
                        (
                            End,
                            static_cast<uint64_t>(Image.Image.size())
                            );

                    Limit = (std::min)
                        (
                            Limit,
                            Rva + Size
                            );

                    if
                        (
                            Entropy(Image.Image.data() + Rva, Size) > Before + 0.1 &&
                            Limit > Rva &&
                            Raw + static_cast<size_t>(Limit - Rva) <= Image.File.size()
                            )
                    {
                        std::memcpy
                        (
                            Image.Image.data() + Rva,
                            Image.File.data() + Raw,
                            static_cast<size_t>(Limit - Rva)
                        );

                        ++Restored;
                    }

                    ++Pages;
                }

                for (size_t Index = 0; Index < Length; ++Index)
                {
                    if (Image.Image[Section.VA + Index] != Image.File[static_cast<size_t>(Section.Raw) + Index])
                        ++Changed;
                }

                Logger::Log
                (
                    "extra section %s: %llu pages, %llu/%llu bytes changed (%.4f -> %.4f entropy, %llu restored)",
                    Section.Name[0] ? Section.Name : "<noname>",
                    Pages,
                    static_cast<unsigned long long>(Changed),
                    Length,
                    Entropy(Image.File.data() + Section.Raw, Length),
                    Entropy(Image.Image.data() + Section.VA, Length),
                    static_cast<unsigned long long>(Restored)
                );

                Extra.push_back
                (
                    &Section
                );
            }
        }

        const MX::Section* Data = nullptr;
        uint32_t DataSize = 0;

        for (const MX::Section* Section : Extra)
        {
            if (Pdata(Image, Section, CodeSection))
            {
                Data = Section;
                DataSize = Section->VSize;

                Logger::Log
                (
                    "exception table: %s (%llu entries)",
                    Section->Name[0] ? Section->Name : "<noname>",
                    static_cast<unsigned long long>(Section->VSize / 12)
                );

                break;
            }
        }

        if (std::strncmp(CodeSection->Name, ".text", 5) == 0 && !DllPath.empty())
        {
            Logger::Log
            (
                "Rebuilding jcc stubs in %s",
                Image.Path.c_str()
            );

            Jcc::Statistics Stats;

            const auto Retry = [&](uint64_t Rva)
                {
                    uint64_t Error = 0;
                    return Decrypt(Rva, Key, Image.Image, Error);
                };

            if
                (
                    !Jcc::Resolve
                    (
                        DllPath,
                        Image.Image,
                        CodeSection,
                        Stats,
                        Retry
                    )
                    )
            {
                Logger::Error
                (
                    "jcc rebuild skipped for %s",
                    Image.Path.c_str()
                );
            }
        }

        if (!Data && std::strncmp(CodeSection->Name, ".text", 5) == 0)
        {
            const MX::Section* Slot = Pdata::FindSlot(Image, CodeSection);
            uint32_t Used = 0;

            if (Slot && Pdata::Build(Image, CodeSection, Slot, Used))
            {
                if (std::find(Extra.begin(), Extra.end(), Slot) == Extra.end())
                    Extra.push_back(Slot);

                Data = Slot;
                DataSize = Used;
            }
        }

        MX::EntryPoint EntryPoint;
        MX::ResolveEntry(Image, CodeSection, EntryPoint);

        return Save(Image, CodeSection, Extra, Data, DataSize, OutputPath, Done, EntryPoint) ? 0 : 1;
    }

    void Clean(const std::string& OutputPath)
    {
        const char* Suffixes[] = { ".checkpoint", ".bak", ".xrefs.json" };

        for (const char* Suffix : Suffixes)
        {
            const std::string Stale = OutputPath + Suffix;

            if (GetFileAttributesA(Stale.c_str()) != INVALID_FILE_ATTRIBUTES)
            {
                if
                    (
                        DeleteFileA
                        (
                            Stale.c_str()
                        )
                        )
                {
                    Logger::Log
                    (
                        "Removed useless files %s",
                        Stale.c_str()
                    );
                }
                else
                {
                    Logger::Error
                    (
                        "Could not remove stale %s (err=%lu)",
                        Stale.c_str(),
                        GetLastError()
                    );
                }
            }
        }
    }
}

#include "StringResolver.cpp"

int main()
{
    Logger::Colors();

    const std::string Target = ".";
    const std::string EXE = Target + "\\RobloxPlayerBeta.exe";
    const std::string DLL = Target + "\\RobloxPlayerBeta.dll";
    const std::string Output = Target + "\\RobloxPlayerBeta.bin";

    Logger::Log
    (
        "Decryptor %s — mxhidk / MX",
        Version
    );

    Logger::Log
    (
        "Target: %s",
        Target.c_str()
    );

    Clean
    (
        Output
    );

    Clean
    (
        DLL
    );

    MX::PE Library{};
    Library.Path = DLL;

    if
        (
            !Read
            (
                DLL,
                Library.File
            ) ||
            !Sections
            (
                Library
            )
            )
    {
        Logger::Error
        (
            "Failed to read %s",
            DLL.c_str()
        );

        return 1;
    }

    std::vector<uint8_t> Data;

    if
        (
            !EmuImage
            (
                Library,
                Data
            )
            )
    {
        Logger::Error
        (
            "Failed to build emulated image from %s",
            DLL.c_str()
        );

        return 1;
    }

    if (Data.size() < Offsets::Key + Offsets::Slot * 32)
    {
        Logger::Error
        (
            "Emulated image too small for key blob at 0x%llx",
            Offsets::Key
        );

        return 1;
    }

    if
        (
            !Open
            (
                std::move(Data)
            )
            )
    {
        Close();

        return 1;
    }

    const uint8_t* Key = Engine.Original.data() + Offsets::Key;

    int ReturnCode = 0;

    Logger::Log
    (
        "--- %s ---",
        EXE.c_str()
    );

    MX::PE Executable{};
    Executable.Path = EXE;

    if
        (
            !Read
            (
                EXE,
                Executable.File
            ) ||
            !Sections
            (
                Executable
            ) ||
            !Map
            (
                Executable
            )
            )
    {
        Logger::Error
        (
            "Failed to read %s",
            EXE.c_str()
        );

        ReturnCode = 1;
    }
    else if
        (
            Run
            (
                Executable,
                Output,
                Key,
                DLL
            ) != 0
            )
    {
        ReturnCode = 1;
    }

    Logger::Log
    (
        "--- %s ---",
        DLL.c_str()
    );

    if
        (
            !Map
            (
                Library
            )
            )
    {
        Logger::Error
        (
            "Failed to build disk image from %s",
            DLL.c_str()
        );

        ReturnCode = 1;
    }
    else if
        (
            Run
            (
                Library,
                Output,
                Key,
                DLL
            ) != 0
            )
    {
        ReturnCode = 1;
    }

    Close();

    return ReturnCode;
}
