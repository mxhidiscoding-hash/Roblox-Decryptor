#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace MX
{
    struct Section
    {
        uint32_t VA = 0;
        uint32_t VSize = 0;
        uint32_t RawSize = 0;
        uint32_t Raw = 0;
        uint32_t Flags = 0;
        char Name[9] = {};
    };

    struct PE
    {
        std::string Path;
        std::vector<uint8_t> File;
        std::vector<Section> Sections;
        std::vector<uint8_t> Image;
        uint64_t Base = 0;
        uint32_t Headers = 0;
        size_t NT = 0;
        size_t OPT = 0;
        uint32_t Dirs = 0;
        size_t DirOff = 0;
    };

    struct EntryPoint
    {
        uint32_t OldEP = 0;
        uint32_t NewEP = 0;
        uint32_t BaseCode = 0;
        bool Changed = false;
        bool EPOK = false;
        bool ImportsOK = false;
        bool ExportsOK = false;
        uint32_t Dlls = 0;
        uint32_t ImportNames = 0;
        uint32_t ExportNames = 0;
        uint32_t ExportFuncs = 0;
    };

    void ResolveEntry(PE& Pe, const Section* Code, EntryPoint& Fix);
}
