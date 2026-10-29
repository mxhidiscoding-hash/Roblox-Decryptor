#pragma once

#include <cstdint>
// version-cec3ad5889b447cf

namespace Offsets
{
    constexpr uint64_t Image = 0x180000000ull;
    constexpr uint64_t ImageSize = 0x15B0000ull;

    constexpr uint64_t Start = 0xEA206Full;
    constexpr uint64_t End = 0xEA35F1ull;
    constexpr uint64_t Guard = 0xF62000ull;
    constexpr uint64_t Steps = 3000000ull;

    constexpr uint64_t Buffer = 0x100000000ull;
    constexpr uint64_t MaxFrame = 0x110000000ull;
    constexpr uint64_t Thread = 0x120000000ull;

    constexpr uint64_t Constant = 0x00002069ull;
    constexpr uint64_t Hash = 0x326B4954ull;

    constexpr uint64_t Key = 0x672A0ull;
    constexpr uint64_t Slot = 0x2004ull;

    constexpr uint64_t RVA = 0xBE0ull;
    constexpr uint64_t Page = 0x1440ull;

    constexpr uint64_t Size = 0x1000ull;

    namespace Frame
    {
        constexpr uint64_t Size = 0x10000ull;
        constexpr uint64_t Base = 0x4000ull;
        constexpr uint64_t Stack = 0xF000ull;

        // Frame slots 
        constexpr uint64_t KX = 0x180ull;
        constexpr uint64_t KW = 0x1B8ull;
        constexpr uint64_t KS = 0x1300ull;
        constexpr uint64_t KY = 0x13C0ull;
        constexpr uint64_t KT = 0x1030ull;
        constexpr uint64_t KH = 0x1118ull;
        constexpr uint64_t KE = 0xFE8ull;
        // ^^^^

        // Solved Values.
        constexpr uint64_t VX = 0xC000009Dull;
        constexpr uint64_t VW = 0xC778CF30ull;
        constexpr uint64_t VS = 0xC778CF31ull;
        constexpr uint64_t VY = 0xC5975C31ull;
        constexpr uint64_t VT = 0x59F71BE6ull;
        constexpr uint64_t VE = 0x10000000000ull;
        // ^^^^^
    }

    namespace Band
    {
        constexpr uint64_t Mask = ~0x1FFFFFull; // cmp 1FFFFFFFF
        constexpr uint64_t Step = 0x1000ull;

        constexpr uint64_t First = 0x1000ull;
        constexpr uint64_t Value = 1ull;

        constexpr uint64_t Seed = 0x4801000ull;
        constexpr uint64_t Seeds = 4ull;

        constexpr uint64_t XMM1 = 0x01201000ull;
        constexpr uint64_t XMM2 = 0x05401000ull;
    }
}
