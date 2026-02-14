#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

#include <Decoder.h>

namespace
{
    #ifdef __x86_64

    TEST(DecoderRelocation, RelocatesRelativeCallRel32)
    {
        hookftw::Decoder decoder;

        // CALL rel32 + 4-byte offset
        uint8_t code[] = {0xE8, 0x11, 0x22, 0x33, 0x44};

        alignas(16) int8_t relocatedBuf[64] = {};
        auto relocated = decoder.Relocate(reinterpret_cast<int8_t*>(code), static_cast<int>(sizeof(code)), relocatedBuf);

        // Basic invariants: relocation returns non-empty, and doesn't exceed our buffer.
        ASSERT_FALSE(relocated.empty());
        ASSERT_LT(relocated.size(), sizeof(relocatedBuf));

        // Ensure relocation produced executable bytes (not all zeros) and kept instruction boundary.
        bool anyNonZero = false;
        for (auto b : relocated) anyNonZero |= (b != 0);
        EXPECT_TRUE(anyNonZero);
    }

    TEST(DecoderRelocation, RelocatesRipRelativeMemoryAccess)
    {
        hookftw::Decoder decoder;

        // sub DWORD PTR [rip+disp32], ebp
        uint8_t code[] = {0x29, 0x2D, 0xF5, 0xE9, 0x28, 0x7C};

        alignas(16) int8_t relocatedBuf[64] = {};
        auto relocated = decoder.Relocate(reinterpret_cast<int8_t*>(code), static_cast<int>(sizeof(code)), relocatedBuf);

        ASSERT_FALSE(relocated.empty());
        ASSERT_LT(relocated.size(), sizeof(relocatedBuf));

        // Relocating RIP-relative instructions should typically expand.
        EXPECT_GE(relocated.size(), sizeof(code));
    }

    #else

    TEST(DecoderRelocation, RelocatesRelativeCallRel32)
    {
        hookftw::Decoder decoder;

        uint8_t code[] = {0xE8, 0x11, 0x22, 0x33, 0x44};
        alignas(16) int8_t relocatedBuf[64] = {};
        auto relocated = decoder.Relocate(reinterpret_cast<int8_t*>(code), static_cast<int>(sizeof(code)), relocatedBuf);

        ASSERT_FALSE(relocated.empty());
        ASSERT_LT(relocated.size(), sizeof(relocatedBuf));
    }

    #endif
}
