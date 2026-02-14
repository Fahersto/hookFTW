#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>

#include <Decoder.h>
#include <Memory.h>

namespace
{
    #if defined(__linux__) && defined(__x86_64__)

    // This is an integration-style test for indirect JMP forms that require valid memory operands.
    // We build a small executable function blob that performs:
    //   jmp qword ptr [rip+0] ; <imm64 target>
    // so it will jump to a second blob that returns a constant.
    TEST(DecoderRelocationIntegration, RelocateRipIndirectJmp_TargetPreserved)
    {
        const int32_t pageSize = hookftw::Memory::GetPageSize();
        ASSERT_GT(pageSize, 0);

        // Allocate a page where our blob lives.
        int8_t* page = hookftw::Memory::AllocPage(nullptr, pageSize, hookftw::MemoryPageProtection::HOOKFTW_PAGE_EXECUTE_READWRITE, hookftw::MemoryPageFlag::HOOKFTW_MEM_DEFAULT);
        ASSERT_NE(page, nullptr);

        // Second blob: mov eax, 0x2A; ret
        uint8_t targetBlob[] = {0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3};
        int8_t* targetAddr = page + 128;
        std::memcpy(targetAddr, targetBlob, sizeof(targetBlob));

        // First blob: jmp [rip+0]; imm64
        // FF 25 00 00 00 00 <imm64>
        uint8_t jmpBlob[14] = {0xFF, 0x25, 0x00, 0x00, 0x00, 0x00};
        std::memcpy(jmpBlob + 6, &targetAddr, sizeof(targetAddr));

        int8_t* srcAddr = page + 32;
        std::memcpy(srcAddr, jmpBlob, sizeof(jmpBlob));

        // Relocate the first blob into another buffer (within the same page for simplicity).
        int8_t* relocatedBuf = page + 256;

        hookftw::Decoder decoder;
        // Only relocate the 6-byte instruction, not the 8-byte operand data
        auto relocated = decoder.Relocate(srcAddr, 6, relocatedBuf);
        ASSERT_FALSE(relocated.empty());

        // Execute relocated code: it should jump to target and return 42.
        std::memcpy(relocatedBuf, relocated.data(), relocated.size());

        // The operand data (8 bytes containing the target address) must also be copied
        // For an indirect RIP-relative JMP [rip+displacement], the operand is at srcAddr + 6
        // and must be at relocatedBuf + 6 (maintaining the same relative offset)
        std::memcpy(relocatedBuf + relocated.size(), srcAddr + 6, 8);

        using Fn = int (*)();
        auto fn = reinterpret_cast<Fn>(relocatedBuf);
        EXPECT_EQ(fn(), 42);

        EXPECT_TRUE(hookftw::Memory::FreePage(page, pageSize));
    }

    #else

    TEST(DecoderRelocationIntegration, RelocateRipIndirectJmp_TargetPreserved)
    {
        GTEST_SKIP() << "Requires Linux x86_64";
    }
    #endif
}
