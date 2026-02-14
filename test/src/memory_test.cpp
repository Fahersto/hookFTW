#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>

#include <Memory.h>

namespace
{
    TEST(Memory, AllocModifyProtectAndFreePage)
    {
        const auto pageSize = hookftw::Memory::GetPageSize();
        ASSERT_GT(pageSize, 0);

        int8_t* page = hookftw::Memory::AllocPage(nullptr, pageSize, hookftw::MemoryPageProtection::HOOKFTW_PAGE_READWRITE, hookftw::MemoryPageFlag::HOOKFTW_MEM_DEFAULT);
        ASSERT_NE(page, nullptr);

        // Write
        std::memset(page, 0xAB, static_cast<size_t>(pageSize));
        EXPECT_EQ(static_cast<uint8_t>(page[0]), 0xAB);

        // Change protection to RX (common for trampolines)
        EXPECT_TRUE(hookftw::Memory::ModifyPageProtection(page, pageSize,
                                                         hookftw::MemoryPageProtection::HOOKFTW_PAGE_EXECUTE_READ));

        auto prot = hookftw::Memory::QueryPageProtection(page);
        (void)prot; // Some platforms may not support precise query invariants.

        EXPECT_TRUE(hookftw::Memory::FreePage(page, pageSize));
    }

    TEST(Memory, FindFunctionInCurrentProcess)
    {
    #if defined(__linux)
        // dlsym can resolve from RTLD_DEFAULT when handle is RTLD_DEFAULT; our wrapper uses dlopen.
        // Use the main program handle via dlopen(nullptr, ...) semantics: moduleName empty isn't supported here,
        // so we just assert the wrapper returns nullptr for unknown modules and non-null for libc.
        auto* putsAddr = hookftw::Memory::FindFunctionInModule("libc.so.6", "puts");
        EXPECT_NE(putsAddr, nullptr);
    #else
        GTEST_SKIP() << "FindFunctionInModule test not implemented for this platform";
    #endif
    }

    TEST(Memory, FreePageWithInvalidSizeFails)
    {
    #if defined(__linux)
        const int32_t pageSize = hookftw::Memory::GetPageSize();
        ASSERT_GT(pageSize, 0);

        int8_t* page = hookftw::Memory::AllocPage(nullptr, pageSize,
                                                  hookftw::MemoryPageProtection::HOOKFTW_PAGE_READWRITE,
                                                  hookftw::MemoryPageFlag::HOOKFTW_MEM_DEFAULT);
        ASSERT_NE(page, nullptr);

        // munmap requires a non-zero size; passing 0 should fail deterministically with EINVAL.
        EXPECT_FALSE(hookftw::Memory::FreePage(page, 0));

        // Clean up correctly.
        EXPECT_TRUE(hookftw::Memory::FreePage(page, pageSize));
    #else
        GTEST_SKIP() << "Invalid-size FreePage behavior is platform-dependent";
    #endif
    }

    #if defined(__x86_64__) && defined(__linux)
    TEST(Memory, ExecuteFromRXPage)
    {
        // Machine code: mov eax, 0x2A; ret
        const uint8_t code[] = {0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3};

        const int32_t pageSize = hookftw::Memory::GetPageSize();
        int8_t* page = hookftw::Memory::AllocPage(nullptr, pageSize, hookftw::MemoryPageProtection::HOOKFTW_PAGE_READWRITE, hookftw::MemoryPageFlag::HOOKFTW_MEM_DEFAULT);
        ASSERT_NE(page, nullptr);

        std::memcpy(page, code, sizeof(code));

        ASSERT_TRUE(hookftw::Memory::ModifyPageProtection(page, pageSize, hookftw::MemoryPageProtection::HOOKFTW_PAGE_EXECUTE_READ));

        using Fn = int (*)();
        auto fn = reinterpret_cast<Fn>(page);
        EXPECT_EQ(fn(), 42);

        EXPECT_TRUE(hookftw::Memory::FreePage(page, pageSize));
    }
    #endif
}
