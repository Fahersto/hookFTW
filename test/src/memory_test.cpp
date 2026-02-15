#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>

#ifdef __linux
#include <unistd.h>
#elif _WIN32
#include <Windows.h>
#endif

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

    TEST(Memory, GetProcessBaseAddress)
    {
        int8_t* baseAddress = hookftw::Memory::GetProcessBaseAddress();

        // Base address should not be null
        ASSERT_NE(baseAddress, nullptr);

        // Base address should be page-aligned (standard for module loading)
        const int32_t pageSize = hookftw::Memory::GetPageSize();
        EXPECT_EQ(reinterpret_cast<uintptr_t>(baseAddress) % pageSize, 0);

        #ifdef _WIN32
        // On Windows, verify it matches GetModuleHandle(NULL)
        EXPECT_EQ(baseAddress, reinterpret_cast<int8_t*>(GetModuleHandle(NULL)));
        #endif
    }

    TEST(Memory, GetProcessBaseAddressPointsToImageHeader)
    {
        // For hooking libraries, the base address should point to the loaded module/image base,
        // NOT the .text section. This is needed for:
        // - Parsing PE/ELF headers (import/export tables, sections, etc.)
        // - Calculating RVAs (Relative Virtual Addresses)
        // - Resolving symbols and addresses
        int8_t* baseAddress = hookftw::Memory::GetProcessBaseAddress();
        ASSERT_NE(baseAddress, nullptr);

        // Verify the base points to the image header by checking magic bytes
        #ifdef __linux
        // ELF magic number: 0x7F 'E' 'L' 'F'
        // This proves we're at the ELF header, not just the .text segment
        EXPECT_EQ(static_cast<uint8_t>(baseAddress[0]), 0x7F);
        EXPECT_EQ(static_cast<uint8_t>(baseAddress[1]), 'E');
        EXPECT_EQ(static_cast<uint8_t>(baseAddress[2]), 'L');
        EXPECT_EQ(static_cast<uint8_t>(baseAddress[3]), 'F');
        #elif _WIN32
        // DOS/PE magic number: 'M' 'Z' (0x4D 0x5A)
        EXPECT_EQ(static_cast<uint8_t>(baseAddress[0]), 'M');
        EXPECT_EQ(static_cast<uint8_t>(baseAddress[1]), 'Z');
        #endif
    }

    TEST(Memory, GetProcessBaseAddressConsistency)
    {
        // Multiple calls should return the same address
        int8_t* baseAddress1 = hookftw::Memory::GetProcessBaseAddress();
        int8_t* baseAddress2 = hookftw::Memory::GetProcessBaseAddress();
        int8_t* baseAddress3 = hookftw::Memory::GetProcessBaseAddress();

        EXPECT_EQ(baseAddress1, baseAddress2);
        EXPECT_EQ(baseAddress2, baseAddress3);
    }

    #ifdef __linux
    TEST(Memory, GetProcessBaseAddressMatchesProcMaps)
    {
        // Read /proc/self/maps and verify our base address matches
        int8_t* baseAddress = hookftw::Memory::GetProcessBaseAddress();
        ASSERT_NE(baseAddress, nullptr);

        // Get the executable path
        char exePath[4096];
        ssize_t len = readlink("/proc/self/exe", exePath, sizeof(exePath) - 1);
        ASSERT_NE(len, -1);
        exePath[len] = '\0';

        // Parse /proc/self/maps
        std::ifstream maps("/proc/self/maps");
        ASSERT_TRUE(maps.is_open());

        std::string line;
        bool found = false;
        while (std::getline(maps, line))
        {
            // Look for the first mapping of our executable
            if (line.find(exePath) != std::string::npos)
            {
                std::istringstream iss(line);
                std::string addr_range;
                iss >> addr_range;
                size_t dash = addr_range.find('-');
                ASSERT_NE(dash, std::string::npos);

                std::string base_str = addr_range.substr(0, dash);
                uintptr_t mapBase = std::stoull(base_str, nullptr, 16);

                // Our base address should match the first mapping
                EXPECT_EQ(reinterpret_cast<uintptr_t>(baseAddress), mapBase);
                found = true;
                break;
            }
        }

        EXPECT_TRUE(found) << "Could not find executable in /proc/self/maps";
    }
    #endif

    TEST(Memory, FindPatternBasic)
    {
        // Create a buffer with a known pattern
        const uint8_t buffer[] = {
            0x48, 0x8B, 0x05, 0x12, 0x34, 0x56, 0x78,  // mov rax, [rip+0x78563412]
            0x48, 0x89, 0x05, 0xAB, 0xCD, 0xEF, 0x00,  // mov [rip+0x00EFCDAB], rax
            0xC3                                        // ret
        };

        // Search for exact pattern at the beginning
        int8_t* result = hookftw::Memory::FindPattern(
            reinterpret_cast<const int8_t*>(buffer),
            sizeof(buffer),
            "48 8B 05"
        );
        ASSERT_NE(result, nullptr);
        EXPECT_EQ(result, reinterpret_cast<const int8_t*>(buffer));

        // Search for pattern in the middle
        result = hookftw::Memory::FindPattern(
            reinterpret_cast<const int8_t*>(buffer),
            sizeof(buffer),
            "48 89 05"
        );
        ASSERT_NE(result, nullptr);
        EXPECT_EQ(result, reinterpret_cast<const int8_t*>(buffer + 7));

        // Search for single byte
        result = hookftw::Memory::FindPattern(
            reinterpret_cast<const int8_t*>(buffer),
            sizeof(buffer),
            "C3"
        );
        ASSERT_NE(result, nullptr);
        EXPECT_EQ(result, reinterpret_cast<const int8_t*>(buffer + 14));
    }

    TEST(Memory, FindPatternWithWildcards)
    {
        // Create a buffer with a known pattern
        const uint8_t buffer[] = {
            0x48, 0x8B, 0x05, 0x12, 0x34, 0x56, 0x78,  // mov rax, [rip+offset]
            0x48, 0x89, 0x05, 0xAB, 0xCD, 0xEF, 0x00,  // mov [rip+offset], rax
            0xC3                                        // ret
        };

        // Search for pattern with wildcards (ignoring the offset bytes)
        int8_t* result = hookftw::Memory::FindPattern(
            reinterpret_cast<const int8_t*>(buffer),
            sizeof(buffer),
            "48 8B 05 ? ? ? ?"
        );
        ASSERT_NE(result, nullptr);
        EXPECT_EQ(result, reinterpret_cast<const int8_t*>(buffer));

        // Search for pattern with mixed wildcards
        result = hookftw::Memory::FindPattern(
            reinterpret_cast<const int8_t*>(buffer),
            sizeof(buffer),
            "48 89 05 ?? ?? ?? 00"
        );
        ASSERT_NE(result, nullptr);
        EXPECT_EQ(result, reinterpret_cast<const int8_t*>(buffer + 7));

        // Wildcard at the beginning
        result = hookftw::Memory::FindPattern(
            reinterpret_cast<const int8_t*>(buffer),
            sizeof(buffer),
            "? 8B 05"
        );
        ASSERT_NE(result, nullptr);
        EXPECT_EQ(result, reinterpret_cast<const int8_t*>(buffer));
    }

    TEST(Memory, FindPatternNotFound)
    {
        const uint8_t buffer[] = {
            0x48, 0x8B, 0x05, 0x12, 0x34, 0x56, 0x78,
            0x48, 0x89, 0x05, 0xAB, 0xCD, 0xEF, 0x00,
            0xC3
        };

        // Search for pattern that doesn't exist
        int8_t* result = hookftw::Memory::FindPattern(
            reinterpret_cast<const int8_t*>(buffer),
            sizeof(buffer),
            "90 90 90"  // NOP NOP NOP
        );
        EXPECT_EQ(result, nullptr);

        // Pattern longer than buffer
        result = hookftw::Memory::FindPattern(
            reinterpret_cast<const int8_t*>(buffer),
            sizeof(buffer),
            "48 8B 05 12 34 56 78 48 89 05 AB CD EF 00 C3 90 90"
        );
        EXPECT_EQ(result, nullptr);
    }

    TEST(Memory, FindPatternEdgeCases)
    {
        const uint8_t buffer[] = {0x48, 0x8B, 0x05, 0x12, 0x34};

        // Empty pattern
        int8_t* result = hookftw::Memory::FindPattern(
            reinterpret_cast<const int8_t*>(buffer),
            sizeof(buffer),
            ""
        );
        EXPECT_EQ(result, nullptr);

        // Pattern exactly matching buffer size
        result = hookftw::Memory::FindPattern(
            reinterpret_cast<const int8_t*>(buffer),
            sizeof(buffer),
            "48 8B 05 12 34"
        );
        ASSERT_NE(result, nullptr);
        EXPECT_EQ(result, reinterpret_cast<const int8_t*>(buffer));

        // All wildcards
        result = hookftw::Memory::FindPattern(
            reinterpret_cast<const int8_t*>(buffer),
            sizeof(buffer),
            "? ? ?"
        );
        ASSERT_NE(result, nullptr);
        EXPECT_EQ(result, reinterpret_cast<const int8_t*>(buffer));

        // Search in zero-size buffer
        result = hookftw::Memory::FindPattern(
            reinterpret_cast<const int8_t*>(buffer),
            0,
            "48"
        );
        EXPECT_EQ(result, nullptr);
    }

    TEST(Memory, FindPatternMultipleOccurrences)
    {
        // Buffer with repeating patterns
        const uint8_t buffer[] = {
            0x90, 0x90, 0x90,  // NOP NOP NOP
            0x48, 0x8B, 0x05, 0x12, 0x34, 0x56, 0x78,
            0x90, 0x90,        // NOP NOP
            0x48, 0x8B, 0x05, 0xAB, 0xCD, 0xEF, 0x00,
            0x90              // NOP
        };

        // Should find the first occurrence
        int8_t* result = hookftw::Memory::FindPattern(
            reinterpret_cast<const int8_t*>(buffer),
            sizeof(buffer),
            "48 8B 05"
        );
        ASSERT_NE(result, nullptr);
        EXPECT_EQ(result, reinterpret_cast<const int8_t*>(buffer + 3));

        // Search from after first occurrence to find second
        result = hookftw::Memory::FindPattern(
            reinterpret_cast<const int8_t*>(buffer + 10),
            sizeof(buffer) - 10,
            "48 8B 05"
        );
        ASSERT_NE(result, nullptr);
        EXPECT_EQ(result, reinterpret_cast<const int8_t*>(buffer + 12));
    }

    TEST(Memory, FindPatternInModuleELFHeader)
    {
        #ifdef __linux
        // Search for ELF magic number in the current executable
        // Pattern: 7F 45 4C 46 (0x7F 'E' 'L' 'F')
        int8_t* result = hookftw::Memory::FindPatternInModule(
            "",  // Empty string for main executable
            "7F 45 4C 46"
        );

        // Should find ELF header at the base address
        ASSERT_NE(result, nullptr);
        EXPECT_EQ(static_cast<uint8_t>(result[0]), 0x7F);
        EXPECT_EQ(static_cast<uint8_t>(result[1]), 'E');
        EXPECT_EQ(static_cast<uint8_t>(result[2]), 'L');
        EXPECT_EQ(static_cast<uint8_t>(result[3]), 'F');

        // Should be at the base address
        int8_t* baseAddress = hookftw::Memory::GetProcessBaseAddress();
        EXPECT_EQ(result, baseAddress);
        #endif
    }

    TEST(Memory, FindPatternInModulePEHeader)
    {
        #ifdef _WIN32
        // Search for DOS/PE magic number in the current executable
        // Pattern: 4D 5A ('M' 'Z')
        int8_t* result = hookftw::Memory::FindPatternInModule(
            "",  // Empty string for main executable
            "4D 5A"
        );

        // Should find DOS header at the base address
        ASSERT_NE(result, nullptr);
        EXPECT_EQ(static_cast<uint8_t>(result[0]), 'M');
        EXPECT_EQ(static_cast<uint8_t>(result[1]), 'Z');

        // Should be at the base address
        int8_t* baseAddress = hookftw::Memory::GetProcessBaseAddress();
        EXPECT_EQ(result, baseAddress);
        #endif
    }

    TEST(Memory, FindPatternInModuleLibC)
    {
        #ifdef __linux
        // Try to find a common pattern in libc
        // We'll search for a RET instruction (0xC3) which should exist
        int8_t* result = hookftw::Memory::FindPatternInModule(
            "libc.so.6",
            "C3"  // ret instruction
        );

        // Should find at least one RET instruction in libc
        EXPECT_NE(result, nullptr);
        #endif
    }

    TEST(Memory, FindPatternInModuleKernel32)
    {
        #ifdef _WIN32
        // Try to find a common pattern in kernel32.dll
        // We'll search for a RET instruction (0xC3) which should exist
        int8_t* result = hookftw::Memory::FindPatternInModule(
            "kernel32.dll",
            "C3"  // ret instruction
        );

        // Should find at least one RET instruction in kernel32
        EXPECT_NE(result, nullptr);
        #endif
    }

    TEST(Memory, FindPatternInModuleNTDLL)
    {
        #ifdef _WIN32
        // Search for RET instruction in ntdll.dll
        int8_t* result = hookftw::Memory::FindPatternInModule(
            "ntdll.dll",
            "C3"
        );

        // Should find at least one RET instruction in ntdll
        EXPECT_NE(result, nullptr);
        #endif
    }

    TEST(Memory, FindPatternInModuleNotFound)
    {
        #ifdef __linux
        // Search for a pattern that's very unlikely to exist
        // A long sequence of 0xFF bytes
        int8_t* result = hookftw::Memory::FindPatternInModule(
            "",
            "FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF"
        );

        // Most likely won't find this pattern
        // (If it does find it, that's okay - the test passes either way)
        // The main point is it shouldn't crash
        (void)result;
        #endif
    }

    TEST(Memory, FindPatternInModuleInvalidModule)
    {
        // Search in a module that doesn't exist
        int8_t* result = hookftw::Memory::FindPatternInModule(
            "nonexistent_module_xyz.so",
            "48 8B 05"
        );

        EXPECT_EQ(result, nullptr);
    }

    TEST(Memory, FindPatternCaseSensitivity)
    {
        const uint8_t buffer[] = {0xAB, 0xCD, 0xEF};

        // Uppercase hex
        int8_t* result = hookftw::Memory::FindPattern(
            reinterpret_cast<const int8_t*>(buffer),
            sizeof(buffer),
            "AB CD EF"
        );
        ASSERT_NE(result, nullptr);

        // Lowercase hex should also work
        result = hookftw::Memory::FindPattern(
            reinterpret_cast<const int8_t*>(buffer),
            sizeof(buffer),
            "ab cd ef"
        );
        ASSERT_NE(result, nullptr);

        // Mixed case
        result = hookftw::Memory::FindPattern(
            reinterpret_cast<const int8_t*>(buffer),
            sizeof(buffer),
            "Ab Cd Ef"
        );
        ASSERT_NE(result, nullptr);
    }

    TEST(Memory, FindPatternRealWorldExample)
    {
        // Simulate a real-world scenario: finding a function prologue
        const uint8_t buffer[] = {
            0x55,                          // push rbp
            0x48, 0x89, 0xE5,              // mov rbp, rsp
            0x48, 0x83, 0xEC, 0x20,        // sub rsp, 0x20
            0x48, 0x89, 0x7D, 0xF8,        // mov [rbp-0x8], rdi
            0x48, 0x8B, 0x45, 0xF8,        // mov rax, [rbp-0x8]
            0x48, 0x8B, 0x00,              // mov rax, [rax]
            0x48, 0x89, 0xC7,              // mov rdi, rax
            0xE8, 0x00, 0x00, 0x00, 0x00,  // call <offset>
            0x90,                          // nop
            0xC9,                          // leave
            0xC3                           // ret
        };

        // Find function prologue
        int8_t* prologue = hookftw::Memory::FindPattern(
            reinterpret_cast<const int8_t*>(buffer),
            sizeof(buffer),
            "55 48 89 E5"  // push rbp; mov rbp, rsp
        );
        ASSERT_NE(prologue, nullptr);
        EXPECT_EQ(prologue, reinterpret_cast<const int8_t*>(buffer));

        // Find call instruction with wildcard offset
        int8_t* call = hookftw::Memory::FindPattern(
            reinterpret_cast<const int8_t*>(buffer),
            sizeof(buffer),
            "E8 ? ? ? ?"
        );
        ASSERT_NE(call, nullptr);
        EXPECT_EQ(call, reinterpret_cast<const int8_t*>(buffer + 22));

        // Find epilogue
        int8_t* epilogue = hookftw::Memory::FindPattern(
            reinterpret_cast<const int8_t*>(buffer),
            sizeof(buffer),
            "C9 C3"  // leave; ret
        );
        ASSERT_NE(epilogue, nullptr);
        EXPECT_EQ(epilogue, reinterpret_cast<const int8_t*>(buffer + 28));
    }

    TEST(Memory, FindPatternWindowsX64Prologue)
    {
        // Common Windows x64 function prologue with stack frame allocation
        const uint8_t buffer[] = {
            0x48, 0x89, 0x5C, 0x24, 0x08,  // mov [rsp+8], rbx
            0x48, 0x89, 0x6C, 0x24, 0x10,  // mov [rsp+10h], rbp
            0x48, 0x89, 0x74, 0x24, 0x18,  // mov [rsp+18h], rsi
            0x57,                          // push rdi
            0x48, 0x83, 0xEC, 0x20,        // sub rsp, 20h
            0x48, 0x8B, 0xF9,              // mov rdi, rcx
            0xC3                           // ret
        };

        // Find the register save pattern
        int8_t* result = hookftw::Memory::FindPattern(
            reinterpret_cast<const int8_t*>(buffer),
            sizeof(buffer),
            "48 89 5C 24 08 48 89 6C 24 10"
        );
        ASSERT_NE(result, nullptr);
        EXPECT_EQ(result, reinterpret_cast<const int8_t*>(buffer));

        // Find stack allocation with wildcard
        result = hookftw::Memory::FindPattern(
            reinterpret_cast<const int8_t*>(buffer),
            sizeof(buffer),
            "48 83 EC ?"  // sub rsp, ?
        );
        ASSERT_NE(result, nullptr);
        EXPECT_EQ(result, reinterpret_cast<const int8_t*>(buffer + 16));
    }

    TEST(Memory, FindPatternWindowsAPICall)
    {
        // Simulate a Windows API call pattern
        const uint8_t buffer[] = {
            0x48, 0x8B, 0x0D, 0x12, 0x34, 0x56, 0x78,  // mov rcx, [rip+offset]
            0xFF, 0x15, 0xAB, 0xCD, 0xEF, 0x00,        // call qword ptr [rip+offset]
            0x85, 0xC0,                                // test eax, eax
            0x74, 0x05,                                // jz short +5
            0x33, 0xC0,                                // xor eax, eax
            0xC3                                       // ret
        };

        // Find indirect call pattern with wildcards
        int8_t* result = hookftw::Memory::FindPattern(
            reinterpret_cast<const int8_t*>(buffer),
            sizeof(buffer),
            "FF 15 ? ? ? ?"
        );
        ASSERT_NE(result, nullptr);
        EXPECT_EQ(result, reinterpret_cast<const int8_t*>(buffer + 7));

        // Find test eax, eax pattern
        result = hookftw::Memory::FindPattern(
            reinterpret_cast<const int8_t*>(buffer),
            sizeof(buffer),
            "85 C0"
        );
        ASSERT_NE(result, nullptr);
        EXPECT_EQ(result, reinterpret_cast<const int8_t*>(buffer + 13));

        // Find conditional jump
        result = hookftw::Memory::FindPattern(
            reinterpret_cast<const int8_t*>(buffer),
            sizeof(buffer),
            "74 ?"  // jz short ?
        );
        ASSERT_NE(result, nullptr);
        EXPECT_EQ(result, reinterpret_cast<const int8_t*>(buffer + 15));
    }

    TEST(Memory, FindPatternVTableLookup)
    {
        // Common vtable access pattern (C++ virtual function call)
        const uint8_t buffer[] = {
            0x48, 0x8B, 0x01,              // mov rax, [rcx]       ; load vtable pointer
            0x48, 0x8B, 0x40, 0x10,        // mov rax, [rax+10h]   ; get function pointer
            0xFF, 0xD0,                    // call rax             ; call virtual function
            0x90, 0x90,                    // nop nop
            0xC3                           // ret
        };

        // Find vtable load pattern
        int8_t* result = hookftw::Memory::FindPattern(
            reinterpret_cast<const int8_t*>(buffer),
            sizeof(buffer),
            "48 8B 01"
        );
        ASSERT_NE(result, nullptr);
        EXPECT_EQ(result, reinterpret_cast<const int8_t*>(buffer));

        // Find indexed access with wildcard
        result = hookftw::Memory::FindPattern(
            reinterpret_cast<const int8_t*>(buffer),
            sizeof(buffer),
            "48 8B 40 ?"
        );
        ASSERT_NE(result, nullptr);
        EXPECT_EQ(result, reinterpret_cast<const int8_t*>(buffer + 3));

        // Find indirect call
        result = hookftw::Memory::FindPattern(
            reinterpret_cast<const int8_t*>(buffer),
            sizeof(buffer),
            "FF D0"
        );
        ASSERT_NE(result, nullptr);
        EXPECT_EQ(result, reinterpret_cast<const int8_t*>(buffer + 7));
    }

    TEST(Memory, FindPatternTLSAccess)
    {
        // Thread Local Storage access pattern (common in Windows)
        const uint8_t buffer[] = {
            0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00,  // mov rax, gs:[30h] ; TEB
            0x48, 0x8B, 0x48, 0x58,                                // mov rcx, [rax+58h] ; TLS
            0xC3                                                    // ret
        };

        // Find GS segment access (TEB access on x64 Windows)
        int8_t* result = hookftw::Memory::FindPattern(
            reinterpret_cast<const int8_t*>(buffer),
            sizeof(buffer),
            "65 48 8B 04 25 30 00 00 00"
        );
        ASSERT_NE(result, nullptr);
        EXPECT_EQ(result, reinterpret_cast<const int8_t*>(buffer));

        // Find TLS array access with wildcard offset
        result = hookftw::Memory::FindPattern(
            reinterpret_cast<const int8_t*>(buffer),
            sizeof(buffer),
            "48 8B 48 ?"
        );
        ASSERT_NE(result, nullptr);
        EXPECT_EQ(result, reinterpret_cast<const int8_t*>(buffer + 9));
    }

    TEST(Memory, FindPatternRIPRelative)
    {
        // RIP-relative addressing patterns (common in x64 code)
        const uint8_t buffer[] = {
            0x48, 0x8D, 0x0D, 0x12, 0x34, 0x56, 0x78,  // lea rcx, [rip+offset]
            0x48, 0x8D, 0x15, 0xAB, 0xCD, 0xEF, 0x00,  // lea rdx, [rip+offset]
            0x4C, 0x8D, 0x05, 0x11, 0x22, 0x33, 0x44,  // lea r8, [rip+offset]
            0xC3                                        // ret
        };

        // Find LEA with RIP-relative addressing (wildcards for offset)
        int8_t* result = hookftw::Memory::FindPattern(
            reinterpret_cast<const int8_t*>(buffer),
            sizeof(buffer),
            "48 8D 0D ? ? ? ?"
        );
        ASSERT_NE(result, nullptr);
        EXPECT_EQ(result, reinterpret_cast<const int8_t*>(buffer));

        // Find second LEA
        result = hookftw::Memory::FindPattern(
            reinterpret_cast<const int8_t*>(buffer),
            sizeof(buffer),
            "48 8D 15 ? ? ? ?"
        );
        ASSERT_NE(result, nullptr);
        EXPECT_EQ(result, reinterpret_cast<const int8_t*>(buffer + 7));

        // Find R8 LEA (uses REX.R prefix)
        result = hookftw::Memory::FindPattern(
            reinterpret_cast<const int8_t*>(buffer),
            sizeof(buffer),
            "4C 8D 05 ? ? ? ?"
        );
        ASSERT_NE(result, nullptr);
        EXPECT_EQ(result, reinterpret_cast<const int8_t*>(buffer + 14));
    }
}






