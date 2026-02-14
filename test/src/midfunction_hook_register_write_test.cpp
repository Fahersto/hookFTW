#include <gtest/gtest.h>

#include <cstdint>

#include <MidfunctionHook.h>


#if defined(_MSC_VER)
#define NOINLINE __declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
#define NOINLINE __attribute__((noinline))
#else
#define NOINLINE
#endif

namespace
{
    #if defined(__x86_64__) || defined(_M_X64)

    // Register reading functions - platform specific implementations
    // Use System V AMD64 ABI (used on Linux and Unix-like systems)
    // vs Microsoft x64 calling convention (used on Windows)
    #if defined(__unix__) || defined(__APPLE__) || defined(__linux__)
    // System V AMD64 ABI: RDI, RSI, RDX, RCX, R8, R9 for first 6 args

    NOINLINE int ReadRDI(int x)
    {
        (void)x;
        int out;
        asm volatile(
            "movl %%edi, %0\n"
            : "=r"(out)
            :
            : "memory");
        return out;
    }

    NOINLINE int ReadRSI(int x, int y)
    {
        (void)x; (void)y;
        int out;
        asm volatile(
            "movl %%esi, %0\n"
            : "=r"(out)
            :
            : "memory");
        return out;
    }

    NOINLINE int ReadRDX(int x, int y, int z)
    {
        (void)x; (void)y; (void)z;
        int out;
        asm volatile(
            "movl %%edx, %0\n"
            : "=r"(out)
            :
            : "memory");
        return out;
    }

    NOINLINE int ReadRCX(int x, int y, int z, int w)
    {
        (void)x; (void)y; (void)z; (void)w;
        int out;
        asm volatile(
            "movl %%ecx, %0\n"
            : "=r"(out)
            :
            : "memory");
        return out;
    }

    NOINLINE int ReadR8(int x, int y, int z, int w, int v)
    {
        (void)x; (void)y; (void)z; (void)w; (void)v;
        int out;
        asm volatile(
            "movl %%r8d, %0\n"
            : "=r"(out)
            :
            : "memory");
        return out;
    }

    NOINLINE int ReadR9(int x, int y, int z, int w, int v, int u)
    {
        (void)x; (void)y; (void)z; (void)w; (void)v; (void)u;
        int out;
        asm volatile(
            "movl %%r9d, %0\n"
            : "=r"(out)
            :
            : "memory");
        return out;
    }

    #elif defined(_WIN32) || defined(_WIN64)
    // Microsoft x64 calling convention (Windows)
    // RCX, RDX, R8, R9 for first 4 args, rest on stack

    NOINLINE int ReadRCX(int x)
    {
        // First argument is in RCX on Windows x64
        return x;
    }

    NOINLINE int ReadRDX(int x, int y)
    {
        // Second argument is in RDX on Windows x64
        (void)x;
        return y;
    }

    NOINLINE int ReadR8(int x, int y, int z)
    {
        // Third argument is in R8 on Windows x64
        (void)x; (void)y;
        return z;
    }

    NOINLINE int ReadR9(int x, int y, int z, int w)
    {
        // Fourth argument is in R9 on Windows x64
        (void)x; (void)y; (void)z;
        return w;
    }

    // On Windows x64, there are only 4 register parameters, rest are on stack
    // We'll define RDI and RSI to use stack parameters
    NOINLINE int ReadStackParam5(int x, int y, int z, int w, int v)
    {
        (void)x; (void)y; (void)z; (void)w;
        return v;
    }

    NOINLINE int ReadStackParam6(int x, int y, int z, int w, int v, int u)
    {
        (void)x; (void)y; (void)z; (void)w; (void)v;
        return u;
    }

    #endif

    // Hook functions - same for all platforms
    void HkWriteReg1(hookftw::context* ctx)
    {
        #if defined(__unix__) || defined(__APPLE__) || defined(__linux__)
        ctx->rdi = 1337;  // Linux: first arg in RDI
        #elif defined(_WIN32) || defined(_WIN64)
        ctx->rcx = 1337;  // Windows: first arg in RCX
        #endif
    }

    void HkWriteReg2(hookftw::context* ctx)
    {
        #if defined(__unix__) || defined(__APPLE__) || defined(__linux__)
        ctx->rsi = 1338;  // Linux: second arg in RSI
        #elif defined(_WIN32) || defined(_WIN64)
        ctx->rdx = 1338;  // Windows: second arg in RDX
        #endif
    }

    void HkWriteReg3(hookftw::context* ctx)
    {
        #if defined(__unix__) || defined(__APPLE__) || defined(__linux__)
        ctx->rdx = 1339;  // Linux: third arg in RDX
        #elif defined(_WIN32) || defined(_WIN64)
        ctx->r8 = 1339;   // Windows: third arg in R8
        #endif
    }

    void HkWriteReg4(hookftw::context* ctx)
    {
        #if defined(__unix__) || defined(__APPLE__) || defined(__linux__)
        ctx->rcx = 1340;  // Linux: fourth arg in RCX
        #elif defined(_WIN32) || defined(_WIN64)
        ctx->r9 = 1340;   // Windows: fourth arg in R9
        #endif
    }

    void HkWriteReg5(hookftw::context* ctx)
    {
        #if defined(__unix__) || defined(__APPLE__) || defined(__linux__)
        ctx->r8 = 1341;   // Linux: fifth arg in R8
        #elif defined(_WIN32) || defined(_WIN64)
        // Windows: fifth arg is on stack, modify stack value
        // Stack layout: [return addr][shadow space 32 bytes][5th param]
        int64_t* stackParam = reinterpret_cast<int64_t*>(ctx->rsp + 8 + 32);
        *stackParam = 1341;
        #endif
    }

    void HkWriteReg6(hookftw::context* ctx)
    {
        #if defined(__unix__) || defined(__APPLE__) || defined(__linux__)
        ctx->r9 = 1342;   // Linux: sixth arg in R9
        #elif defined(_WIN32) || defined(_WIN64)
        // Windows: sixth arg is on stack
        int64_t* stackParam = reinterpret_cast<int64_t*>(ctx->rsp + 8 + 32 + 8);
        *stackParam = 1342;
        #endif
    }

    // Tests - platform-specific function names but same test logic
    #if defined(__unix__) || defined(__APPLE__) || defined(__linux__)

    TEST(MidfunctionHookLinux, ProxyCanRewriteRdiArgument)
    {
        hookftw::MidfunctionHook hook;
        EXPECT_EQ(ReadRDI(7), 7);
        hook.Hook(reinterpret_cast<int8_t*>(&ReadRDI), &HkWriteReg1);
        EXPECT_EQ(ReadRDI(7), 1337);
        hook.Unhook();
        EXPECT_EQ(ReadRDI(7), 7);
    }

    TEST(MidfunctionHookLinux, ProxyCanRewriteRsiArgument)
    {
        hookftw::MidfunctionHook hook;
        EXPECT_EQ(ReadRSI(1, 8), 8);
        hook.Hook(reinterpret_cast<int8_t*>(&ReadRSI), &HkWriteReg2);
        EXPECT_EQ(ReadRSI(1, 8), 1338);
        hook.Unhook();
        EXPECT_EQ(ReadRSI(1, 8), 8);
    }

    TEST(MidfunctionHookLinux, ProxyCanRewriteRdxArgument)
    {
        hookftw::MidfunctionHook hook;
        EXPECT_EQ(ReadRDX(1, 2, 9), 9);
        hook.Hook(reinterpret_cast<int8_t*>(&ReadRDX), &HkWriteReg3);
        EXPECT_EQ(ReadRDX(1, 2, 9), 1339);
        hook.Unhook();
        EXPECT_EQ(ReadRDX(1, 2, 9), 9);
    }

    TEST(MidfunctionHookLinux, ProxyCanRewriteRcxArgument)
    {
        hookftw::MidfunctionHook hook;
        EXPECT_EQ(ReadRCX(1, 2, 3, 10), 10);
        hook.Hook(reinterpret_cast<int8_t*>(&ReadRCX), &HkWriteReg4);
        EXPECT_EQ(ReadRCX(1, 2, 3, 10), 1340);
        hook.Unhook();
        EXPECT_EQ(ReadRCX(1, 2, 3, 10), 10);
    }

    TEST(MidfunctionHookLinux, ProxyCanRewriteR8Argument)
    {
        hookftw::MidfunctionHook hook;
        EXPECT_EQ(ReadR8(1, 2, 3, 4, 11), 11);
        hook.Hook(reinterpret_cast<int8_t*>(&ReadR8), &HkWriteReg5);
        EXPECT_EQ(ReadR8(1, 2, 3, 4, 11), 1341);
        hook.Unhook();
        EXPECT_EQ(ReadR8(1, 2, 3, 4, 11), 11);
    }

    TEST(MidfunctionHookLinux, ProxyCanRewriteR9Argument)
    {
        hookftw::MidfunctionHook hook;
        EXPECT_EQ(ReadR9(1, 2, 3, 4, 5, 12), 12);
        hook.Hook(reinterpret_cast<int8_t*>(&ReadR9), &HkWriteReg6);
        EXPECT_EQ(ReadR9(1, 2, 3, 4, 5, 12), 1342);
        hook.Unhook();
        EXPECT_EQ(ReadR9(1, 2, 3, 4, 5, 12), 12);
    }

    #elif defined(_WIN32) || defined(_WIN64)

    TEST(MidfunctionHookWindows, ProxyCanRewriteRcxArgument)
    {
        hookftw::MidfunctionHook hook;
        EXPECT_EQ(ReadRCX(7), 7);
        hook.Hook(reinterpret_cast<int8_t*>(&ReadRCX), &HkWriteReg1);
        EXPECT_EQ(ReadRCX(7), 1337);
        hook.Unhook();
        EXPECT_EQ(ReadRCX(7), 7);
    }

    TEST(MidfunctionHookWindows, ProxyCanRewriteRdxArgument)
    {
        hookftw::MidfunctionHook hook;
        EXPECT_EQ(ReadRDX(1, 8), 8);
        hook.Hook(reinterpret_cast<int8_t*>(&ReadRDX), &HkWriteReg2);
        EXPECT_EQ(ReadRDX(1, 8), 1338);
        hook.Unhook();
        EXPECT_EQ(ReadRDX(1, 8), 8);
    }

    TEST(MidfunctionHookWindows, ProxyCanRewriteR8Argument)
    {
        hookftw::MidfunctionHook hook;
        EXPECT_EQ(ReadR8(1, 2, 9), 9);
        hook.Hook(reinterpret_cast<int8_t*>(&ReadR8), &HkWriteReg3);
        EXPECT_EQ(ReadR8(1, 2, 9), 1339);
        hook.Unhook();
        EXPECT_EQ(ReadR8(1, 2, 9), 9);
    }

    TEST(MidfunctionHookWindows, ProxyCanRewriteR9Argument)
    {
        hookftw::MidfunctionHook hook;
        EXPECT_EQ(ReadR9(1, 2, 3, 10), 10);
        hook.Hook(reinterpret_cast<int8_t*>(&ReadR9), &HkWriteReg4);
        EXPECT_EQ(ReadR9(1, 2, 3, 10), 1340);
        hook.Unhook();
        EXPECT_EQ(ReadR9(1, 2, 3, 10), 10);
    }

    TEST(MidfunctionHookWindows, ProxyCanRewriteStackParam5)
    {
        hookftw::MidfunctionHook hook;
        EXPECT_EQ(ReadStackParam5(1, 2, 3, 4, 11), 11);
        hook.Hook(reinterpret_cast<int8_t*>(&ReadStackParam5), &HkWriteReg5);
        EXPECT_EQ(ReadStackParam5(1, 2, 3, 4, 11), 1341);
        hook.Unhook();
        EXPECT_EQ(ReadStackParam5(1, 2, 3, 4, 11), 11);
    }

    TEST(MidfunctionHookWindows, ProxyCanRewriteStackParam6)
    {
        hookftw::MidfunctionHook hook;
        EXPECT_EQ(ReadStackParam6(1, 2, 3, 4, 5, 12), 12);
        hook.Hook(reinterpret_cast<int8_t*>(&ReadStackParam6), &HkWriteReg6);
        EXPECT_EQ(ReadStackParam6(1, 2, 3, 4, 5, 12), 1342);
        hook.Unhook();
        EXPECT_EQ(ReadStackParam6(1, 2, 3, 4, 5, 12), 12);
    }

    #endif

    #else  // Not x86_64


    // Skip stubs for non-x64 platforms - Linux test names
    TEST(MidfunctionHookLinux, ProxyCanRewriteRdiArgument)
    {
        GTEST_SKIP() << "Requires x86_64";
    }

    TEST(MidfunctionHookLinux, ProxyCanRewriteRsiArgument)
    {
        GTEST_SKIP() << "Requires x86_64";
    }

    TEST(MidfunctionHookLinux, ProxyCanRewriteRdxArgument)
    {
        GTEST_SKIP() << "Requires x86_64";
    }

    TEST(MidfunctionHookLinux, ProxyCanRewriteRcxArgument)
    {
        GTEST_SKIP() << "Requires x86_64";
    }

    TEST(MidfunctionHookLinux, ProxyCanRewriteR8Argument)
    {
        GTEST_SKIP() << "Requires x86_64";
    }

    TEST(MidfunctionHookLinux, ProxyCanRewriteR9Argument)
    {
        GTEST_SKIP() << "Requires x86_64";
    }

    // Skip stubs for non-x64 platforms - Windows test names
    TEST(MidfunctionHookWindows, ProxyCanRewriteRcxArgument)
    {
        GTEST_SKIP() << "Requires x86_64";
    }

    TEST(MidfunctionHookWindows, ProxyCanRewriteRdxArgument)
    {
        GTEST_SKIP() << "Requires x86_64";
    }

    TEST(MidfunctionHookWindows, ProxyCanRewriteR8Argument)
    {
        GTEST_SKIP() << "Requires x86_64";
    }

    TEST(MidfunctionHookWindows, ProxyCanRewriteR9Argument)
    {
        GTEST_SKIP() << "Requires x86_64";
    }

    TEST(MidfunctionHookWindows, ProxyCanRewriteStackParam5)
    {
        GTEST_SKIP() << "Requires x86_64";
    }

    TEST(MidfunctionHookWindows, ProxyCanRewriteStackParam6)
    {
        GTEST_SKIP() << "Requires x86_64";
    }

    #endif
}
