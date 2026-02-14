#include <gtest/gtest.h>

#include <atomic>
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

    std::atomic<int> g_proxyCalls{0};

    NOINLINE int Target(int x)
    {
        return x + 5;
    }

    void TargetProxy(hookftw::context* ctx)
    {
        (void)ctx;
        g_proxyCalls.fetch_add(1, std::memory_order_relaxed);
    }

    TEST(MidfunctionHook, HookCallsProxyAndUnhookRestores)
    {
        g_proxyCalls.store(0, std::memory_order_relaxed);

        hookftw::MidfunctionHook hook;

        // Baseline behavior.
        EXPECT_EQ(Target(10), 15);

        hook.Hook(reinterpret_cast<int8_t*>(&Target), &TargetProxy);

        // Call should succeed and invoke proxy at least once.
        EXPECT_EQ(Target(10), 15);
        EXPECT_GE(g_proxyCalls.load(std::memory_order_relaxed), 1);

        hook.Unhook();

        int before = g_proxyCalls.load(std::memory_order_relaxed);
        EXPECT_EQ(Target(10), 15);
        EXPECT_EQ(g_proxyCalls.load(std::memory_order_relaxed), before);
    }

    TEST(MidfunctionHook, CallableOriginalCanBeInvokedFromProxy)
    {
        g_proxyCalls.store(0, std::memory_order_relaxed);

        static hookftw::MidfunctionHook* g_hookPtr = nullptr;
        static std::atomic<int> g_callOriginalResult{0};

        auto proxy = +[](hookftw::context* ctx)
        {
            g_proxyCalls.fetch_add(1, std::memory_order_relaxed);
            // Call original through the hook-provided callable address.
            #ifdef _WIN32
            const int res = ctx->CallOriginal<int, int>(hookftw::CallingConvention::default_call, 7);
            #else
            const int res = ctx->CallOriginal<int, int>(7);
            #endif
            g_callOriginalResult.store(res, std::memory_order_relaxed);
        };

        hookftw::MidfunctionHook hook;
        g_hookPtr = &hook;

        hook.Hook(reinterpret_cast<int8_t*>(&Target), proxy);

        EXPECT_EQ(Target(1), 6);
        EXPECT_GE(g_proxyCalls.load(std::memory_order_relaxed), 1);
        EXPECT_EQ(g_callOriginalResult.load(std::memory_order_relaxed), 12);

        hook.Unhook();
    }

    #else

    TEST(MidfunctionHook, HookCallsProxyAndUnhookRestores)
    {
        GTEST_SKIP() << "Requires x86_64";
    }

    TEST(MidfunctionHook, CallableOriginalCanBeInvokedFromProxy)
    {
        GTEST_SKIP() << "Requires x86_64";
    }

    #endif
}
