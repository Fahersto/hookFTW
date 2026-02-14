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

    std::atomic<int> callCount{0};

    NOINLINE int Target(int x)
    {
        callCount.fetch_add(1, std::memory_order_relaxed);
        return x + 5;
    }

    void TargetProxy(hookftw::context* ctx)
    {
        ctx->SkipOriginalFunction();
    }

    TEST(MidfunctionHook, SkipOriginalFunctionSkipsBody)
    {
        callCount.store(0, std::memory_order_relaxed);

        hookftw::MidfunctionHook hook;

        EXPECT_EQ(Target(10), 15);
        EXPECT_EQ(callCount.load(std::memory_order_relaxed), 1);

        hook.Hook(reinterpret_cast<int8_t*>(&Target), &TargetProxy);

        (void)Target(10);
        EXPECT_EQ(callCount.load(std::memory_order_relaxed), 1);

        hook.Unhook();

        EXPECT_EQ(Target(10), 15);
        EXPECT_EQ(callCount.load(std::memory_order_relaxed), 2);
    }

    #else

    TEST(MidfunctionHook, SkipOriginalFunctionSkipsBody)
    {
        GTEST_SKIP() << "Requires x86_64";
    }

    #endif
}
