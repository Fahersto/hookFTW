#include <gtest/gtest.h>

#include <atomic>
#include <cstdint>

#include <Detour.h>

#if defined(_MSC_VER)
#define NOINLINE __declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
#define NOINLINE __attribute__((noinline))
#else
#define NOINLINE
#endif

namespace
{
    using TargetFn = int (*)(int);
    hookftw::Detour detour;
    TargetFn originalFunction = nullptr;
    std::atomic<int> callCount{0};

    NOINLINE int Target(int x)
    {
        callCount.fetch_add(1, std::memory_order_relaxed);
        return x + 1;
    }

    NOINLINE int TargetProxy(int x)
    {
        // Call original (through trampoline) and then modify.
        const int base = originalFunction ? originalFunction(x) : (x + 1000);
        return base + 10;
    }

#if defined(__linux__) && defined(__x86_64__)
    TEST(Detour, HookAndUnhookRestoresBehavior)
    {
        callCount.store(0, std::memory_order_relaxed);

        // Precondition.
        EXPECT_EQ(Target(5), 6);
        EXPECT_EQ(callCount.load(std::memory_order_relaxed), 1);

        originalFunction = reinterpret_cast<TargetFn>(detour.Hook(reinterpret_cast<int8_t *>(&Target), reinterpret_cast<int8_t *>(&TargetProxy)));

        ASSERT_NE(originalFunction, nullptr);
        EXPECT_EQ(Target(5), 16);
        EXPECT_GE(callCount.load(std::memory_order_relaxed), 2);

        detour.Unhook();
        int before = callCount.load(std::memory_order_relaxed);

        EXPECT_EQ(Target(5), 6);
        EXPECT_EQ(callCount.load(std::memory_order_relaxed), before + 1);
    }
#else
    TEST(Detour, HookAndUnhookRestoresBehavior)
    {
        GTEST_SKIP() << "Flacky on mscvc";
    }
#endif

}
