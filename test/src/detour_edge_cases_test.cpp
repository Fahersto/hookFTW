#include <gtest/gtest.h>

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
    using Fn = int (*)(int);
    Fn originalFunction = nullptr;
    hookftw::Detour detour;

    NOINLINE int Target(int x)
    {
        return x * 3;
    }

    NOINLINE int TargetProxy(int x)
    {
        return (originalFunction ? originalFunction(x) : x) + 1;
    }

    TEST(Detour, UnhookWithoutHookDoesNotCrash)
    {
        hookftw::Detour d;
        d.Unhook();
        SUCCEED();
    }

    TEST(Detour, HookTwiceInSequenceAndUnhook)
    {
        originalFunction = reinterpret_cast<Fn>(detour.Hook(reinterpret_cast<int8_t*>(&Target), reinterpret_cast<int8_t*>(&TargetProxy)));
        ASSERT_NE(originalFunction, nullptr);

        EXPECT_EQ(Target(2), 7); // (2*3)+1

        detour.Unhook();
        EXPECT_EQ(Target(2), 6);

        originalFunction = reinterpret_cast<Fn>(detour.Hook(reinterpret_cast<int8_t*>(&Target), reinterpret_cast<int8_t*>(&TargetProxy)));
        ASSERT_NE(originalFunction, nullptr);

        EXPECT_EQ(Target(3), 10);

        detour.Unhook();
        EXPECT_EQ(Target(3), 9);
    }
}
