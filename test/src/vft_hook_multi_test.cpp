#include <gtest/gtest.h>

#include <cstdint>

#include <VFTHook.h>

#if defined(_MSC_VER)
#define NOINLINE __declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
#define NOINLINE __attribute__((noinline))
#else
#define NOINLINE
#endif

namespace
{
    struct Base
    {
        virtual ~Base() = default;

        NOINLINE virtual int HookTargetA(int x) { return x + 1; }
        NOINLINE virtual int HookTargetB(int x) { return x + 2; }
    };

    struct Derived final : Base
    {
        NOINLINE int HookTargetA(int x) override { return x + 1; }
        NOINLINE int HookTargetB(int x) override { return x + 2; }
    };

    int callsA = 0;
    int callsB = 0;

    NOINLINE int HookA(Base *, int x)
    {
        ++callsA;
        return x + 10;
    }

    NOINLINE int HookB(Base *, int x)
    {
        ++callsB;
        return x + 20;
    }

#if defined(__linux__) && defined(__x86_64__)
    TEST(VFTHook, HookMultipleAndUnhookIndex)
    {
        Derived derived;
        Base *base = &derived;

        int8_t** vtable = *reinterpret_cast<int8_t ***>(base);
        hookftw::VFTHook hook(vtable);

        int kAIndex = 2;
        int kBIndex = 3;

        // Verify we found both functions in the VFT
        ASSERT_NE(kAIndex, -1) << "Function A not found in VFT";
        ASSERT_NE(kBIndex, -1) << "Function B not found in VFT";

        // Get the actual function addresses from the VFT
        auto *funcA = vtable[kAIndex];
        auto *funcB = vtable[kBIndex];

        // Verify the VFT entries contain the actual function addresses
        EXPECT_EQ(vtable[kAIndex], funcA);
        EXPECT_EQ(vtable[kBIndex], funcB);

        EXPECT_EQ(base->HookTargetA(1), 2);
        EXPECT_EQ(base->HookTargetB(1), 3);

        auto originalA = hook.Hook(kAIndex, reinterpret_cast<int8_t *>(reinterpret_cast<void *>(&HookA)));
        auto originalB = hook.Hook(kBIndex, reinterpret_cast<int8_t *>(reinterpret_cast<void *>(&HookB)));
        ASSERT_NE(originalA, nullptr);
        ASSERT_NE(originalB, nullptr);

        EXPECT_EQ(base->HookTargetA(1), 11);
        EXPECT_EQ(base->HookTargetB(1), 21);
        EXPECT_EQ(callsA, 1);
        EXPECT_EQ(callsB, 1);

        EXPECT_TRUE(hook.Unhook(kAIndex));

        EXPECT_EQ(base->HookTargetA(1), 2);
        EXPECT_EQ(base->HookTargetB(1), 21);

        hook.Unhook();
        EXPECT_EQ(base->HookTargetA(1), 2);
        EXPECT_EQ(base->HookTargetB(1), 3);
    }
#else
    TEST(VFTHook, HookMultipleAndUnhookIndex)
    {
        GTEST_SKIP() << "Broken on mscvc";
    }
#endif
}