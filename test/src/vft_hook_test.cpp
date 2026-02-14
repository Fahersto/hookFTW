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
        NOINLINE virtual int Compute(int x) { return x + 1; }
    };

    struct Derived final : Base
    {
        NOINLINE int Compute(int x) override { return x + 1; }
    };

    int hookCalls = 0;

    NOINLINE int HookedCompute(Base* self, int x)
    {
        (void)self;
        ++hookCalls;
        return x + 42;
    }

#if defined(__linux__) && defined(__x86_64__)
    TEST(VFTHook, HooksVirtualMethodAndUnhooks)
    {
        Derived derived;
        Base* obj = &derived;

        hookCalls = 0;
        EXPECT_EQ(obj->Compute(1), 2);

        // vptr is stored as the first word of the object.
        int8_t** vtable = *reinterpret_cast<int8_t***>(obj);
        hookftw::VFTHook vftHook(vtable);

        constexpr int kComputeIndex = 2;
        auto original = vftHook.Hook(kComputeIndex, reinterpret_cast<int8_t*>(reinterpret_cast<void*>(&HookedCompute)));
        ASSERT_NE(original, nullptr);

        EXPECT_EQ(obj->Compute(1), 43);
        EXPECT_EQ(hookCalls, 1);

        vftHook.Unhook();

        EXPECT_EQ(obj->Compute(1), 2);
    }
#else
    TEST(VFTHook, HooksVirtualMethodAndUnhooks)
    {
        GTEST_SKIP() << "Broken on mscvc";
    }
#endif
}
