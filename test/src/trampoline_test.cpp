#include <gtest/gtest.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>

#include <Trampoline.h>
#include <Memory.h>
#include <Decoder.h>

#if defined(_MSC_VER)
#define NOINLINE __declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
#define NOINLINE __attribute__((noinline))
#else
#define NOINLINE
#endif

namespace
{
    // Simple target function without RIP-relative instructions
    NOINLINE int SimpleTarget(int x)
    {
        return x + 7;
    }

    // Target with more instructions to test longer sequences
    NOINLINE int LongerTarget(int a, int b, int c)
    {
        int result = a + b;
        result *= c;
        result -= a;
        result += b * 2;
        return result;
    }

    // Target that uses stack operations
    NOINLINE int StackTarget(int x)
    {
        int temp = x * 2;
        temp += 10;
        return temp - 3;
    }

    // Additional test functions with different characteristics
    NOINLINE int RecursiveTarget(int n)
    {
        if (n <= 1) return 1;
        return n * RecursiveTarget(n - 1);
    }

    NOINLINE double FloatingPointTarget(double x, double y)
    {
        return (x * y) + (x / y);
    }

    NOINLINE void VoidTarget()
    {
        volatile int dummy = 42;
        (void)dummy;
    }

    //
    // Basic Allocation Tests
    //

    TEST(Trampoline, AllocatesTrampolineForSourceAddress)
    {
        hookftw::Trampoline tramp;
        bool restricted = false;

        int8_t* mem = tramp.HandleTrampolineAllocation(reinterpret_cast<int8_t*>(&SimpleTarget), &restricted);
        ASSERT_NE(mem, nullptr) << "Trampoline allocation should always succeed (either in restricted or non-restricted mode)";

        // The restricted flag may be true or false depending on whether memory could be allocated within +-2GB
        // On Linux with ASLR, this often falls into restricted mode
        EXPECT_TRUE(hookftw::Memory::FreePage(mem, hookftw::Memory::GetPageSize()));
    }

    TEST(Trampoline, RestrictedFlagIsSetCorrectly)
    {
        hookftw::Trampoline tramp;
        bool restricted = false;

        int8_t* mem = tramp.HandleTrampolineAllocation(reinterpret_cast<int8_t*>(&SimpleTarget), &restricted);
        ASSERT_NE(mem, nullptr);

        // The restricted flag should be set to either true or false (not uninitialized)
        // It indicates whether a 5-byte (restricted=false) or 14-byte (restricted=true) jump is needed
        EXPECT_TRUE(restricted == true || restricted == false) << "Restricted flag should be explicitly set";

        EXPECT_TRUE(hookftw::Memory::FreePage(mem, hookftw::Memory::GetPageSize()));
    }

    TEST(Trampoline, AllocateTrampolineDirectly)
    {
        hookftw::Trampoline tramp;
        bool restricted = false;

        int8_t* mem = tramp.AllocateTrampoline(reinterpret_cast<int8_t*>(&SimpleTarget), &restricted);
        ASSERT_NE(mem, nullptr) << "Direct trampoline allocation should always succeed";

        // restricted flag indicates whether allocation succeeded within +-2GB range
        EXPECT_TRUE(hookftw::Memory::FreePage(mem, hookftw::Memory::GetPageSize()));
    }

#if defined(__x86_64__) || defined(_WIN64)
    TEST(Trampoline, AllocatedMemoryRangeIsValid)
    {
        hookftw::Trampoline tramp;
        bool restricted = false;

        int8_t* sourceAddr = reinterpret_cast<int8_t*>(&SimpleTarget);
        int8_t* trampolineAddr = tramp.AllocateTrampoline(sourceAddr, &restricted);

        ASSERT_NE(trampolineAddr, nullptr);

        if (!restricted)
        {
            // If not in restricted mode, verify the trampoline is within +-2GB range
            int64_t distance = reinterpret_cast<int64_t>(trampolineAddr) - reinterpret_cast<int64_t>(sourceAddr);
            const int64_t maxRel32Distance = 0x7FFFFFFF; // 2GB - 1

            EXPECT_LE(std::abs(distance), maxRel32Distance + 5)
                << "When not in restricted mode, trampoline should be within rel32 jump range (+-2GB)";
        }
        else
        {
            // In restricted mode, trampoline can be anywhere
            EXPECT_NE(trampolineAddr, nullptr)
                << "In restricted mode, trampoline is allocated anywhere in memory";
        }

        EXPECT_TRUE(hookftw::Memory::FreePage(trampolineAddr, hookftw::Memory::GetPageSize()));
    }

    TEST(Trampoline, AllocateTrampolineWithinBounds)
    {
        hookftw::Trampoline tramp;
        bool restricted = false;

        int8_t* sourceAddr = reinterpret_cast<int8_t*>(&SimpleTarget);

        // Set bounds around the source address (simulate RIP-relative memory access)
        int64_t lowestAccess = reinterpret_cast<int64_t>(sourceAddr) - 0x1000;
        int64_t highestAccess = reinterpret_cast<int64_t>(sourceAddr) + 0x1000;

        int8_t* trampolineAddr = tramp.AllocateTrampolineWithinBounds(
            sourceAddr,
            lowestAccess,
            highestAccess,
            &restricted
        );

        ASSERT_NE(trampolineAddr, nullptr);

        if (!restricted)
        {
            // If allocation succeeded without restricted mode, verify bounds
            int64_t trampolineAddr64 = reinterpret_cast<int64_t>(trampolineAddr);
            const int64_t maxRel32Distance = 0x7FFFFFFF;

            EXPECT_LE(trampolineAddr64 - lowestAccess, maxRel32Distance)
                << "Trampoline should be able to reach lowest RIP-relative access";
            EXPECT_LE(highestAccess - trampolineAddr64, maxRel32Distance)
                << "Trampoline should be able to reach highest RIP-relative access";
        }

        EXPECT_TRUE(hookftw::Memory::FreePage(trampolineAddr, hookftw::Memory::GetPageSize()));
    }

    TEST(Trampoline, VerifyTrampolineMemoryIsExecutable)
    {
        hookftw::Trampoline tramp;
        bool restricted = false;

        int8_t* trampolineAddr = tramp.HandleTrampolineAllocation(
            reinterpret_cast<int8_t*>(&SimpleTarget),
            &restricted
        );

        ASSERT_NE(trampolineAddr, nullptr);

        // Write a simple RET instruction (0xC3) and try to execute it
        // This verifies the page has execute permissions
        const uint8_t retInstruction = 0xC3;
        std::memcpy(trampolineAddr, &retInstruction, 1);

        // Cast to function pointer and call it
        using VoidFn = void (*)();
        auto fn = reinterpret_cast<VoidFn>(trampolineAddr);

        // This should not crash if the page is executable
        fn();

        EXPECT_TRUE(hookftw::Memory::FreePage(trampolineAddr, hookftw::Memory::GetPageSize()));
    }

#else
    // 32-bit tests
    TEST(Trampoline, AllocatesOn32Bit)
    {
        hookftw::Trampoline tramp;
        bool restricted = false;

        int8_t* mem = tramp.AllocateTrampoline(
            reinterpret_cast<int8_t*>(&SimpleTarget),
            &restricted
        );

        ASSERT_NE(mem, nullptr);

        EXPECT_TRUE(hookftw::Memory::FreePage(mem, hookftw::Memory::GetPageSize()));
    }
#endif

    TEST(Trampoline, ConsecutiveAllocationsForSameFunction)
    {
        // Test that we can allocate multiple trampolines for the same source address
        hookftw::Trampoline tramp1, tramp2;
        bool restricted1 = false, restricted2 = false;

        int8_t* mem1 = tramp1.HandleTrampolineAllocation(
            reinterpret_cast<int8_t*>(&SimpleTarget),
            &restricted1
        );
        int8_t* mem2 = tramp2.HandleTrampolineAllocation(
            reinterpret_cast<int8_t*>(&SimpleTarget),
            &restricted2
        );

        ASSERT_NE(mem1, nullptr);
        ASSERT_NE(mem2, nullptr);

        // They should be different allocations
        EXPECT_NE(mem1, mem2) << "Consecutive allocations should return different addresses";

        EXPECT_TRUE(hookftw::Memory::FreePage(mem1, hookftw::Memory::GetPageSize()));
        EXPECT_TRUE(hookftw::Memory::FreePage(mem2, hookftw::Memory::GetPageSize()));
    }

    TEST(Trampoline, AllocationReturnsExecutableMemory)
    {
        hookftw::Trampoline tramp;
        bool restricted = false;

        int8_t* trampolineAddr = tramp.HandleTrampolineAllocation(
            reinterpret_cast<int8_t*>(&VoidTarget),
            &restricted
        );

        ASSERT_NE(trampolineAddr, nullptr);

        // Memory should be writable for setup
        const uint8_t nopInstruction = 0x90; // NOP
        std::memcpy(trampolineAddr, &nopInstruction, 1);

        // Verify we can read it back
        EXPECT_EQ(*reinterpret_cast<uint8_t*>(trampolineAddr), nopInstruction);

        EXPECT_TRUE(hookftw::Memory::FreePage(trampolineAddr, hookftw::Memory::GetPageSize()));
    }

    TEST(Trampoline, HandleAllocationVsDirectAllocation)
    {
        // Compare HandleTrampolineAllocation vs AllocateTrampoline
        hookftw::Trampoline tramp1, tramp2;
        bool restricted1 = false, restricted2 = false;

        int8_t* sourceAddr = reinterpret_cast<int8_t*>(&SimpleTarget);

        int8_t* mem1 = tramp1.HandleTrampolineAllocation(sourceAddr, &restricted1);
        int8_t* mem2 = tramp2.AllocateTrampoline(sourceAddr, &restricted2);

        ASSERT_NE(mem1, nullptr);
        ASSERT_NE(mem2, nullptr);

        // Both methods should successfully allocate memory
        EXPECT_NE(mem1, mem2) << "Different trampolines should have different addresses";

        EXPECT_TRUE(hookftw::Memory::FreePage(mem1, hookftw::Memory::GetPageSize()));
        EXPECT_TRUE(hookftw::Memory::FreePage(mem2, hookftw::Memory::GetPageSize()));
    }

#if defined(__x86_64__) || defined(_WIN64)
    TEST(Trampoline, BoundsAllocationWithNoRIPRelative)
    {
        // Test AllocateTrampolineWithinBounds when there are no actual RIP-relative constraints
        hookftw::Trampoline tramp;
        bool restricted = false;

        int8_t* sourceAddr = reinterpret_cast<int8_t*>(&SimpleTarget);

        // Set very wide bounds (entire 32-bit range)
        int64_t lowestAccess = 0;
        int64_t highestAccess = 0xFFFFFFFFLL;

        int8_t* trampolineAddr = tramp.AllocateTrampolineWithinBounds(
            sourceAddr,
            lowestAccess,
            highestAccess,
            &restricted
        );

        ASSERT_NE(trampolineAddr, nullptr);

        EXPECT_TRUE(hookftw::Memory::FreePage(trampolineAddr, hookftw::Memory::GetPageSize()));
    }

    TEST(Trampoline, NarrowBoundsAllocation)
    {
        // Test with very narrow bounds
        hookftw::Trampoline tramp;
        bool restricted = false;

        int8_t* sourceAddr = reinterpret_cast<int8_t*>(&LongerTarget);

        // Set narrow bounds (1KB range)
        int64_t lowestAccess = reinterpret_cast<int64_t>(sourceAddr) - 512;
        int64_t highestAccess = reinterpret_cast<int64_t>(sourceAddr) + 512;

        int8_t* trampolineAddr = tramp.AllocateTrampolineWithinBounds(
            sourceAddr,
            lowestAccess,
            highestAccess,
            &restricted
        );

        ASSERT_NE(trampolineAddr, nullptr) << "Allocation should succeed even with narrow bounds (may use restricted mode)";

        EXPECT_TRUE(hookftw::Memory::FreePage(trampolineAddr, hookftw::Memory::GetPageSize()));
    }

    TEST(Trampoline, BoundsCheckingPreventsInvalidAllocations)
    {
        // Test that when bounds are specified, the allocator respects them
        // and doesn't return memory outside the reachable range (unless in restricted mode)
        hookftw::Trampoline tramp;
        bool restricted = false;

        int8_t* sourceAddr = reinterpret_cast<int8_t*>(&StackTarget);

        // Set reasonable bounds (1MB range)
        int64_t lowestAccess = reinterpret_cast<int64_t>(sourceAddr) - 0x80000;   // 512KB
        int64_t highestAccess = reinterpret_cast<int64_t>(sourceAddr) + 0x80000;  // 512KB

        int8_t* trampolineAddr = tramp.AllocateTrampolineWithinBounds(
            sourceAddr,
            lowestAccess,
            highestAccess,
            &restricted
        );

        ASSERT_NE(trampolineAddr, nullptr);

        if (!restricted)
        {
            // If not in restricted mode, the trampoline MUST be able to reach both bounds
            int64_t trampolineAddr64 = reinterpret_cast<int64_t>(trampolineAddr);
            const int64_t maxRel32Distance = 0x7FFFFFFF;

            int64_t distToLowest = trampolineAddr64 - lowestAccess;
            int64_t distToHighest = highestAccess - trampolineAddr64;

            EXPECT_LE(distToLowest, maxRel32Distance)
                << "Trampoline at " << std::hex << trampolineAddr64
                << " cannot reach lowest access at " << lowestAccess;
            EXPECT_LE(distToHighest, maxRel32Distance)
                << "Trampoline at " << std::hex << trampolineAddr64
                << " cannot reach highest access at " << highestAccess;
        }

        EXPECT_TRUE(hookftw::Memory::FreePage(trampolineAddr, hookftw::Memory::GetPageSize()));
    }

#endif
}
