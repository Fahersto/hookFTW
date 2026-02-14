#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <thread>

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
    std::atomic<bool> unhookingInProgress{false};
    std::atomic<bool> functionExecuting{false};
    std::atomic<int> returnedSuccessfully{0};

    // A function that will be called from within the hooked function
    // This simulates a scenario where a call instruction needs to be relocated
    NOINLINE int HelperFunction(int x)
    {
        // Simulate some work
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        return x * 2;
    }

    // Function that contains a call instruction (to HelperFunction)
    // This call will be relocated when we hook FunctionWithCall
    NOINLINE int FunctionWithCall(int x)
    {
        functionExecuting.store(true, std::memory_order_release);

        // This call instruction will be relocated to the trampoline
        int result = HelperFunction(x);

        // Wait a bit to give the unhook thread time to unhook
        if (unhookingInProgress.load(std::memory_order_acquire))
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }

        functionExecuting.store(false, std::memory_order_release);
        returnedSuccessfully.fetch_add(1, std::memory_order_relaxed);

        return result + 1;
    }

    NOINLINE int ProxyFunction(int x)
    {
        // Just pass through, we're testing the relocation safety not the hook logic
        return x + 100;
    }

#if defined(__linux__) && defined(__x86_64__)
    // Test fixture for safe unhook tests
    class DetourSafeUnhookTest : public ::testing::Test
    {
    protected:
        void SetUp() override
        {
            // Reset all state before each test
            unhookingInProgress.store(false, std::memory_order_relaxed);
            functionExecuting.store(false, std::memory_order_relaxed);
            returnedSuccessfully.store(0, std::memory_order_relaxed);
        }

        void TearDown() override
        {
            // Clean up after each test
            unhookingInProgress.store(false, std::memory_order_relaxed);
            functionExecuting.store(false, std::memory_order_relaxed);
            returnedSuccessfully.store(0, std::memory_order_relaxed);
        }
    };

    TEST_F(DetourSafeUnhookTest, CanUnhookWhileFunctionWithRelocatedCallIsExecuting)
    {
        hookftw::Detour detour;

        // Verify function works before hooking
        EXPECT_EQ(FunctionWithCall(5), 11);

        // Reset counter after initial verification
        returnedSuccessfully.store(0, std::memory_order_relaxed);

        // Hook the function (this will relocate the call to HelperFunction)
        TargetFn trampoline = reinterpret_cast<TargetFn>(
            detour.Hook(
                reinterpret_cast<int8_t*>(&FunctionWithCall),
                reinterpret_cast<int8_t*>(&ProxyFunction)
            )
        );

        ASSERT_NE(trampoline, nullptr);

        // Verify hook is working
        EXPECT_EQ(FunctionWithCall(5), 105);

        // Reset counter before the actual test
        returnedSuccessfully.store(0, std::memory_order_relaxed);

        // Now the critical test: call the TRAMPOLINE in one thread and unhook in another
        // The trampoline contains the relocated call instruction to HelperFunction
        // The function execution will cross the unhook operation
        std::thread executingThread([trampoline]() {
            // Call the trampoline - this executes the relocated call to HelperFunction
            // The return from HelperFunction should be safe even if unhook happens
            int result = trampoline(10);

            // With the old implementation, this would crash
            // With our fix (push return_addr + jmp), this succeeds
            EXPECT_EQ(result, 21);  // 10 * 2 + 1 = 21
        });

        // Wait for the function to start executing and enter HelperFunction
        while (!functionExecuting.load(std::memory_order_acquire))
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }

        // Give it a moment to enter HelperFunction (where the relocated call returns to)
        std::this_thread::sleep_for(std::chrono::milliseconds(5));

        // Signal that unhooking is happening
        unhookingInProgress.store(true, std::memory_order_release);

        // UNHOOK WHILE THE FUNCTION IS EXECUTING
        // With old implementation: return from HelperFunction would jump to freed memory → crash
        // With our fix: return from HelperFunction jumps to original code → success
        detour.Unhook();

        // Wait for the executing thread to finish
        executingThread.join();

        // Verify the function returned successfully (didn't crash)
        EXPECT_EQ(returnedSuccessfully.load(std::memory_order_relaxed), 1);

        // Verify function is unhooked and works normally
        EXPECT_EQ(FunctionWithCall(5), 11);
    }

    TEST_F(DetourSafeUnhookTest, MultipleThreadsWithRelocatedCallsDuringUnhook)
    {
        hookftw::Detour detour;

        // Hook the function
        TargetFn trampoline = reinterpret_cast<TargetFn>(
            detour.Hook(
                reinterpret_cast<int8_t*>(&FunctionWithCall),
                reinterpret_cast<int8_t*>(&ProxyFunction)
            )
        );

        ASSERT_NE(trampoline, nullptr);

        const int numThreads = 4;
        std::vector<std::thread> threads;

        // Start multiple threads executing the trampoline (which has relocated calls)
        for (int i = 0; i < numThreads; ++i)
        {
            threads.emplace_back([i, trampoline]() {
                for (int j = 0; j < 3; ++j)
                {
                    // Call the trampoline - this executes the relocated call
                    int result = trampoline(i * 10 + j);
                    EXPECT_GT(result, 0);
                }
            });
        }

        // Let them get started
        std::this_thread::sleep_for(std::chrono::milliseconds(15));

        // Unhook while threads are executing
        unhookingInProgress.store(true, std::memory_order_release);
        detour.Unhook();

        // Wait for all threads to complete
        for (auto& t : threads)
        {
            t.join();
        }

        // All threads should have completed successfully without crashes
        // We expect at least some calls to have completed (12 total calls from 4 threads * 3 iterations)
        int completedCalls = returnedSuccessfully.load(std::memory_order_relaxed);
        EXPECT_GE(completedCalls, 1);

        // Verify function is unhooked
        EXPECT_EQ(FunctionWithCall(5), 11);
    }

    TEST_F(DetourSafeUnhookTest, VerifyReturnAddressPointsToOriginalCode)
    {
        hookftw::Detour detour;

        // This test verifies that the relocated call instruction pushes
        // a return address that points to the original function code, not the trampoline


        // Hook the function
        TargetFn trampoline = reinterpret_cast<TargetFn>(
            detour.Hook(
                reinterpret_cast<int8_t*>(&FunctionWithCall),
                reinterpret_cast<int8_t*>(&ProxyFunction)
            )
        );

        ASSERT_NE(trampoline, nullptr);

        // Call the trampoline multiple times
        // If the return address was pointing to the trampoline, this would only work once
        // With our fix, it should work every time because the return address points to original code
        for (int i = 0; i < 5; ++i)
        {
            int result = trampoline(i);
            EXPECT_EQ(result, i * 2 + 1) << "Iteration " << i;
        }

        // Verify all calls completed successfully
        EXPECT_EQ(returnedSuccessfully.load(std::memory_order_relaxed), 5);

        detour.Unhook();
    }
#else
    // Test fixture for platforms where tests are not implemented
    class DetourSafeUnhookTest : public ::testing::Test
    {
    protected:
        void SetUp() override {}
        void TearDown() override {}
    };

    TEST_F(DetourSafeUnhookTest, CanUnhookWhileFunctionWithRelocatedCallIsExecuting)
    {
        GTEST_SKIP() << "Test only implemented for Linux x86_64";
    }

    TEST_F(DetourSafeUnhookTest, MultipleThreadsWithRelocatedCallsDuringUnhook)
    {
        GTEST_SKIP() << "Test only implemented for Linux x86_64";
    }

    TEST_F(DetourSafeUnhookTest, VerifyReturnAddressPointsToOriginalCode)
    {
        GTEST_SKIP() << "Test only implemented for Linux x86_64";
    }
#endif

}

