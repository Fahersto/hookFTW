#include <gtest/gtest.h>

#include <cstdint>
#include <cstdlib>

#include <Trampoline.h>
#include <Memory.h>

namespace
{

    int Target(int x)
    {
        return x + 7;
    }

    TEST(Trampoline, AllocatesTrampolineForSourceAddress)
    {
        hookftw::Trampoline tramp;
        bool restricted = false;

        int8_t* mem = tramp.HandleTrampolineAllocation(reinterpret_cast<int8_t*>(&Target), &restricted);
        ASSERT_NE(mem, nullptr);

        EXPECT_TRUE(hookftw::Memory::FreePage(mem, hookftw::Memory::GetPageSize()));
    }
}
