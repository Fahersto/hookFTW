#pragma once

#include <cstdint>

namespace hookftw
{
	/**
	 * \brief Allocates trampolines and provides information about it.
	 */
	class Trampoline
	{
	public:
		Trampoline();
		int8_t* HandleTrampolineAllocation(int8_t* sourceAddress, bool* restrictedRelocation);
		int8_t* AllocateTrampoline(int8_t* sourceAddress, bool* restrictedRelocation);
		int8_t* AllocateTrampolineWithinBounds(int8_t* sourceAddress, int64_t lowestRipRelativeMemoryAccess, int64_t highestRipRelativeMemoryAddress, bool* restrictedRelocation);
	};
}