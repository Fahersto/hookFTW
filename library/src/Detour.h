#pragma once

#include <cstdint>

namespace hookftw
{
	/**
	 * \brief Creates and manages hooks at the beginning of a function
	 *
	 * This hooking method requires knowledge of parameters and calling convention of the target function.
	 */
	class Detour
	{
		// bytes overwritten by placing the detour
		int8_t* originalBytes_;

		// location where hook is placed
		int8_t* sourceAddress_;

		// runs overwritten instructions
		int8_t* trampoline_;

		// number of bytes to overwrite (don't cut instructions in half)
		int hookLength_;

	public:
		Detour();
		int8_t* Hook(int8_t* sourceAddress, int8_t* targetAddress);
		void Unhook();
	};
}