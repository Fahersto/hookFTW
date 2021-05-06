#pragma once

#include <vector>
#include <Windows.h>

#include "Registers.h"



namespace hookftw
{
	/**
	 * \brief Allows to hook anywhere in a function.
	 * 
	 * Place a hook anywhere within a function
	 */
	class Hook
	{
		//bytes overwritten by placing the detour
		int8_t* originalBytes{};

		//location where hook is placed
		int8_t* sourceAddress{};

		//contrains overwritten instructions
		int8_t* trampoline{};

		//number of bytes to overwrite (don't cut instructions in half)
		int hookLength{};

		void GenerateTrampolineAndApplyHook(int8_t* sourceAddress, int hookLength, std::vector<int8_t> rellocatedBytes, void proxy(registers* registers));

	public:
		
		Hook(int8_t* sourceAddress, void proxy(registers* regs));
		void Unhook();
	};
}
