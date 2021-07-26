#include "Detour.h"

#include "Decoder.h"

#include <cstdint>
#include <cassert>

namespace hookftw
{
#ifdef _WIN64
	//
	// Hooks a function by placing jumping to a proxy function using 14 bytes:
	// 0xff, 0x25, 0x0, 0x0, 0x0, 0x0					JMP[rip + 0]
	// 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88	absolute address of jump
	// the trampoline (return value of DetourHook::Hook()) runs the overwritten instructions and returns back to the original code
	int8_t* Detour::Hook(int8_t* sourceAddress, int8_t* targetAddress)
	{
		// remember for unhooking
		this->sourceAddress_ = sourceAddress;

		Decoder decoder;
		// allocate space for stub + space for overwritten bytes + jumpback
		bool restrictedRelocation;
		trampoline_ = decoder.HandleTrampolineAllocation(sourceAddress, &restrictedRelocation);
		if (!trampoline_)
		{
			printf("[Error] - Detour - Failed to allocate trampoline\n");
			return nullptr;
		}

		if (restrictedRelocation)
		{
			this->hookLength_ = decoder.GetLengthOfInstructions(sourceAddress, 5);;
		}
		else
		{
			this->hookLength_ =  decoder.GetLengthOfInstructions(sourceAddress, 14);
		}

		// 5 bytes are required to place detour
		assert(this->hookLength_ >= 5);

		// save original bytes
		originalBytes_ = new int8_t[hookLength_];
		memcpy(originalBytes_, sourceAddress, hookLength_);

		// make page of detour address writeable
		DWORD pageProtection;
		VirtualProtect(sourceAddress, hookLength_, PAGE_READWRITE, &pageProtection);

		// relocate to be overwritten instructions to trampoline
		std::vector<int8_t> relocatedBytes = decoder.Relocate(sourceAddress, this->hookLength_, trampoline_, restrictedRelocation);
		if (relocatedBytes.empty())
		{
			printf("[Error] - Detour - Relocation of bytes replaced by hook failed\n");
			return nullptr;
		}

		// copy overwritten bytes to trampoline
		memcpy(trampoline_, relocatedBytes.data(), relocatedBytes.size());

		int8_t* addressAfterRelocatedBytes = trampoline_ + relocatedBytes.size();

		// write JMP back from trampoline to original code
		const int stubJumpBackLength = 14;
		addressAfterRelocatedBytes[0] = 0xFF;														//opcodes = JMP [rip+0]
		addressAfterRelocatedBytes[1] = 0x25;														//opcodes = JMP [rip+0]
		*(uint32_t*)(&addressAfterRelocatedBytes[2]) = 0;											//relative distance from RIP (+0) 
		*(uint64_t*)(&addressAfterRelocatedBytes[2 + 4]) = (uint64_t)(sourceAddress + hookLength_);	//destination to jump to

		int jmpToTrampolineLength = 5;
		if (restrictedRelocation)
		{
			jmpToTrampolineLength = 14;
			// write JMP from original code to hook function
			sourceAddress[0] = 0xFF;																//opcodes = JMP [rip+0]
			sourceAddress[1] = 0x25;																//opcodes = JMP [rip+0]
			*(uint32_t*)(&sourceAddress[2]) = 0;													//relative distance from RIP (+0) 
			*(uint64_t*)(&sourceAddress[2 + 4]) = (uint64_t)(targetAddress);						//destination to jump to
		}
		else
		{
			sourceAddress[0] = 0xE9;																//JMP rel32
			*(uint32_t*)(sourceAddress + 1) = (uint32_t)(targetAddress - sourceAddress) - 5;
		}

		// NOP left over bytes
		for (int i = jmpToTrampolineLength; i < hookLength_; i++)
		{
			sourceAddress[i] = 0x90;
		}

		// restore page protection
		VirtualProtect(sourceAddress, hookLength_, pageProtection, &pageProtection);

		// make trampoline executable
		VirtualProtect(trampoline_, relocatedBytes.size() + stubJumpBackLength, PAGE_EXECUTE_READWRITE, &pageProtection);

		// flush instruction cache for new executable region to ensure cache coherency
		FlushInstructionCache(GetModuleHandle(NULL), trampoline_, relocatedBytes.size() + stubJumpBackLength);
	
		// return the address of the trampoline so we can call it to invoke the original function
		return trampoline_;
	}

	void Detour::Unhook()
	{
		// make page writeable
		DWORD oldProtection;
		VirtualProtect(sourceAddress_, hookLength_, PAGE_EXECUTE_READWRITE, &oldProtection);

		// copy back original bytes
		memcpy(sourceAddress_, originalBytes_, hookLength_);

		// restore page protection
		VirtualProtect(sourceAddress_, hookLength_, oldProtection, &oldProtection);

		//clean up allocated memory
		//delete[] originalBytes_;
		//delete[] trampoline_;
	}

#else
	//
	// Hooks a function by placing a jump (JMP 0xE9) from the original function to the proxy function
	// The proxy function is expected to return to the trampoline (return value of DetourHook::Hook()) which runs the overwritten instructions and returns back to the original code
	// Only for x86 since JMP (0xE9) hast 32bit target address
	// Important: the overwritten bytes are NOT relocated meaning only position independet instructions can be overwritten
	int8_t* Detour::Hook(int8_t* sourceAddress, int8_t* targetAddress)
	{
		// length of jmp rel32
		const int stubJumpBackLength = 5;

		Decoder decoder;
		int lengthWithoutCuttingInstructionsInHalf = decoder.GetLengthOfInstructions(sourceAddress, stubJumpBackLength);

		// 5 bytes are required for jmp rel32
		assert(lengthWithoutCuttingInstructionsInHalf >= stubJumpBackLength);

		// remember for unhooking
		this->hookLength_ = lengthWithoutCuttingInstructionsInHalf;
		this->sourceAddress_ = sourceAddress;

		// save original bytes
		originalBytes_ = new int8_t[hookLength_];
		memcpy(originalBytes_, sourceAddress, hookLength_);

		// make page of detour address writeable
		DWORD pageProtection;
		VirtualProtect(sourceAddress, hookLength_, PAGE_READWRITE, &pageProtection);

		// allocate trampoline
		bool restrictedRelocation;
		trampoline_ = decoder.AllocateTrampoline(sourceAddress, &restrictedRelocation);
		if (!trampoline_)
		{
			printf("[Error] - Detour - Failed to allocate trampoline\n");
			return nullptr;
		}

		// relocate to be overwritten instructions to trampoline
		std::vector<int8_t> relocatedBytes = decoder.Relocate(sourceAddress, lengthWithoutCuttingInstructionsInHalf, trampoline_);
		if (relocatedBytes.empty())
		{
			printf("[Error] - Detour - Relocation of bytes replaced by hook failed\n");
			return nullptr;
		}

		// copy relocated instructions to trampoline
		memcpy(trampoline_, relocatedBytes.data(), relocatedBytes.size());

		int8_t* addressAfterRelocatedBytes = trampoline_ + relocatedBytes.size();

		// write JMP back from trampoline to original code
		addressAfterRelocatedBytes[0] = 0xE9;
		*(uint32_t*)(addressAfterRelocatedBytes + 1) = (uint32_t)(sourceAddress + hookLength_ - addressAfterRelocatedBytes) - 5;

		// write JMP from original code to hook function
		sourceAddress[0] = 0xE9;
		*(uint32_t*)(sourceAddress + 1) = (uint32_t)(targetAddress - sourceAddress) - 5;

		// NOP left over bytes
		for (int i = stubJumpBackLength; i < hookLength_; i++)
		{
			sourceAddress[i] = 0x90;
		}

		// restore page protection
		VirtualProtect(sourceAddress, hookLength_, pageProtection, &pageProtection);

		// make trampoline executable
		VirtualProtect(trampoline_, relocatedBytes.size() + stubJumpBackLength, PAGE_EXECUTE_READWRITE, &pageProtection);

		// flush instruction cache for new executable region to ensure cache coherency
		FlushInstructionCache(GetModuleHandle(NULL), trampoline_, relocatedBytes.size() + stubJumpBackLength);
	
		// return the address of the trampoline so we can call it to invoke the original function
		return trampoline_;
	}

	//
	// Unhooks a previously hooked function by copying back the original bytes
	void Detour::Unhook()
	{
		// make page writeable
		DWORD dwback;
		VirtualProtect(sourceAddress_, hookLength_, PAGE_READWRITE, &dwback);

		// copy back original bytes
		memcpy(sourceAddress_, originalBytes_, hookLength_);

		// restore page protection
		VirtualProtect(sourceAddress_, hookLength_, dwback, &dwback);

		// clean up allocated memory
		//delete[] originalBytes_;
		//delete[] trampoline_;
	}
#endif

}