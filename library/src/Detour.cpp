#include "Detour.h"

#include "Decoder.h"

#include <cstdint>
#include <cassert>

namespace hookftw
{
#ifdef _WIN64
	//
	//Hooks a function by placing jumping to a proxy function using 14 bytes:
	//0xff, 0x25, 0x0, 0x0, 0x0, 0x0					JMP[rip + 0]
	//0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88	absolute address of jump
	//The proxy function is expected to return to the trampoline (return value of DetourHook::Hook()) which runs the overwritten instructions and returns back to the original code
	//Important: the overwritten bytes are NOT relocated meaning only position independet instructions can be overwritten
	int8_t* Detour::Hook(int8_t* sourceAddress, int8_t* targetAddress)
	{
		//length of detour
		const int stubJumpBackLength = 14;

		Decoder decoder;
		//TODO we currently assume that we can reach the trampole with rel32.
		int lengthWithoutCuttingInstructionsInHalf = decoder.GetLengthOfInstructions(sourceAddress, stubJumpBackLength);

		//5 bytes are required to place detour
		assert(lengthWithoutCuttingInstructionsInHalf >= stubJumpBackLength);

		//remember for unhooking
		this->hookLength_ = lengthWithoutCuttingInstructionsInHalf;
		this->sourceAddress_ = sourceAddress;

		//save original bytes
		originalBytes_ = new int8_t[hookLength_];
		memcpy(originalBytes_, sourceAddress, hookLength_);


		//make page of detour address writeable
		DWORD pageProtection;
		VirtualProtect(sourceAddress, hookLength_, PAGE_READWRITE, &pageProtection);

		//allocate space for stub + space for overwritten bytes + jumpback
		//TODO the calculation is technically not correct. But since we get a page worth of memory anyway it doesn't matter
		trampoline_ = (int8_t*)VirtualAlloc(NULL, hookLength_ + stubJumpBackLength, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!trampoline_)
		{
			printf("[Error] - Detour - Failed to allocate trampoline\n");
		}
	
		std::vector<int8_t> relocatedBytes = decoder.Relocate(sourceAddress, lengthWithoutCuttingInstructionsInHalf, trampoline_);
		if (relocatedBytes.empty())
		{
			printf("[Error] - Detour - Relocation of bytes replaced by hook failed\n");
		}

		//copy overwritten bytes to trampoline
		memcpy(trampoline_, relocatedBytes.data(), relocatedBytes.size());

		int8_t* addressAfterRelocatedBytes = trampoline_ + relocatedBytes.size();


		//write JMP back from trampoline to original code
		addressAfterRelocatedBytes[0] = 0xFF;														//opcodes = JMP [rip+0]
		addressAfterRelocatedBytes[1] = 0x25;														//opcodes = JMP [rip+0]
		*(uint32_t*)(&addressAfterRelocatedBytes[2]) = 0;											//relative distance from RIP (+0) 
		*(uint64_t*)(&addressAfterRelocatedBytes[2 + 4]) = (uint64_t)(sourceAddress + hookLength_);	//destination to jump to

		//write JMP from original code to hook function
		sourceAddress[0] = 0xFF;																	//opcodes = JMP [rip+0]
		sourceAddress[1] = 0x25;																	//opcodes = JMP [rip+0]
		*(uint32_t*)(&sourceAddress[2]) = 0;														//relative distance from RIP (+0) 
		*(uint64_t*)(&sourceAddress[2 + 4]) = (uint64_t)(targetAddress);							//destination to jump to

		//NOP left over bytes
		for (int i = stubJumpBackLength; i < hookLength_; i++)
		{
			sourceAddress[i] = 0x90;
		}

		//restore page protection
		VirtualProtect(sourceAddress, hookLength_, pageProtection, &pageProtection);
		VirtualProtect(trampoline_, relocatedBytes.size() + 14, PAGE_EXECUTE_READWRITE, &pageProtection);
	
		//return the address of the trampoline so we can call it to invoke the original function
		return trampoline_;
	}



	void Detour::Unhook()
	{
		//make page writeable
		DWORD oldProtection;
		VirtualProtect(sourceAddress_, hookLength_, PAGE_EXECUTE_READWRITE, &oldProtection);

		//copy back original bytes
		memcpy(sourceAddress_, originalBytes_, hookLength_);

		//restore page protection
		VirtualProtect(sourceAddress_, hookLength_, oldProtection, &oldProtection);

		//clean up allocated memory
		delete[] originalBytes_;

		//memory leak but enables unhooking inside hooked function and makes it threadsafe?
		//delete[] trampoline;
	}

#else
	//
	//Hooks a function by placing a jump (JMP 0xE9) from the original function to the proxy function
	//The proxy function is expected to return to the trampoline (return value of DetourHook::Hook()) which runs the overwritten instructions and returns back to the original code
	//Only for x86 since JMP (0xE9) hast 32bit target address
	//Important: the overwritten bytes are NOT relocated meaning only position independet instructions can be overwritten
	int8_t* Detour::Hook(int8_t* sourceAddress, int8_t* targetAddress)
	{
		//length of detour
		const int stubJumpBackLength = 5;

		Decoder decoder;

		//TODO we currently assume that we can reach the trampole with rel32.
		int lengthWithoutCuttingInstructionsInHalf = decoder.GetLengthOfInstructions(sourceAddress, stubJumpBackLength);

		//5 bytes are required to place detour
		assert(lengthWithoutCuttingInstructionsInHalf >= stubJumpBackLength);

		//remember for unhooking
		this->hookLength_ = lengthWithoutCuttingInstructionsInHalf;
		this->sourceAddress_ = sourceAddress;

		//save original bytes
		originalBytes_ = new int8_t[hookLength_];
		memcpy(originalBytes_, sourceAddress, hookLength_);


		//make page of detour address writeable
		DWORD pageProtection;
		VirtualProtect(sourceAddress, hookLength_, PAGE_READWRITE, &pageProtection);

		//allocate trampoline
		//TODO check fir rip relative instructions if we can reach original targets with rel32
		trampoline_ = (int8_t*)VirtualAlloc(NULL, hookLength_ + stubJumpBackLength, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!trampoline_)
		{
			printf("[Error] - Detour - Failed to allocate trampoline\n");
		}

		std::vector<int8_t> relocatedBytes = decoder.Relocate(sourceAddress, lengthWithoutCuttingInstructionsInHalf, trampoline_);
		if (relocatedBytes.empty())
		{
			printf("[Error] - Detour - Relocation of bytes replaced by hook failed\n");
		}

		//copy overwritten bytes to trampoline
		memcpy(trampoline_, relocatedBytes.data(), relocatedBytes.size());

		int8_t* addressAfterRelocatedBytes = trampoline_ + relocatedBytes.size();

		//write JMP back from trampoline to original code
		addressAfterRelocatedBytes[0] = 0xE9;
		*(uint32_t*)(addressAfterRelocatedBytes + 1) = (uint32_t)(sourceAddress + hookLength_ - addressAfterRelocatedBytes) - 5;

		//write JMP from original code to hook function
		sourceAddress[0] = 0xE9;
		*(uint32_t*)(sourceAddress + 1) = (uint32_t)(targetAddress - sourceAddress) - 5;

		//NOP left over bytes
		for (int i = stubJumpBackLength; i < hookLength_; i++)
		{
			sourceAddress[i] = 0x90;
		}

		//restore page protection
		VirtualProtect(sourceAddress, hookLength_, pageProtection, &pageProtection);

		//make trampoline executable
		VirtualProtect(trampoline_, relocatedBytes.size() + 5, PAGE_EXECUTE_READWRITE, &pageProtection);
	
		//return the address of the trampoline so we can call it to invoke the original function
		return trampoline_;
	}

	//
	//Unhooks a previously hooked function by copying back the original bytes
	void Detour::Unhook()
	{
		//make page writeable
		DWORD dwback;
		VirtualProtect(sourceAddress_, hookLength_, PAGE_READWRITE, &dwback);

		//copy back original bytes
		memcpy(sourceAddress_, originalBytes_, hookLength_);

		//restore page protection
		VirtualProtect(sourceAddress_, hookLength_, dwback, &dwback);

		//clean up allocated memory
		delete[] originalBytes_;

		//memory leak but enables unhooking inside hooked function and makes it threadsafe?
		//delete[] trampoline;
	}
#endif

}