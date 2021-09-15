#include "Detour.h"

#include "Decoder.h"
#include "Trampoline.h"

#include <cstdint>
#include <cassert>
#include <climits>

namespace hookftw
{
	/**
	 * \brief Default constructor.
	 */
	Detour::Detour()
		: originalBytes_(nullptr), sourceAddress_(nullptr), trampoline_(nullptr), hookLength_(0)
	{

	}

#ifdef _WIN64
	/**
	 * \brief Creates a detour hook.
	 *
	 * @param sourceAddress Address to apply the hook to
	 * @param targetAddress Function to be executed when hook is called
	 * @return returns the address of the trampoline which can be used to call the original function
	 */
	int8_t* Detour::Hook(int8_t* sourceAddress, int8_t* targetAddress)
	{
		// remember for unhooking
		this->sourceAddress_ = sourceAddress;

		// allocate space for stub + space for overwritten bytes + jumpback
		Trampoline trampoline;
		bool restrictedRelocation;
		trampoline_ = trampoline.HandleTrampolineAllocation(sourceAddress, &restrictedRelocation);
		if (!trampoline_)
		{
			printf("[Error] - Detour - Failed to allocate trampoline\n");
			return nullptr;
		}

		Decoder decoder;
		int64_t addressDelta = (int64_t)targetAddress - (int64_t)sourceAddress;

		if (addressDelta > INT32_MAX || addressDelta < INT32_MIN)
		{
			this->hookLength_ = decoder.GetLengthOfInstructions(sourceAddress, 14);
		}
		else
		{
			this->hookLength_ = decoder.GetLengthOfInstructions(sourceAddress, 5);
		}

		// 5 bytes are required to place detour
		assert(this->hookLength_ >= 5);

		// save original bytes
		originalBytes_ = new int8_t[hookLength_];
		memcpy(originalBytes_, sourceAddress, hookLength_);

		// make page of detour address writeable
		DWORD pageProtection;
		VirtualProtect(sourceAddress, hookLength_, PAGE_EXECUTE_READWRITE, &pageProtection);

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
		*(int32_t*)(&addressAfterRelocatedBytes[2]) = 0;											//relative distance from RIP (+0) 
		*(int64_t*)(&addressAfterRelocatedBytes[2 + 4]) = (int64_t)(sourceAddress + hookLength_);	//destination to jump to

		int jmpToHookedFunctionLength = 5;

		// check if a jmp rel32 can reach
		if (addressDelta > INT32_MAX || addressDelta < INT32_MIN)
		{
			// need absolute 14 byte jmp
			jmpToHookedFunctionLength = 14;
			// write JMP from original code to hook function
			sourceAddress[0] = 0xFF;																//opcodes = JMP [rip+0]
			sourceAddress[1] = 0x25;																//opcodes = JMP [rip+0]
			*(int32_t*)(&sourceAddress[2]) = 0;														//relative distance from RIP (+0) 
			*(int64_t*)(&sourceAddress[2 + 4]) = (int64_t)(targetAddress);							//destination to jump to
		}
		else
		{
			// jmp rel32 is enough
			int64_t target1 = (int64_t)targetAddress - (int64_t)sourceAddress;
			int32_t target2 = (int32_t)((int64_t)targetAddress - (int64_t)sourceAddress);
			sourceAddress[0] = 0xE9;																//JMP rel32
			*(int32_t*)(&sourceAddress[1]) = (int32_t)((int64_t)targetAddress - (int64_t)sourceAddress - 5);
		}

		// NOP left over bytes
		for (int i = jmpToHookedFunctionLength; i < hookLength_; i++)
		{
			sourceAddress[i] = 0x90;
		}

		// restore page protection
		VirtualProtect(sourceAddress, hookLength_, pageProtection, &pageProtection);

		// make trampoline executable
		VirtualProtect(trampoline_, relocatedBytes.size() + stubJumpBackLength, PAGE_EXECUTE_READWRITE, &pageProtection);

		// flush instruction cache for new executable region to ensure cache coherency
		//FlushInstructionCache(GetModuleHandle(NULL), trampoline_, relocatedBytes.size() + stubJumpBackLength);

		// return the address of the trampoline so we can call it to invoke the original function
		return trampoline_;
	}

#else
	/**
	 * \brief Creates a detour hook.
	 *
	 * @param sourceAddress Address to apply the hook to
	 * @param targetAddress Function to be executed when hook is called
	 * @return returns the address of the trampoline which can be used to call the original function
	 */
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
		VirtualProtect(sourceAddress, hookLength_, PAGE_EXECUTE_READWRITE, &pageProtection);

		// allocate trampoline
		Trampoline trampoline;
		bool restrictedRelocation;
		trampoline_ = trampoline.AllocateTrampoline(sourceAddress, &restrictedRelocation);
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

#endif

	/**
	 * \brief Unhooks a detour hook.
	 *
	 *  \warning It is the users responsiblity to ensure that code within the trampoline is not going to be executed after unhooking.
	 */
	void Detour::Unhook()
	{
		// make page writeable
		DWORD oldProtection;
		VirtualProtect(sourceAddress_, hookLength_, PAGE_EXECUTE_READWRITE, &oldProtection);

		// copy back original bytes
		memcpy(sourceAddress_, originalBytes_, hookLength_);

		// restore page protection
		VirtualProtect(sourceAddress_, hookLength_, oldProtection, &oldProtection);

		// clean up allocated memory
		delete[] originalBytes_;

		// free trampolin memory page
		VirtualFree(trampoline_, 0, MEM_RELEASE);
	}

}