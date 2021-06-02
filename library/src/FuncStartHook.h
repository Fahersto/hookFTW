#pragma once
#include <cstdint>
#include <vector>
#include <Windows.h>
#include <xmmintrin.h>

#include "Registers.h"

namespace hookftw
{
	struct context;
	/**
	 * \brief Supports hooking at the start of a target function
	 * 
	 * Hooking at the start of a function enables additional functionality such as
	 * calling the original function or skipping the call of the original function that invoked the hook.
	 * 
	 * \warning The caller is responsible to ensure that the start of a function is hooked. Otherwhise context::CallOriginal() and context::SkipCall() behavior is undefined.
	 */
	class FuncStartHook
	{
		//bytes overwritten by placing the detour
		int8_t* original_bytes_ = nullptr;

		//location where hook is placed
		int8_t* sourceAddress_ = nullptr;

		//contrains overwritten instructions
		int8_t* trampoline_ = nullptr;

		//contains the address after the trampoline_ stub. starts with the rellocated origin instruction.
		int8_t* addressToCallFunctionWithoutHook_= nullptr;

		//contains the address to which the trampoline_ returns. This can be used to skip the original call for example.
		int64_t returnAddressFromTrampoline_ = NULL;

		//number of bytes to overwrite (don't cut instructions in half)
		int hookLength_ = NULL;

		//rax is used to change the location to jump back
		int64_t savedRax_ = NULL;
		int64_t originalRsp_ = NULL;

		void AllocateTrampoline(int8_t* hookAddress);
		void GenerateTrampolineAndApplyHook(int8_t* sourceAddress, int hookLength, std::vector<int8_t> relocatedBytes, void proxy(context* ctx));

		
	public:
		int8_t* GetCallableVersionOfOriginal();
		FuncStartHook(int8_t* sourceAddress, void proxy(context* ctx));
		
		void Unhook();


		//TODO this should not be accessible here. But we need to get here from context
		void ChangeReturn(int64_t returnValue);
		void SkipOriginalFunction();
	};

	/**
	 * \brief Holds the state of the registers at the time of call to the original function and a pointer to the FuncStartHook
	 * 
	 * Context of the hooked function.
	 */
	struct context
	{
		FuncStartHook* hook;
		registers registers;	

		/**
		 * Skips the call of the hooked function.
		 */
		void ChangeControllFlow(int64_t addressToReturnToAfterHook)
		{
			hook->ChangeReturn(addressToReturnToAfterHook);
		}

		void SkipOriginalFunction()
		{
			hook->SkipOriginalFunction();
		}

		/**
		 * Calls the original (unhooked) version of the function. Allows to call the hooked function without recursivly calling the hook again.
		 */
		template<class RET, class...PARAMS>
		RET CallOriginal(PARAMS... parameters)
		{
			typedef RET(*fnSignature)(PARAMS...);
			fnSignature fn = (fnSignature)hook->GetCallableVersionOfOriginal();
			return fn(parameters...);
		}

	};
}
