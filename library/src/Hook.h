#pragma once
#include <cstdint>
#include <vector>
#include <Windows.h>
#include <xmmintrin.h>
#include <functional>

#include "Registers.h"

namespace hookftw
{
	struct context;
	/**
	 * \brief Creates and manages hooks.
	 * 
	 * Hooking at the start of a function enables additional functionality such as
	 * calling the original function or skipping the call of the original function that invoked the hook.
	 * 
	 * \warning The caller is responsible to ensure that the start of a function is hooked. Otherwhise context::CallOriginal() and context::SkipCall() behavior is undefined.
	 */
	class Hook
	{
		//bytes overwritten by placing the detour
		int8_t* originalBytes_ = nullptr;

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

		int8_t* addressOfRET = nullptr;

		void AllocateTrampoline(int8_t* hookAddress);
		void GenerateTrampolineAndApplyHook(int8_t* sourceAddress, int hookLength, std::vector<int8_t> relocatedBytes, void __fastcall proxy(context* ctx));

		
	public:
		int8_t* GetCallableVersionOfOriginal();
		Hook(int8_t* sourceAddress, void __fastcall proxy(context* ctx));
		
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
	#if _WIN64
	 /**
	  * \brief context for 64bit to be used in the hook callback
	  *
	  * \note Inside the hook any register can be read/written by using this context.
	  * \warning Values of registers are at the time of hooking. The only expection to this is RSP which can be calculated by \GetRspAtHookAddress.
	  */
	struct context
	{
		Hook* hook;
		//registers registers; we do not use the struct here because it is aligned at the start
		int64_t rsp;
		int64_t rax;
		int64_t rcx;
		int64_t rdx;
		int64_t rbx;
		int64_t rbp;
		int64_t rsi;
		int64_t rdi;
		int64_t r8;
		int64_t r9;
		int64_t r10;
		int64_t r11;
		int64_t r12;
		int64_t r13;
		int64_t r14;
		int64_t r15;

		__m128 xmm0;
		__m128 xmm1;
		__m128 xmm2;
		__m128 xmm3;
		__m128 xmm4;
		__m128 xmm5;
		__m128 xmm6;
		__m128 xmm7;
		__m128 xmm8;
		__m128 xmm9;
		__m128 xmm10;
		__m128 xmm11;
		__m128 xmm12;
		__m128 xmm13;
		__m128 xmm14;
		__m128 xmm15;

		/**
		 * Prints the values of all registers
		 */
		void PrintRegister()
		{
			printf("register:\n\trsp %llx\n\trax %llx\n\trcx %llx\n\trdx %llx\n\trbx %llx\n\trbp %llx\n\trsi %llx\n\trdi %llx\n\tr8 %llx\n\tr9 %llx\n\tr10 %llx\n\tr11 %llx\n\tr12 %llx\n\tr13 %llx\n\tr14 %llx\n\tr15 %llx\n",
				rsp, rax, rcx, rdx, rbx, rbp, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15);
		}
		

		/**
		 * Changes the address to which is returned to after the hook (usually the hooked function).
		 * \warning Changing the control flow of a function is very likely to produce crashes if not done with caution.
		 */
		void ChangeControllFlow(int64_t addressToReturnToAfterHook)
		{
			hook->ChangeReturn(addressToReturnToAfterHook);
		}

		/**
		 * Skips the call of the hooked function but executing a RET.
		 * \warning This usually only makes sense if the function is hooked directly at its beginning. Otherwhise behavior is undefined.
		 */
		void SkipOriginalFunction()
		{
			hook->SkipOriginalFunction();
		}

		/**
		 * Calls the original (unhooked) version of the function. Allows to call the hooked function without recursivly calling the hook again.
		 *
		 * @return result of the hooked function when invoked with the specified parameters.
		 */
		template<class RET, class...PARAMS>
		RET CallOriginal(PARAMS... parameters)
		{
			typedef RET(*fnSignature)(PARAMS...);
			fnSignature fn = (fnSignature)hook->GetCallableVersionOfOriginal();
			return fn(parameters...);
		}

	};
	#elif _WIN32
	 /**
	  * \brief context for 32bit to be used in the hook callback
	  *
	  * \note Inside the hook any register can be read/written by using this context.
	  * \warning Values of registers are at the time of hooking. The only expection to this is ESP which can be calculated by \GetEspAtHookAddress.
	  */
	struct context
	{
		Hook* hook;
		//registers registers; we do not use the struct here because it is aligned at the start
		int32_t esp;
		int32_t eax;
		int32_t ecx;
		int32_t edx;
		int32_t ebx;
		int32_t ebp;
		int32_t esi;
		int32_t edi;

		__m128 xmm0;
		__m128 xmm1;
		__m128 xmm2;
		__m128 xmm3;
		__m128 xmm4;
		__m128 xmm5;
		__m128 xmm6;
		__m128 xmm7;

		int32_t eflags;

		/**
		 * Prints the values of all registers
		 */
		void PrintRegister()
		{
			printf("register:\n\tesp %x\n\teax %x\n\tecx %x\n\tedx %x\n\tebx %x\n\tebp %x\n\tesi %x\n\tedi %x\n\teflags %x\n",
				esp, eax, ecx, edx, ebx, ebp, esi, edi, eflags);
		}

		/**
		* Changes the address to which is returned to after the hook (usually the hooked function).
		* \warning Changing the control flow of a function is very likely to produce crashes if not done with caution.
		*/
		void ChangeControllFlow(int64_t addressToReturnToAfterHook)
		{
			hook->ChangeReturn(addressToReturnToAfterHook);
		}

		/**
		* Skips the call of the hooked function but executing a RET.
		* \warning This usually only makes sense if the function is hooked directly at its beginning. Otherwhise behavior is undefined.
		*/
		void SkipOriginalFunction()
		{
			hook->SkipOriginalFunction();
		}

		/**
		 * Calls the original (unhooked) version of the function. Allows to call the hooked function without recursivly calling the hook again.
		 *
		 * @return result of the hooked function when invoked with the specified parameters.
		*/
		template<class RET, class...PARAMS>
		RET CallOriginal(PARAMS... parameters)
		{
			typedef RET(*fnSignature)(PARAMS...);
			fnSignature fn = (fnSignature)hook->GetCallableVersionOfOriginal();
			return fn(parameters...);
		}

	};
	#endif
}
