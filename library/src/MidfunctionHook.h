#pragma once
#include <cstdint>
#include <vector>
#include <Windows.h>
#include <xmmintrin.h>
#include <functional>

#include "Registers.h"

namespace hookftw
{
	enum class CallingConvention
	{
		default_call,
		cdecl_call,
		stdcall_call,
		fastcall_call,
		thiscall_call
	};

	struct context;
	/**
	 * \brief Creates and manages hooks. Supports hooking within a function.
	 *
	 * Hooking at the start of a function enables additional functionality such as
	 * calling the original function or skipping the call of the original function that invoked the hook.
	 */
	class MidfunctionHook
	{
		// bytes overwritten by placing the detour
		int8_t* originalBytes_ = nullptr;

		// location where hook is placed
		int8_t* sourceAddress_ = nullptr;

		// contrains overwritten instructions
		int8_t* trampoline_ = nullptr;

		// contains the address after the trampoline_ stub. starts with the rellocated origin instruction.
		int8_t* addressToCallFunctionWithoutHook_ = nullptr;

		// contains the address to which the trampoline_ returns. This can be used to skip the original call for example.
		int64_t returnAddressFromTrampoline_ = NULL;

		// number of bytes to overwrite (don't cut instructions in half)
		int hookLength_ = NULL;

		// rax is used to change the location to jump back
		int64_t savedRax_ = NULL;
		int64_t originalRsp_ = NULL;

		int8_t* addressOfRET = nullptr;

		// relocation can be caused by inability to allocate the trampoline within +-2GB range of the hook address
		// in x64 this can be solved using an absolute JMP, but we then can no longer relocate rip-relative memory accesses
		bool restrictedRelocation_ = false;

		// length of the static part of the trampoline. This is required to know where relocation starts when relocating rip-relative memoy accesses
		int32_t staticTrampolineLength_ = 0;

		void ApplyHook(int8_t* sourceAddress, int hookLength, std::vector<int8_t> relocatedBytes, void __fastcall proxy(context* ctx));

	public:
		int8_t* GetCallableVersionOfOriginal();
		MidfunctionHook();
		void Hook(int8_t* sourceAddress, void __fastcall proxy(context* ctx));

		void Unhook();


		// TODO this should not be accessible here. But we need to get here from context
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
	  * 
	  * \warning Values of registers are at the time of hooking. The only expection to this is RSP which can be calculated by \GetRspAtHookAddress.
	  */
	struct context
	{
		MidfunctionHook* hook;
		// registers registers; we do not use the struct here because it is aligned at the start
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

		// why not use __m128? because it uses 16 byte alignment
		int8_t xmm0[16];
		int8_t xmm1[16];
		int8_t xmm2[16];
		int8_t xmm3[16];
		int8_t xmm4[16];
		int8_t xmm5[16];
		int8_t xmm6[16];
		int8_t xmm7[16];
		int8_t xmm8[16];
		int8_t xmm9[16];
		int8_t xmm10[16];
		int8_t xmm11[16];
		int8_t xmm12[16];
		int8_t xmm13[16];
		int8_t xmm14[16];
		int8_t xmm15[16];

		int64_t rflags;

		/**
		 * \brief Prints the values of all registers
		 */
		void PrintRegister()
		{
			printf("register:\n\trsp %llx\n\trax %llx\n\trcx %llx\n\trdx %llx\n\trbx %llx\n\trbp %llx\n\trsi %llx\n\trdi %llx\n\tr8 %llx\n\tr9 %llx\n\tr10 %llx\n\tr11 %llx\n\tr12 %llx\n\tr13 %llx\n\tr14 %llx\n\tr15 %llx\n\trflags %llx\n",
				rsp, rax, rcx, rdx, rbx, rbp, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15, rflags);
		}

		/**
		 * \brief Changes the address to which is returned to after the hook (usually the hooked function).
		 * 
		 * \warning Changing the control flow of a function is very likely to produce crashes if not done with caution.
		 */
		void ChangeControllFlow(int64_t addressToReturnToAfterHook)
		{
			hook->ChangeReturn(addressToReturnToAfterHook);
		}

		/**
		 * \brief Skips the call of the hooked function but executing a RET.
		 * 
		 \warning Only to be called if the beginning of a function was hooked. Otherwhise results in undefined behavior.
		 */
		void SkipOriginalFunction()
		{
			hook->SkipOriginalFunction();
		}

		/**
		 * \brief Calls the original (unhooked) version of the function. Allows to call the hooked function without recursivly calling the hook again.
		 *
		 * @return result of the hooked function when invoked with the specified parameters.
		 */
		template<class RET, class...PARAMS>
		RET CallOriginal(CallingConvention cc = CallingConvention::cdecl_call, PARAMS... parameters)
		{
			using defaultFunc = RET(*)(PARAMS...);
			using cdeclFunc = RET(__cdecl*)(PARAMS...);
			using stdcallFunc = RET(__stdcall*)(PARAMS...);
			using fastcallFunc = RET(__fastcall*)(PARAMS...);
			using thiscallFunc = RET(__thiscall*)(PARAMS...);

			int8_t* originalFunction = hook->GetCallableVersionOfOriginal();

			switch (cc)
			{
			case CallingConvention::default_call:
				return ((defaultFunc)originalFunction)(parameters...);
				break;
			case CallingConvention::cdecl_call:
				return ((cdeclFunc)originalFunction)(parameters...);
				break;
			case CallingConvention::stdcall_call:
				return ((stdcallFunc)originalFunction)(parameters...);
				break;
			case CallingConvention::fastcall_call:
				return ((fastcallFunc)originalFunction)(parameters...);
				break;
			case CallingConvention::thiscall_call:
				return ((thiscallFunc)originalFunction)(parameters...);
				break;
			}
		}

	};
#elif _WIN32
	 /**
	  * \brief context for 32bit to be used in the hook callback
	  *
	  * \note Inside the hook any register can be read/written by using this context.
	  * 
	  * \warning Values of registers are at the time of hooking. The only expection to this is ESP which can be calculated by \GetEspAtHookAddress.
	  */
	struct context
	{
		MidfunctionHook* hook;
		// registers registers; we do not use the struct here because it is aligned at the start
		int32_t esp;
		int32_t eax;
		int32_t ecx;
		int32_t edx;
		int32_t ebx;
		int32_t ebp;
		int32_t esi;
		int32_t edi;

		// why not use __m128? because it uses 16 byte alignment
		int8_t xmm0[16];
		int8_t xmm1[16];
		int8_t xmm2[16];
		int8_t xmm3[16];
		int8_t xmm4[16];
		int8_t xmm5[16];
		int8_t xmm6[16];
		int8_t xmm7[16];

		int32_t eflags;

		/**
		 * \brief Prints the values of all registers
		 */
		void PrintRegister()
		{
			printf("register:\n\tesp %x\n\teax %x\n\tecx %x\n\tedx %x\n\tebx %x\n\tebp %x\n\tesi %x\n\tedi %x\n\teflags %x\n",
				esp, eax, ecx, edx, ebx, ebp, esi, edi, eflags);
		}

		/**
		* \brief Changes the address to which is returned to after the hook (usually the hooked function).
		* 
		* \warning Changing the control flow of a function is very likely to produce crashes if not done with caution.
		*/
		void ChangeControllFlow(int64_t addressToReturnToAfterHook)
		{
			hook->ChangeReturn(addressToReturnToAfterHook);
		}

		/**
		* \brief Skips the call of the hooked function but executing a RET.
		* 
		* \warning This usually only makes sense if the function is hooked directly at its beginning. Otherwhise behavior is undefined.
		*/
		void SkipOriginalFunction()
		{
			hook->SkipOriginalFunction();
		}

		/**
		 * \brief Calls the original (unhooked) version of the function. Allows to call the hooked function without recursivly calling the hook again.
		 *
		 * @return result of the hooked function when invoked with the specified parameters.
		 * 
		 * \warning Only to be called if the beginning of a function was hooked. Otherwhise results in undefined behavior.
		*/
		template<class RET, class...PARAMS>
		RET CallOriginal(CallingConvention cc = CallingConvention::cdecl_call, PARAMS... parameters)
		{
			using defaultFunc = RET(*)(PARAMS...);
			using cdeclFunc = RET(__cdecl*)(PARAMS...);
			using stdcallFunc = RET(__stdcall*)(PARAMS...);
			using fastcallFunc = RET(__fastcall*)(PARAMS...);
			using thiscallFunc = RET(__thiscall*)(PARAMS...);

			int8_t* originalFunction = hook->GetCallableVersionOfOriginal();

			switch (cc)
			{
				case CallingConvention::default_call:
					return ((defaultFunc)originalFunction)(parameters...);
					break;
				case CallingConvention::cdecl_call:
					return ((cdeclFunc)originalFunction)(parameters...);
					break;
				case CallingConvention::stdcall_call:
					return ((stdcallFunc)originalFunction)(parameters...);
					break;
				case CallingConvention::fastcall_call:
					return ((fastcallFunc)originalFunction)(parameters...);
					break;
				case CallingConvention::thiscall_call:
					return ((thiscallFunc)originalFunction)(parameters...);
					break;
			}
		}

	};
#endif
}
