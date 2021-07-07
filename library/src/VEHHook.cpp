#include "VEHHook.h"

#include <cstdio>
#include <Windows.h>

namespace hookftw
{
	int8_t* VEHHook::addressedWhichCausedException_ = nullptr;
	std::map<int8_t*, int8_t*> VEHHook::addressToProxyfunction_;

	//TODO this is not threads safe..
#ifdef _WIN64
	LONG WINAPI VEHHook::CustomExceptionHandler(EXCEPTION_POINTERS* pExceptionInfo)
	{
		//catch page guard validation
		if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
		{
			auto iterator = VEHHook::addressToProxyfunction_.find((int8_t*)pExceptionInfo->ContextRecord->Rip);
			addressedWhichCausedException_ = (int8_t*)pExceptionInfo->ContextRecord->Rip;

			//check if we are at the instruction within the page where we hooked
			if (iterator != VEHHook::addressToProxyfunction_.end())
			{
				//change program counter 
				pExceptionInfo->ContextRecord->Rip = (DWORD64)iterator->second; 
			}

			//STATUS_SINGLE_STEP exception --> handler will be invoked again on the next instruction
			pExceptionInfo->ContextRecord->EFlags |= 0x100;
			return EXCEPTION_CONTINUE_EXECUTION;
		}

		//catch STATUS_SINGLE_STEP exception
		if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
		{
			DWORD pageProtection;
			//set PAGE_GUARD protection because it got removed when catched earlier
			VirtualProtect(addressedWhichCausedException_, 1, PAGE_GUARD | PAGE_EXECUTE_READ, &pageProtection);
			return EXCEPTION_CONTINUE_EXECUTION;
		}

		//pass through exception which we don't handle
		return EXCEPTION_CONTINUE_SEARCH;
	}
#elif _WIN32
	LONG WINAPI VEHHook::CustomExceptionHandler(EXCEPTION_POINTERS* pExceptionInfo)
	{
		//catch page guard validation
		if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
		{
			auto iterator = VEHHook::addressToProxyfunction_.find((int8_t*)pExceptionInfo->ContextRecord->Eip);
			addressedWhichCausedException_ = (int8_t*)pExceptionInfo->ContextRecord->Eip;

			//check if we are at the instruction within the page where we hooked
			if (iterator != VEHHook::addressToProxyfunction_.end())
			{
				//change program counter
				pExceptionInfo->ContextRecord->Eip = (DWORD64)iterator->second;
			}

			//STATUS_SINGLE_STEP exception --> handler will be invoked again on the next instruction
			pExceptionInfo->ContextRecord->EFlags |= 0x100;
			return EXCEPTION_CONTINUE_EXECUTION;
}

		//catch STATUS_SINGLE_STEP exception
		if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
		{
			DWORD pageProtection;
			//set PAGE_GUARD protection because it got removed when catched earlier
			VirtualProtect(addressedWhichCausedException_, 1, PAGE_GUARD | PAGE_EXECUTE_READ, &pageProtection);
			return EXCEPTION_CONTINUE_EXECUTION;
		}

		//pass through exceptions we don't handle
		return EXCEPTION_CONTINUE_SEARCH;
	}
#endif

	VEHHook::VEHHook()
	{
	}

	void VEHHook::Hook(int8_t* originalFunction, int8_t* hookedFunction)
	{
		MEMORY_BASIC_INFORMATION mbiOriginal;
		MEMORY_BASIC_INFORMATION mbiHookedFunction;

		//query pages of orginal and hooked function
		if (!VirtualQuery(originalFunction, &mbiOriginal, sizeof(MEMORY_BASIC_INFORMATION)) ||
			!VirtualQuery(hookedFunction, &mbiHookedFunction, sizeof(MEMORY_BASIC_INFORMATION)))
		{
			printf("[Error] - VEHHook - Could not query page information!\n");
			return;
		}

		//We cannot hook two functions in the same page, because we will cause an infinite callback
		if (mbiOriginal.BaseAddress == mbiHookedFunction.BaseAddress)
		{
			printf("[Error] - VEHHook - Original function and hooked function are within the same page. This is not supported by this hooking method!\n");
			return;
		}
	
		VEHHook::addressToProxyfunction_.emplace(std::make_pair<>(originalFunction, hookedFunction));

		//Register the Custom Exception Handler
		handleVEH_ = AddVectoredExceptionHandler(true, CustomExceptionHandler);

		//Toggle PAGE_GUARD flag on the page
		VirtualProtect(originalFunction, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &originalPageProtection_);
	}

	void VEHHook::Unhook()
	{
		if (!handleVEH_)
		{
			return;
		}

		DWORD oldProtection;
		for (auto& hooks : VEHHook::addressToProxyfunction_)
		{
			//restore original page protection
			VirtualProtect(hooks.first, 1, originalPageProtection_, &oldProtection); 
		}

		//remove the custom exception handler
		RemoveVectoredExceptionHandler(handleVEH_);
	}

}