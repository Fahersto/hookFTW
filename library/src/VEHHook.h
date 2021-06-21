#pragma once
#include <Windows.h>
#include <cstdint>
#include <map>

namespace hookftw
{
	/**
	 * \brief Creates and manages VEH hooks.
	 *
	 * Only supports hooking at the start of a function. It would be possible to use it for midfunction hook aswell.. 
	 *
	 * \warning VEH Hooking is not thread safe
	 */
	class VEHHook
	{
		void* handleVEH_;
	
		DWORD originalPageProtection_;

		static LONG WINAPI CustomExceptionHandler(EXCEPTION_POINTERS* pExceptionInfo);
		static int8_t* addressedWhichCausedException_;
		static std::map<int8_t*, int8_t*> addressToProxyfunction_;

	public:	
		VEHHook(int8_t* originalFunction, int8_t* hookedFunction);
		void Unhook();
	};
}
