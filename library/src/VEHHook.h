#pragma once

#include <cstdint>
#include <map>

namespace hookftw
{
	/**
	 * \brief Creates and manages VEH hooks.
	 *
	 * The current implementation supports hooking at the start of a function.
	 *
	 * \warning VEH Hooking is not thread safe
	 */
	class VEHHook
	{
		void* handleVEH_;
	
		int32_t originalPageProtection_;

		static LONG WINAPI CustomExceptionHandler(EXCEPTION_POINTERS* pExceptionInfo);
		static int8_t* addressedWhichCausedException_;
		static std::map<int8_t*, int8_t*> addressToProxyfunction_;

	public:	
		VEHHook();
		void Hook(int8_t* originalFunction, int8_t* hookedFunction);
		void Unhook();
	};
}
