#pragma once

#include <cstdint>
#include <string>

namespace hookftw
{
	/**
	 * \brief Creates and manages Import Address Table hooks.
	 */
	class IATHook
	{
		int8_t* addressOfEntry_ = nullptr;
		int8_t* originalFunctionPointer_ = nullptr;
	public:
		IATHook();
		int8_t* Hook(std::string moduleName, std::string functionName, int8_t* hookedFunction);
		void Unhook();
	};
}
