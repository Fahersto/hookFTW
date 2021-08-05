#pragma once

#include <map>

namespace hookftw
{
	/**
	 * \brief Creates and manages hooks on the virtual function tables.
	 *
	 * While this hooking method requires deeper knowledge of the target function its main benefit is that only .data is written to hook. Therefore checksums of the .code section of the target program don't break.
	 * Also there is no requirement to allocate additional memory pages (VirtualAlloc) or change page protections (VirtualProtect).
	 */
	class VFTHook
	{
	private:
		int8_t** vftable_;
		std::map<int, int8_t*> hookedfuncs_;

	public:
		VFTHook(int8_t** vftable);

		int8_t* Hook(int index, int8_t* hookedFunction);

		bool Unhook(int index);
		void Unhook();
	};
}