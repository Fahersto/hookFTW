#pragma once

#include <map>

namespace hookftw
{
	/**
	 * \brief Creates and manages hooks on the virtual function table of an object.
	 *
	 * While this hooking method requires deeper knowledge of the target function its main benefit is that only .data is written to hook. Therefore checksums of the .code section of the target program don't break.
	 * Also there is no requirement to allocate additional memory pages (VirtualAlloc) or change page protections (VirtualProtect).
	 */
	class VFTHook
	{
	private:
		void** vftable_;
		std::map<int, void*> hookedfuncs_;

	public:
		VFTHook(void** vftable);

		void* Hook(int index, void* hookedFunction);

		bool Unhook(int index);
		void Unhook();
	};
}