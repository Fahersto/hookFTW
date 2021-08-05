#include "VFTHook.h"

#include <Windows.h>

namespace hookftw
{
	/**
	 * \brief Creates and manages hooks on the virtual function table of an object.
	 *
	 * @param vftable address of the first entry in the virtual function table
	 */
	VFTHook::VFTHook(int8_t** vftable)
		: vftable_(vftable)
	{
	}

	/**
	 * \brief Hooks a function inside the virtual function table.
	 *
	 * @param index index of the function to hook inside the virtual function table (starting at 0)
	 * @param hookedFunction proxy function
	 */
	int8_t* VFTHook::Hook(int index, int8_t* hookedFunction)
	{
		hookedfuncs_.insert(std::make_pair(index, vftable_[index]));

		//make memory page writeable
		DWORD pageProtection;
		VirtualProtect(&vftable_[index], sizeof(void*), PAGE_EXECUTE_READWRITE, &pageProtection);

		//overwrite function pointer in vftable to hook function
		vftable_[index] = hookedFunction;

		//restore page protection
		VirtualProtect(&vftable_[index], sizeof(void*), pageProtection, &pageProtection);

		return hookedfuncs_[index];
	}

	/**
	* \brief Unhooks a previously hooked function inside the virtual function table.
	*
	* @param index index of the function to uhook inside the virtual function table (starting at 0)
	*
	* @return true if the function was hooked previously and is unhooked now. False otherwhise. 
	 */
	bool VFTHook::Unhook(int index)
	{
		const auto entry = hookedfuncs_.find(index);
		if (entry != hookedfuncs_.end())
		{
			vftable_[entry->first] = entry->second;
			return true;
		}
		return false;
	}

	/**
	* \brief Unhooks all previously hooked functions in the virtual function table.
	*/
	void VFTHook::Unhook()
	{
		for (const std::pair<int, int8_t*> pair : hookedfuncs_)
		{
			DWORD oldProtection;
			VirtualProtect(&vftable_[pair.first], sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProtection);
			vftable_[pair.first] = pair.second;
			VirtualProtect(&vftable_[pair.first], sizeof(void*), oldProtection, &oldProtection);
		}
	}
}