#include "VFTHook.h"

#include "Memory.h"

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
	 * @param hookedFunction function to be called instead of the original
	 */
	int8_t* VFTHook::Hook(int index, int8_t* hookedFunction)
	{
		hookedfuncs_.insert(std::make_pair(index, vftable_[index]));

		// safe old protection
		MemoryPageProtection oldProtection = Memory::QueryPageProtection((int8_t*)&vftable_[index]);

		//make memory page writeable
		Memory::ModifyPageProtection((int8_t*)&vftable_[index], sizeof(void*), MemoryPageProtection::PAGE_EXECUTE_READWRITE);

		//overwrite function pointer in vftable to hook function
		vftable_[index] = hookedFunction;

		//restore page protection
		Memory::ModifyPageProtection((int8_t*)&vftable_[index], sizeof(void*), oldProtection);

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

			// safe old protection
			MemoryPageProtection oldProtection = Memory::QueryPageProtection((int8_t*)&vftable_[pair.first]);

			//make memory page writeable
			Memory::ModifyPageProtection((int8_t*)&vftable_[pair.first], sizeof(void*), MemoryPageProtection::PAGE_EXECUTE_READWRITE);

			//overwrite function pointer in vftable to hook function
			vftable_[pair.first] = pair.second;

			//restore page protection
			Memory::ModifyPageProtection((int8_t*)&vftable_[pair.first], sizeof(void*), oldProtection);
		}
	}
}