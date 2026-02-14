#include "VFTHook.h"

#include <iostream>
#include <iomanip>

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
		hookedFunctions_.insert(std::make_pair(index, vftable_[index]));

		// safe old protection
		MemoryPageProtection oldProtection = Memory::QueryPageProtection((int8_t*)&vftable_[index]);

		//make memory page writeable
		Memory::ModifyPageProtection((int8_t*)&vftable_[index], sizeof(void*), MemoryPageProtection::HOOKFTW_PAGE_EXECUTE_READWRITE);

		//overwrite function pointer in vftable to hook function
		vftable_[index] = hookedFunction;

		//restore page protection
		Memory::ModifyPageProtection((int8_t*)&vftable_[index], sizeof(void*), oldProtection);

		return hookedFunctions_[index];
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
		const auto entry = hookedFunctions_.find(index);
		if (entry != hookedFunctions_.end())
		{
			// safe old protection
			MemoryPageProtection oldProtection = Memory::QueryPageProtection((int8_t*)&vftable_[entry->first]);

			//make memory page writeable
			Memory::ModifyPageProtection((int8_t*)&vftable_[entry->first], sizeof(void*), MemoryPageProtection::HOOKFTW_PAGE_EXECUTE_READWRITE);

			vftable_[entry->first] = entry->second;

			//restore page protection
			Memory::ModifyPageProtection((int8_t*)&vftable_[entry->first], sizeof(void*), oldProtection);

			return true;
		}
		return false;
	}

	/**
	* \brief Unhooks all previously hooked functions in the virtual function table.
	*/
	void VFTHook::Unhook()
	{
		for (const std::pair<int, int8_t*> pair : hookedFunctions_)
		{
			// safe old protection
			MemoryPageProtection oldProtection = Memory::QueryPageProtection((int8_t*)&vftable_[pair.first]);

			//make memory page writeable
			Memory::ModifyPageProtection((int8_t*)&vftable_[pair.first], sizeof(void*), MemoryPageProtection::HOOKFTW_PAGE_EXECUTE_READWRITE);

			//overwrite function pointer in vftable to hook function
			vftable_[pair.first] = pair.second;

			//restore page protection
			Memory::ModifyPageProtection((int8_t*)&vftable_[pair.first], sizeof(void*), oldProtection);
		}
	}

	/**
	 * \brief Prints all function pointers in the virtual function table.
	 *
	 * This is a best-effort function that safely scans the VFT and prints
	 * all valid function pointers. It will never crash even if it encounters
	 * invalid memory or corrupted VFT entries.
	 */
	void VFTHook::PrintVFT(int maxEntries) const
	{
		if (!vftable_)
		{
			std::cout << "VFT is null" << std::endl;
			return;
		}

		std::cout << "Virtual Function Table Contents:" << std::endl;
		std::cout << "Index | Address    | Status" << std::endl;
		std::cout << "------|------------|-------" << std::endl;

		try
		{
			for (int i = 0; i < maxEntries; ++i)
			{
				try
				{
					int8_t* funcPtr = nullptr;
					bool canRead = false;

					try
					{
						funcPtr = vftable_[i];
						canRead = true;
					}
					catch (...)
					{
						canRead = false;
					}

					// Print the entry information
					std::cout << std::setw(5) << i << " | ";

					if (!canRead)
					{
						std::cout << "INACCESSIBLE | error" << std::endl;
						continue;
					}

					if (funcPtr == nullptr)
					{
						std::cout << "NULL       | null" << std::endl;
					}
					else
					{
						std::cout << "0x" << std::hex << std::setw(8) << std::setfill('0')
								  << reinterpret_cast<uintptr_t>(funcPtr) << " | ";

						// Check if this function is currently hooked
						auto hookedEntry = hookedFunctions_.find(i);
						if (hookedEntry != hookedFunctions_.end())
						{
							std::cout << "hooked (orig: 0x" << std::hex << std::setw(8) << std::setfill('0')
									  << reinterpret_cast<uintptr_t>(hookedEntry->second) << ")" << std::endl;
						}
						else
						{
							auto addr = reinterpret_cast<uintptr_t>(funcPtr);
							if (addr > 0x1000 && addr < 0x7FFFFFFFFFFF)  // Basic sanity check for 64-bit addresses
							{
								std::cout << "valid" << std::endl;
							}
							else
							{
								std::cout << "invalid?" << std::endl;
							}
						}
					}
					std::cout << std::dec << std::setfill(' ');
				}
				catch (...)
				{
					std::cout << std::setw(5) << i << " | INACCESSIBLE | error" << std::endl;
				}
			}
		}
		catch (...)
		{
			std::cout << "Error occurred while scanning VFT" << std::endl;
		}

		std::cout << "End of VFT scan" << std::endl;
	}
}