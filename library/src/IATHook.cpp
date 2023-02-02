#include "IATHook.h"

#include <cstdint>

#ifdef _WIN32
#include <Windows.h>
#elif __linux
#endif

namespace hookftw
{
	/**
	 * \brief Resolves module and function name to its IAT entry.
	 *
	 * @param moduleName name of the module in which the target function resides (e.g. User32.dll)
	 * @param functionName name of the function to hook (e.g. MessageBoxA)
	 *
	 * @return pointer to the address of the target function inside the IAT
	 */
	int8_t* GetPointerToFunctionAddress(std::string moduleName, std::string functionName)
	{
		PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)GetModuleHandle(NULL);
		PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((int8_t*)dosHeader + dosHeader->e_lfanew);

		if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
		{
			return nullptr;
		}

		// get import descriptor from PE header
		PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((int8_t*)dosHeader + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		for (int32_t i = 0; importDescriptor[i].Characteristics != 0; i++)
		{
			char* currentModuleName = (char*)dosHeader + importDescriptor[i].Name;

			// check if we found the target module
			if (strcmpi(currentModuleName, moduleName.c_str()) != 0)
			{
				continue;
			}

			// check if IAT adresses are bound
			if (!importDescriptor[i].FirstThunk || !importDescriptor[i].OriginalFirstThunk)
			{
				return nullptr;
			}

			PIMAGE_THUNK_DATA originalThunk = (PIMAGE_THUNK_DATA)((int8_t*)dosHeader + importDescriptor[i].OriginalFirstThunk);
			PIMAGE_THUNK_DATA currentThunk = (PIMAGE_THUNK_DATA)((int8_t*)dosHeader + importDescriptor[i].FirstThunk);
			while (originalThunk->u1.Function != NULL)
			{
				PIMAGE_IMPORT_BY_NAME import = (PIMAGE_IMPORT_BY_NAME)((int8_t*)dosHeader + originalThunk->u1.AddressOfData);

				// check if named import is used (we don't support ordinals). Additionally check if we found the target function
				if (originalThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG || strcmpi(functionName.c_str(), (char*)import->Name) != 0)
				{
					originalThunk++;
					currentThunk++;
					continue;
				}

				// return address of the found IAT entry
				return (int8_t*)&currentThunk->u1.Function;
			}
		}
		return nullptr;
	}

	/**
	 * \brief Default constructor.
	 */
	IATHook::IATHook()
	{

	}

	/**
	 * \brief Hooks a function inside the import address table.
	 *
	 * @param moduleName name of the module in which the target function resides (e.g. User32.dll)
	 * @param functionName name of the function to hook (e.g. MessageBoxA)
	 * @param hookedFunction function to be called instead of the original
	 */
	int8_t* IATHook::Hook(std::string moduleName, std::string functionName, int8_t* hookedFunction)
	{
		// get address of IAT entry
		addressOfEntry_ = GetPointerToFunctionAddress(moduleName, functionName);

		if (addressOfEntry_ == nullptr)
		{
			printf("[Error] - Failed to find IAT entry for %s --> %s\n", moduleName.c_str(), functionName.c_str());
			return nullptr;
		}

		DWORD oldProtection = 0;

		// make page writeable
		VirtualProtect(addressOfEntry_, sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProtection);

		// save original function
		memcpy(&originalFunctionPointer_, addressOfEntry_, sizeof(void*));

		// overwrite IAT entry with supplied function
		memcpy(addressOfEntry_, &hookedFunction, sizeof(void*));

		// restore page protection
		VirtualProtect(addressOfEntry_, sizeof(void*), oldProtection, &oldProtection);

		// return address of original function so it can be called
		return originalFunctionPointer_;
	}

	/**
	 * \brief Unhooks a previously hooked function inside the import address table.
	 */
	void IATHook::Unhook()
	{
		DWORD oldProtection = 0;

		// make page writeable
		VirtualProtect(addressOfEntry_, sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProtection);

		// restore IAT entry with supplied saved function pointer
		memcpy(addressOfEntry_, &originalFunctionPointer_, sizeof(void*));

		// restore page protection
		VirtualProtect(addressOfEntry_, sizeof(void*), oldProtection, &oldProtection);
	}
}
