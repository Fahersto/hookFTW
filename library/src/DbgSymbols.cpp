#include "DbgSymbols.h"

#include <Windows.h>
#include <dbghelp.h>
#include <tchar.h>

#include "Logger.h"

namespace hookftw
{
    bool DbgSymbols::symbolsLoaded_ = false;
    int64_t DbgSymbols::baseAddress_ = NULL;

    /**
     * Loads debug symbols of the current process.
     *
     * @param path to search for the .pdb file. If no path is given the default paths are used.
     */
    DbgSymbols::DbgSymbols(char* path)
    {
    	if (!symbolsLoaded_)
    	{
            LoadSymbols(path);
            char executablePath[MAX_PATH];
            GetModuleFileNameA(NULL, executablePath, MAX_PATH);
			baseAddress_ = SymLoadModuleEx(GetCurrentProcess(), NULL, executablePath, NULL, (DWORD64)GetModuleHandle(nullptr), 0x7fffffffffffffff, NULL, 0);
            symbolsLoaded_ = true;
    	}
    }

	/**
	 * Loads debug symbols of the current process.
	 *
	 * @return <code>true</code> or <code>false</code> depending on success of load operation
	 */
    bool DbgSymbols::LoadSymbols(char* path)
    {
        SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);

        if (!SymInitialize(GetCurrentProcess(), path, FALSE))
        {
            printf("SymInitialize returned error : %d\n", GetLastError());
            return false;
        }
		symbolsLoaded_ = true;
        return true;
    }

	/**
	 * Resolves the address of a symbol by its name.
	 *
	 * @return address of the symbols or nullptr if the symbol name could not be found.
	 */
    //https://docs.microsoft.com/en-us/windows/win32/debug/using-dbghelp
    int8_t* DbgSymbols::GetAddressBySymbolName(const char* name)
    {
        if (!symbolsLoaded_ || !baseAddress_)
        {
            printf("Symbols are not loaded\n");
            return nullptr;
        }
    	
        TCHAR szSymbolName[MAX_SYM_NAME];
        ULONG64 buffer[(sizeof(SYMBOL_INFO) +
            MAX_SYM_NAME * sizeof(TCHAR) +
            sizeof(ULONG64) - 1) /
            sizeof(ULONG64)];
        PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;

        _tcscpy_s(szSymbolName, MAX_SYM_NAME, TEXT(name));
        pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        pSymbol->MaxNameLen = MAX_SYM_NAME;

        pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        pSymbol->MaxNameLen = MAX_SYM_NAME;
    	
        if (SymFromName(GetCurrentProcess(), name, pSymbol))
        {
            int8_t* base = (int8_t*)baseAddress_;
            int8_t* symbolAddress = (int8_t*)pSymbol->Address;
            int8_t* symbolBase = (int8_t*)pSymbol->ModBase;
        	
			return symbolAddress - symbolBase + base;
        }

        printf("SymFromName returned error : %d\n", GetLastError());
        return nullptr;
    }

    BOOL CALLBACK EnumSymProc(PSYMBOL_INFO pSymInfo, ULONG SymbolSize, PVOID UserContext)
    {
        UNREFERENCED_PARAMETER(UserContext);
        char buffer[5000];
        sprintf(buffer, "%llx %4u %s\n", pSymInfo->Address, SymbolSize, pSymInfo->Name);
        // printf("%llx %4u %s\n", pSymInfo->Address, SymbolSize, pSymInfo->Name);
        Logger::Log(buffer);
        return TRUE;
    }


    /**
     * Enumerates all symbols in the binary and writes them to a log file.
     */
    void DbgSymbols::EnumerateSymbols()
    {
        if (!symbolsLoaded_)
        {
            return;
        }

        const char* allInImageName = "*";
        const char* allInEveryModule = "*!*";

        char executablePath[MAX_PATH];
        GetModuleFileNameA(NULL, executablePath, MAX_PATH);
        auto base_addr = (size_t)SymLoadModuleEx(GetCurrentProcess(), NULL, executablePath, NULL, NULL, 0x7fffffffffffffff, NULL, 0);
        SymEnumSymbols(GetCurrentProcess(), base_addr, allInEveryModule, EnumSymProc, NULL);
    }
}
