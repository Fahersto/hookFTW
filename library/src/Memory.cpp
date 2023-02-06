#include "Memory.h"

#include <iostream>

#ifdef _WIN32
#elif __linux
#include <unistd.h>
#include <dlfcn.h>
 #endif

namespace hookftw
{
    int8_t* Memory::FindFunctionInModule(std::string moduleName, std::string functionName)
    {
        #ifdef _WIN32
        HMODULE moduleHandle = GetModuleHandleA(moduleName.c_str());
        if (moduleHandle)
        {
            return (int8_t*)GetProcAddress(moduleHandle, functionName.c_str());
        }
        #elif __linux
        void* handle = dlopen(moduleName.c_str(), RTLD_LAZY);
        if (handle)
        {
            return (int8_t*)dlsym(handle, functionName.c_str());
        }
        #endif
        return nullptr;
    }

    int8_t* Memory::AllocPage(int8_t* address, int32_t size, MemoryPageProtection protection, MemoryPageFlag flag)
    {
        #ifdef _WIN32
        return (int8_t*)VirtualAlloc(address, size, (int)flag, (int)protection);
        #elif __linux
        return (int8_t*)mmap(address, size, (int)protection, (int)flag, -1, 0);
        #endif
    }

    bool Memory::FreePage(int8_t* address, int32_t size)
    {
        #ifdef _WIN32
        if (!VirtualFree(address, 0, MEM_RELEASE))
        {
            return false;
        }
        #elif __linux
        if (munmap(address, size))
        {
            return false;
        }
        #endif   
    }

    MemoryPageProtection Memory::QueryPageProtection(int8_t* address)
    {
        #ifdef _WIN32
                /*    
        SIZE_T VirtualQuery(
        [in, optional] LPCVOID                   lpAddress,
        [out]          PMEMORY_BASIC_INFORMATION lpBuffer,
        [in]           SIZE_T                    dwLength
        );
        */
        printf("Warning - QueryPageProtection not implemented¡\n");
        #elif __linux
        printf("Warning - QueryPageProtection not implemented¡\n");
        #endif

        return MemoryPageProtection::HOOKFTW_PAGE_EXECUTE_READ;

    }

    bool Memory::ModifyPageProtection(int8_t* address, int32_t size, MemoryPageProtection protection)
    {
        #ifdef _WIN32
        DWORD old;
        if (!VirtualProtect(address, size, (DWORD)protection, &old))
        {
            return false;
        }
        #elif __linux
        uint64_t addressPageBoundary = (uint64_t)address & ~(sysconf(_SC_PAGE_SIZE) - 1);
        if (mprotect((int8_t*)addressPageBoundary, size, (int)protection))
        {
            int errsv = errno;
            return false;
        }
        #endif
        return true;
    }

    int32_t Memory::GetPageSize()
    {
        #ifdef _WIN32
        SYSTEM_INFO systemInfo;
		GetSystemInfo(&systemInfo);
        return (int32_t)systemInfo.dwPageSize;
        #elif __linux
        return sysconf(_SC_PAGESIZE);
        #endif
    }

}