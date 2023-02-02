#include "Memory.h"

#include <iostream>

#ifdef _WIN32
#elif __linux
#include <unistd.h>
 #endif

namespace hookftw
{
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

        return MemoryPageProtection::HOOKFTW_PAGE_EXECUTE_READWRITE;

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
        if (mprotect(address, size, (int)protection))
        {
            return false;
        }
        #endif
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