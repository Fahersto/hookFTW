#include "Memory.h"

#include <iostream>

#ifdef _WIN32
#include <Windows.h>
#elif __linux
#include <dlfcn.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#endif

namespace hookftw
{
    int8_t* Memory::FindFunctionInModule(const std::string& moduleName, const std::string& functionName)
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
        auto result = static_cast<int8_t*>(mmap(address, size, (int) protection, address ? (int) flag : MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
        if (result == MAP_FAILED)
        {
            return nullptr;
        }
        return result;
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
        return true;
    }

    MemoryPageProtection Memory::QueryPageProtection(const int8_t* address)
    {
        #ifdef _WIN32
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(address, &mbi, sizeof(mbi)) == 0) {
            // Query failed, return a safe default
            return MemoryPageProtection::HOOKFTW_PAGE_EXECUTE_READ;
        }

        // Map Windows protection flags to our enum
        switch (mbi.Protect & 0xFF) { // Mask out PAGE_GUARD, PAGE_NOCACHE, etc.
            case PAGE_READONLY:
                return MemoryPageProtection::HOOKFTW_PAGE_READONLY;
            case PAGE_READWRITE:
            case PAGE_WRITECOPY:
                return MemoryPageProtection::HOOKFTW_PAGE_READWRITE;
            case PAGE_EXECUTE:
                return MemoryPageProtection::HOOKFTW_PAGE_EXECUTE;
            case PAGE_EXECUTE_READ:
                return MemoryPageProtection::HOOKFTW_PAGE_EXECUTE_READ;
            case PAGE_EXECUTE_READWRITE:
            case PAGE_EXECUTE_WRITECOPY:
                return MemoryPageProtection::HOOKFTW_PAGE_EXECUTE_READWRITE;
            default:
                return MemoryPageProtection::HOOKFTW_PAGE_EXECUTE_READ;
        }
        #elif __linux
        FILE* fp = fopen("/proc/self/maps", "r");
        if (!fp) {
            perror("fopen /proc/self/maps");
            return MemoryPageProtection::HOOKFTW_PAGE_EXECUTE_READ;
        }

        char line[256];
        uintptr_t addr_start, addr_end;
        char perms[5];
        MemoryPageProtection protection = MemoryPageProtection::HOOKFTW_PAGE_EXECUTE_READ;

        while (fgets(line, sizeof(line), fp)) {
            if (sscanf(line, "%lx-%lx %4s", &addr_start, &addr_end, perms) == 3) {
                if ((uintptr_t)address >= addr_start && (uintptr_t)address < addr_end) {
                    if (perms[0] == 'r' && perms[1] == 'w' && perms[2] == 'x') {
                        protection = MemoryPageProtection::HOOKFTW_PAGE_EXECUTE_READWRITE;
                    } else if (perms[0] == 'r' && perms[1] == 'w') {
                        protection = MemoryPageProtection::HOOKFTW_PAGE_READWRITE;
                    } else if (perms[0] == 'r' && perms[2] == 'x') {
                        protection = MemoryPageProtection::HOOKFTW_PAGE_EXECUTE_READ;
                    } else if (perms[0] == 'r') {
                        protection = MemoryPageProtection::HOOKFTW_PAGE_READONLY;
                    }
                     // Handle other cases if necessary
                    break;
                }
            }
        }
        fclose(fp);
        return protection;
        #endif
    }

    bool Memory::ModifyPageProtection(const int8_t* address, int32_t size, MemoryPageProtection protection)
    {
        #ifdef _WIN32
        DWORD old;
        // VirtualProtect requires non-const pointer, but doesn't actually modify the memory at the pointer itself
        if (!VirtualProtect(const_cast<int8_t*>(address), size, (DWORD)protection, &old))
        {
            return false;
        }
        #elif __linux
        uintptr_t addressPageBoundary = (uintptr_t)address & ~(sysconf(_SC_PAGE_SIZE) - 1);
        uintptr_t addressEnd = (uintptr_t)address + size;
        uintptr_t addressEndPageBoundary = (addressEnd + sysconf(_SC_PAGE_SIZE) - 1) & ~(sysconf(_SC_PAGE_SIZE) - 1);
        size_t totalSize = addressEndPageBoundary - addressPageBoundary;

        if (mprotect((void*)addressPageBoundary, totalSize, (int)protection))
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