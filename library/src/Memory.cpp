#include "Memory.h"

#include <iostream>
#include <vector>
#include <sstream>

#ifdef _WIN32
#include <Windows.h>
#elif __linux
#include <dlfcn.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <link.h>
#include <fstream>
#include <sstream>
#endif

namespace hookftw
{
    int8_t *Memory::FindFunctionInModule(const std::string &moduleName, const std::string &functionName)
    {
#ifdef _WIN32
        HMODULE moduleHandle = GetModuleHandleA(moduleName.c_str());
        if (moduleHandle)
        {
            return (int8_t *) GetProcAddress(moduleHandle, functionName.c_str());
        }
#elif __linux
        void *handle = dlopen(moduleName.c_str(), RTLD_LAZY);
        if (handle)
        {
            return (int8_t *) dlsym(handle, functionName.c_str());
        }
#endif
        return nullptr;
    }

    int8_t *Memory::FindPattern(const int8_t *startAddress, size_t searchSize, const std::string &pattern)
    {
        // Parse pattern string into bytes and mask
        // Pattern format: "48 8B 05 ? ? ? ? 48 89 05" where ? is wildcard
        std::vector<uint8_t> patternBytes;
        std::vector<bool> patternMask; // true = check byte, false = wildcard

        std::istringstream iss(pattern);
        std::string token;
        while (iss >> token)
        {
            if (token == "?" || token == "??")
            {
                patternBytes.push_back(0);
                patternMask.push_back(false); // wildcard
            }
            else
            {
                // Parse hex byte
                patternBytes.push_back((uint8_t) std::stoul(token, nullptr, 16));
                patternMask.push_back(true); // check this byte
            }
        }

        if (patternBytes.empty())
        {
            return nullptr;
        }

        // Check if pattern is larger than search size
        if (patternBytes.size() > searchSize)
        {
            return nullptr;
        }

        // Search for pattern
        for (size_t i = 0; i <= searchSize - patternBytes.size(); i++)
        {
            bool found = true;
            for (size_t j = 0; j < patternBytes.size(); j++)
            {
                if (patternMask[j] && static_cast<uint8_t>(startAddress[i + j]) != patternBytes[j])
                {
                    found = false;
                    break;
                }
            }

            if (found)
            {
                return const_cast<int8_t *>(startAddress + i);
            }
        }

        return nullptr;
    }

    int8_t *Memory::FindPatternInModule(const std::string &moduleName, const std::string &pattern)
    {
#ifdef _WIN32
        // Empty module name means main executable
        HMODULE moduleHandle = GetModuleHandleA(moduleName.empty() ? NULL : moduleName.c_str());
        if (!moduleHandle)
        {
            return nullptr;
        }

        // Parse PE header to get module size
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER) moduleHandle;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((int8_t *) moduleHandle + dosHeader->e_lfanew);
        size_t moduleSize = ntHeaders->OptionalHeader.SizeOfImage;

        return FindPattern((int8_t *) moduleHandle, moduleSize, pattern);

#elif __linux
        // Helper callback to find module info
        struct CallbackData
        {
            std::string targetModule;
            int8_t *baseAddress;
            size_t moduleSize;
        };

        auto dl_callback = [](struct dl_phdr_info *info, size_t size, void *data) -> int
        {
            auto *callbackData = static_cast<CallbackData *>(data);

            // Check if this is the module we're looking for
            const char *moduleName = info->dlpi_name;
            if (moduleName == nullptr || moduleName[0] == '\0')
            {
                // Main executable - check against executable name
                char exePathBuf[4096];
                ssize_t len = readlink("/proc/self/exe", exePathBuf, sizeof(exePathBuf) - 1);
                if (len != -1)
                {
                    exePathBuf[len] = '\0';
                    moduleName = exePathBuf;
                }
            }

            if (moduleName && (std::string(moduleName).find(callbackData->targetModule) != std::string::npos ||
                               callbackData->targetModule.find(moduleName) != std::string::npos))
            {
                callbackData->baseAddress = (int8_t *) info->dlpi_addr;

                // Calculate module size from program headers
                size_t maxAddr = 0;
                for (int i = 0; i < info->dlpi_phnum; i++)
                {
                    if (info->dlpi_phdr[i].p_type == PT_LOAD)
                    {
                        size_t segmentEnd = info->dlpi_phdr[i].p_vaddr + info->dlpi_phdr[i].p_memsz;
                        if (segmentEnd > maxAddr)
                        {
                            maxAddr = segmentEnd;
                        }
                    }
                }
                callbackData->moduleSize = maxAddr;

                return 1; // Stop iteration
            }
            return 0; // Continue iteration
        };

        CallbackData data = {moduleName, nullptr, 0};
        dl_iterate_phdr(dl_callback, &data);

        if (data.baseAddress == nullptr)
        {
            return nullptr;
        }

        return FindPattern(data.baseAddress, data.moduleSize, pattern);
#endif
    }

    int8_t *Memory::AllocPage(int8_t *address, int32_t size, MemoryPageProtection protection, MemoryPageFlag flag)
    {
#ifdef _WIN32
        return (int8_t *) VirtualAlloc(address, size, (int) flag, (int) protection);
#elif __linux
        if (address == nullptr)
        {
            // No hint address - allocate anywhere
            auto result = static_cast<int8_t *>(mmap(nullptr, size, (int) protection, MAP_PRIVATE | MAP_ANONYMOUS, -1,
                                                     0));
            if (result == MAP_FAILED)
            {
                return nullptr;
            }
            return result;
        }

        uint64_t alignedAddress = (uintptr_t)address & ~(GetPageSize() - 1);
        auto result = static_cast<int8_t *>(mmap((void *)alignedAddress, size, (int) protection, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0));
        if (result != MAP_FAILED)
        {
            return result;
        }
#endif
        return nullptr;
    }

    bool Memory::FreePage(int8_t *address, int32_t size)
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

    MemoryPageProtection Memory::QueryPageProtection(const int8_t *address)
    {
#ifdef _WIN32
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(address, &mbi, sizeof(mbi)) == 0)
        {
            // Query failed, return a safe default
            return MemoryPageProtection::HOOKFTW_PAGE_EXECUTE_READ;
        }

        // Map Windows protection flags to our enum
        switch (mbi.Protect & 0xFF)
        {
            // Mask out PAGE_GUARD, PAGE_NOCACHE, etc.
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
        FILE *fp = fopen("/proc/self/maps", "r");
        if (!fp)
        {
            perror("fopen /proc/self/maps");
            return MemoryPageProtection::HOOKFTW_PAGE_EXECUTE_READ;
        }

        char line[256];
        uintptr_t addr_start, addr_end;
        char perms[5];
        MemoryPageProtection protection = MemoryPageProtection::HOOKFTW_PAGE_EXECUTE_READ;

        while (fgets(line, sizeof(line), fp))
        {
            if (sscanf(line, "%lx-%lx %4s", &addr_start, &addr_end, perms) == 3)
            {
                if ((uintptr_t) address >= addr_start && (uintptr_t) address < addr_end)
                {
                    if (perms[0] == 'r' && perms[1] == 'w' && perms[2] == 'x')
                    {
                        protection = MemoryPageProtection::HOOKFTW_PAGE_EXECUTE_READWRITE;
                    }
                    else if (perms[0] == 'r' && perms[1] == 'w')
                    {
                        protection = MemoryPageProtection::HOOKFTW_PAGE_READWRITE;
                    }
                    else if (perms[0] == 'r' && perms[2] == 'x')
                    {
                        protection = MemoryPageProtection::HOOKFTW_PAGE_EXECUTE_READ;
                    }
                    else if (perms[0] == 'r')
                    {
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

    bool Memory::ModifyPageProtection(const int8_t *address, int32_t size, MemoryPageProtection protection)
    {
#ifdef _WIN32
        DWORD old;
        // VirtualProtect requires non-const pointer, but doesn't actually modify the memory at the pointer itself
        if (!VirtualProtect(const_cast<int8_t *>(address), size, (DWORD) protection, &old))
        {
            return false;
        }
#elif __linux
        uintptr_t addressPageBoundary = (uintptr_t) address & ~(sysconf(_SC_PAGE_SIZE) - 1);
        uintptr_t addressEnd = (uintptr_t) address + size;
        uintptr_t addressEndPageBoundary = (addressEnd + sysconf(_SC_PAGE_SIZE) - 1) & ~(sysconf(_SC_PAGE_SIZE) - 1);
        size_t totalSize = addressEndPageBoundary - addressPageBoundary;

        if (mprotect((void *) addressPageBoundary, totalSize, (int) protection))
        {
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
        return (int32_t) systemInfo.dwPageSize;
#elif __linux
        return sysconf(_SC_PAGESIZE);
#endif
    }

    int8_t *Memory::GetProcessBaseAddress()
    {
#ifdef _WIN32
        // On Windows, GetModuleHandle(NULL) returns the base address of the main executable
        return (int8_t *) GetModuleHandle(NULL);

#elif __linux
        // Helper callback for dl_iterate_phdr
        struct CallbackData
        {
            int8_t *baseAddress;
        };

        auto dl_callback = [](struct dl_phdr_info *info, size_t size, void *data) -> int
        {
            // The main executable has an empty name
            if (info->dlpi_name == nullptr || info->dlpi_name[0] == '\0')
            {
                auto *callbackData = static_cast<CallbackData *>(data);
                callbackData->baseAddress = (int8_t *) info->dlpi_addr;
                return 1; // Stop iteration
            }
            return 0; // Continue iteration
        };

        CallbackData data = {nullptr};
        dl_iterate_phdr(dl_callback, &data);

        // Fallback: parse /proc/self/maps if dl_iterate_phdr returned 0
        // (can happen with some PIE configurations)
        if (data.baseAddress == nullptr)
        {
            // Get the path to the main executable
            char exePathBuf[4096];
            ssize_t len = readlink("/proc/self/exe", exePathBuf, sizeof(exePathBuf) - 1);
            if (len == -1)
            {
                return nullptr;
            }
            exePathBuf[len] = '\0';
            std::string exePath(exePathBuf);

            std::ifstream maps("/proc/self/maps");
            if (!maps.is_open())
            {
                return nullptr;
            }

            std::string line;
            while (std::getline(maps, line))
            {
                // Look for the first executable mapping of our binary
                if (line.find("r-xp") != std::string::npos && line.find(exePath) != std::string::npos)
                {
                    std::istringstream iss(line);
                    std::string addr_range;
                    iss >> addr_range;
                    size_t dash = addr_range.find('-');
                    if (dash != std::string::npos)
                    {
                        std::string base_str = addr_range.substr(0, dash);
                        return (int8_t *) std::stoull(base_str, nullptr, 16);
                    }
                }
            }
        }

        return data.baseAddress;
#endif
    }
}
