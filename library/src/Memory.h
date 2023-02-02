#pragma once

#include <cstdint>
#include <string>

#ifdef _WIN32
#include <Windows.h>
#elif __linux
#include <sys/mman.h>
#endif


namespace hookftw
{
    enum class MemoryPageProtection
    {
    #ifdef _WIN32
        HOOKFTW_PAGE_READONLY          = PAGE_READONLY,
        HOOKFTW_PAGE_READWRITE         = PAGE_READWRITE,
        HOOKFTW_PAGE_EXECUTE           = PAGE_EXECUTE,
        HOOKFTW_PAGE_EXECUTE_READ      = PAGE_EXECUTE_READ,
        HOOKFTW_PAGE_EXECUTE_READWRITE = PAGE_EXECUTE_READWRITE

    #elif __linux
        HOOKFTW_PAGE_READONLY          = PROT_READ,
        HOOKFTW_PAGE_READWRITE         = PROT_READ | PROT_WRITE,
        HOOKFTW_PAGE_EXECUTE           = PROT_EXEC,
        HOOKFTW_PAGE_EXECUTE_READ      = PROT_EXEC | PROT_READ,
        HOOKFTW_PAGE_EXECUTE_READWRITE = PROT_EXEC | PROT_READ | PROT_WRITE

    #endif
    };

    enum class MemoryPageFlag
    {
    #ifdef _WIN32
        HOOKFTW_MEM_DEFAULT = MEM_RESERVE | MEM_COMMIT

    #elif __linux
        HOOKFTW_MEM_DEFAULT = MAP_PRIVATE | MAP_ANONYMOUS
    #endif
    };

class Memory
{
    public:
        static int8_t* FindFunctionInModule(std::string moduleName, std::string functionName);
        static int8_t* AllocPage(int8_t* address, int32_t size, MemoryPageProtection protection, MemoryPageFlag flag);
        static bool FreePage(int8_t* address, int32_t size);
        static bool ModifyPageProtection(int8_t* address, int32_t size, MemoryPageProtection protection);
        static MemoryPageProtection QueryPageProtection(int8_t* address);
        static int32_t GetPageSize();
};
}