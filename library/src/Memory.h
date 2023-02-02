#pragma once

#include <cstdint>

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
        PAGE_READONLY          = PAGE_READONLY,
        PAGE_READWRITE         = PAGE_READWRITE,
        PAGE_EXECUTE           = PAGE_EXECUTE,
        PAGE_EXECUTE_READ      = PAGE_EXECUTE_READ,
        PAGE_EXECUTE_READWRITE = PAGE_EXECUTE_READWRITE

    #elif __linux
        PAGE_READONLY          = PROT_READ,
        PAGE_READWRITE         = PROT_READ | PROT_WRITE,
        PAGE_EXECUTE           = PROT_EXEC,
        PAGE_EXECUTE_READ      = PROT_EXEC | PROT_READ,
        PAGE_EXECUTE_READWRITE = PROT_EXEC | PROT_READ | PROT_WRITE

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
        static int8_t* VirtualAlloc(int8_t* address, int32_t size, MemoryPageProtection protection, MemoryPageFlag flag);
        static bool VirtualFree(int8_t* address, int32_t size);
        static bool ModifyPageProtection(int8_t* address, int32_t size, MemoryPageProtection protection);
        static MemoryPageProtection QueryPageProtection(int8_t* address);
        static int32_t GetPageSize();
};
}