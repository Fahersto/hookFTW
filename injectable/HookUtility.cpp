#include "HookUtility.h"
#include "MidfunctionHook.h"
#include <cstdarg>
#include <map>
#include <cstring>
#include <cctype>
#include <fstream>

#ifdef _WIN32
#include <Windows.h>
#include <Psapi.h>
#include <winternl.h>
#elif __linux
#include <sys/time.h>
#include <unistd.h>
#endif

namespace HookUtil
{
    static const char* g_logFile = "./hook.log";
    static std::map<std::string, uint64_t> g_timers;
    static std::map<const void*, uint64_t> g_hitCounts;

    void SetLogFile(const char* path)
        {
        g_logFile = path;
    }

    void Log(const char* format, ...)
    {
        FILE* f = fopen(g_logFile, "a");
        if (!f) return;

        // Get timestamp
    #ifdef _WIN32
        SYSTEMTIME st;
        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        FileTimeToSystemTime(&ft, &st);

        // Convert FILETIME to microseconds
        ULARGE_INTEGER uli;
        uli.LowPart = ft.dwLowDateTime;
        uli.HighPart = ft.dwHighDateTime;
        uint64_t microseconds = (uli.QuadPart / 10) % 1000000;

        fprintf(f, "[%04d-%02d-%02d %02d:%02d:%02d.%06llu] ",
                st.wYear, st.wMonth, st.wDay,
                st.wHour, st.wMinute, st.wSecond, microseconds);
    #elif __linux
        struct timeval tv;
        gettimeofday(&tv, nullptr);
        time_t nowtime = tv.tv_sec;
        struct tm* nowtm = localtime(&nowtime);
        char tmbuf[64];
        strftime(tmbuf, sizeof(tmbuf), "%Y-%m-%d %H:%M:%S", nowtm);

        // Write timestamp with microseconds
        fprintf(f, "[%s.%06ld] ", tmbuf, tv.tv_usec);
    #endif

        // Write message
        va_list args;
        va_start(args, format);
        vfprintf(f, format, args);
        va_end(args);

        fprintf(f, "\n");
        fclose(f);
    }

    void LogRaw(const char* format, ...)
    {
        FILE* f = fopen(g_logFile, "a");
        if (!f) return;

        va_list args;
        va_start(args, format);
        vfprintf(f, format, args);
        va_end(args);

        fclose(f);
    }

    void LogRegisters(hookftw::context* ctx)
    {
        if (!ctx)
        {
            return;
        }
        Log("Registers:");
        LogRaw("  RAX: 0x%016lx  RBX: 0x%016lx\n", ctx->rax, ctx->rbx);
        LogRaw("  RCX: 0x%016lx  RDX: 0x%016lx\n", ctx->rcx, ctx->rdx);
        LogRaw("  RSI: 0x%016lx  RDI: 0x%016lx\n", ctx->rsi, ctx->rdi);
        LogRaw("  RBP: 0x%016lx  RSP: 0x%016lx\n", ctx->rbp, ctx->rsp);
        LogRaw("  R8 : 0x%016lx  R9 : 0x%016lx\n", ctx->r8, ctx->r9);
        LogRaw("  R10: 0x%016lx  R11: 0x%016lx\n", ctx->r10, ctx->r11);
        LogRaw("  R12: 0x%016lx  R13: 0x%016lx\n", ctx->r12, ctx->r13);
        LogRaw("  R14: 0x%016lx  R15: 0x%016lx\n", ctx->r14, ctx->r15);
    }

    void ClearLog()
    {
        FILE* f = fopen(g_logFile, "w");
        if (f) fclose(f);
    }

    void LogSeparator()
    {
        LogRaw("================================================================================\n");
    }

    void LogFunctionEntry(const char* functionName)
    {
        Log(">>> ENTERING: %s", functionName);
    }

    void LogFunctionExit(const char* functionName)
    {
        Log("<<< EXITING: %s", functionName);
    }

    bool IsMemoryReadable(const void* address, size_t size)
    {
        if (!address)
        {
            return false;
        }

    #ifdef _WIN32
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(address, &mbi, sizeof(mbi)) == 0) {
            return false;
        }

        // Check if memory is committed
        if (mbi.State != MEM_COMMIT) {
            return false;
        }

        // Check if memory is readable (not PAGE_NOACCESS and not PAGE_EXECUTE)
        DWORD readableProtections = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                                     PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
        if ((mbi.Protect & readableProtections) == 0) {
            return false;
        }

        // Check if the entire range is within the region
        uint64_t regionEnd = (uint64_t)mbi.BaseAddress + mbi.RegionSize;
        uint64_t requestEnd = (uint64_t)address + size;
        return requestEnd <= regionEnd;
    #elif __linux
        // Try to read /proc/self/maps to check if address is mapped
        std::ifstream maps("/proc/self/maps");
        std::string line;
        uint64_t addr = (uint64_t)address;

        while (std::getline(maps, line)) {
            uint64_t start, end;
            if (sscanf(line.c_str(), "%lx-%lx", &start, &end) == 2) {
                if (addr >= start && addr + size <= end) {
                    // Check if readable (contains 'r')
                    size_t perm_pos = line.find(' ');
                    if (perm_pos != std::string::npos) {
                        perm_pos++;
                        if (perm_pos < line.length() && line[perm_pos] == 'r') {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    #endif
    }

    bool SafeRead(const void* address, void* buffer, size_t size)
    {
        if (!IsMemoryReadable(address, size)) return false;
        memcpy(buffer, address, size);
        return true;
    }

    bool SafeReadString(const void* address, char* buffer, size_t maxLength)
    {
        if (!address || !buffer || maxLength == 0) return false;

        const char* src = (const char*)address;
        size_t i = 0;

        while (i < maxLength - 1)
        {
            if (!IsMemoryReadable(src + i, 1))
            {
                buffer[i] = '\0';
                return i > 0;
            }
            buffer[i] = src[i];
            if (buffer[i] == '\0') return true;
            i++;
        }
        buffer[maxLength - 1] = '\0';
        return true;
    }

    void DumpMemory(const void* address, size_t size, const char* label)
    {
        if (label)
        {
            Log("Memory dump: %s @ %p (%zu bytes)", label, address, size);
        } else
        {
            Log("Memory dump @ %p (%zu bytes)", address, size);
        }

        if (!IsMemoryReadable(address, size))
        {
            LogRaw("  [Memory not readable]\n");
            return;
        }

        const uint8_t* bytes = (const uint8_t*)address;
        for (size_t i = 0; i < size; i += 16)
        {
            LogRaw("  %p: ", (const void*)((uint64_t)address + i));

            // Hex bytes
            for (size_t j = 0; j < 16 && i + j < size; j++)
            {
                LogRaw("%02x ", bytes[i + j]);
            }
            LogRaw("\n");
        }
    }

    void DumpMemoryWithASCII(const void* address, size_t size, const char* label)
    {
        if (label)
        {
            Log("Memory dump (hex+ASCII): %s @ %p (%zu bytes)", label, address, size);
        } else
        {
            Log("Memory dump (hex+ASCII) @ %p (%zu bytes)", address, size);
        }

        if (!IsMemoryReadable(address, size))
        {
            LogRaw("  [Memory not readable]\n");
            return;
        }

        const uint8_t* bytes = (const uint8_t*)address;
        for (size_t i = 0; i < size; i += 16)
        {
            LogRaw("  %016lx: ", (uint64_t)address + i);

            // Hex bytes
            for (size_t j = 0; j < 16; j++)
            {
                if (i + j < size)
                {
                    LogRaw("%02x ", bytes[i + j]);
                }
                else
                {
                    LogRaw("   ");
                }
            }

            LogRaw(" |");

            for (size_t j = 0; j < 16 && i + j < size; j++)
            {
                uint8_t c = bytes[i + j];
                LogRaw("%c", (c >= 32 && c < 127) ? c : '.');
            }

            LogRaw("|\n");
        }
    }

    void BytesToHex(const void* data, size_t size, char* output, size_t outputSize)
    {
        const uint8_t* bytes = (const uint8_t*)data;
        size_t written = 0;

        for (size_t i = 0; i < size && written < outputSize - 3; i++)
        {
            written += snprintf(output + written, outputSize - written, "%02X ", bytes[i]);
        }

        if (written > 0 && output[written - 1] == ' ')
        {
            output[written - 1] = '\0';
        }
    }

    void FormatPointer(const void* ptr, char* output, size_t outputSize)
    {
        snprintf(output, outputSize, "0x%016lx", (uint64_t)ptr);
    }

    void LogHex(const void* data, size_t size, const char* label)
    {
        char hex[256];
        BytesToHex(data, size > 80 ? 80 : size, hex, sizeof(hex));

        if (label)
        {
            Log("%s: %s%s", label, hex, size > 80 ? "..." : "");
        }
        else
        {
            Log("Hex: %s%s", hex, size > 80 ? "..." : "");
        }
    }

    void IntToStr(int64_t value, char* buffer, size_t bufferSize, int base)
    {
        if (base == 16)
        {
            snprintf(buffer, bufferSize, "0x%lx", value);
        }
        else if (base == 10)
        {
            snprintf(buffer, bufferSize, "%ld", value);
        }
        else if (base == 8)
        {
            snprintf(buffer, bufferSize, "0%lo", value);
        }
        else
        {
            snprintf(buffer, bufferSize, "%ld", value);
        }
    }

    uint64_t GetRegisterByName(hookftw::context* ctx, const char* regName)
    {
        if (!ctx || !regName) return 0;

        // Convert to lowercase for comparison
        char name[8] = {0};
        for (int i = 0; i < 7 && regName[i]; i++)
        {
            name[i] = tolower(regName[i]);
        }

        if (strcmp(name, "rax") == 0) return ctx->rax;
        if (strcmp(name, "rbx") == 0) return ctx->rbx;
        if (strcmp(name, "rcx") == 0) return ctx->rcx;
        if (strcmp(name, "rdx") == 0) return ctx->rdx;
        if (strcmp(name, "rsi") == 0) return ctx->rsi;
        if (strcmp(name, "rdi") == 0) return ctx->rdi;
        if (strcmp(name, "rbp") == 0) return ctx->rbp;
        if (strcmp(name, "rsp") == 0) return ctx->rsp;
        if (strcmp(name, "r8") == 0) return ctx->r8;
        if (strcmp(name, "r9") == 0) return ctx->r9;
        if (strcmp(name, "r10") == 0) return ctx->r10;
        if (strcmp(name, "r11") == 0) return ctx->r11;
        if (strcmp(name, "r12") == 0) return ctx->r12;
        if (strcmp(name, "r13") == 0) return ctx->r13;
        if (strcmp(name, "r14") == 0) return ctx->r14;
        if (strcmp(name, "r15") == 0) return ctx->r15;

        return 0;
    }

    bool SetRegisterByName(hookftw::context* ctx, const char* regName, uint64_t value)
    {
        if (!ctx || !regName) return false;

        char name[8] = {0};
        for (int i = 0; i < 7 && regName[i]; i++)
        {
            name[i] = tolower(regName[i]);
        }

        if (strcmp(name, "rax") == 0) { ctx->rax = value; return true; }
        if (strcmp(name, "rbx") == 0) { ctx->rbx = value; return true; }
        if (strcmp(name, "rcx") == 0) { ctx->rcx = value; return true; }
        if (strcmp(name, "rdx") == 0) { ctx->rdx = value; return true; }
        if (strcmp(name, "rsi") == 0) { ctx->rsi = value; return true; }
        if (strcmp(name, "rdi") == 0) { ctx->rdi = value; return true; }
        if (strcmp(name, "rbp") == 0) { ctx->rbp = value; return true; }
        if (strcmp(name, "rsp") == 0) { ctx->rsp = value; return true; }
        if (strcmp(name, "r8") == 0) { ctx->r8 = value; return true; }
        if (strcmp(name, "r9") == 0) { ctx->r9 = value; return true; }
        if (strcmp(name, "r10") == 0) { ctx->r10 = value; return true; }
        if (strcmp(name, "r11") == 0) { ctx->r11 = value; return true; }
        if (strcmp(name, "r12") == 0) { ctx->r12 = value; return true; }
        if (strcmp(name, "r13") == 0) { ctx->r13 = value; return true; }
        if (strcmp(name, "r14") == 0) { ctx->r14 = value; return true; }
        if (strcmp(name, "r15") == 0) { ctx->r15 = value; return true; }

        return false;
    }

    void LogAllRegisters(hookftw::context* ctx)
    {
        LogRegisters(ctx);
    }

    bool IsRegisterValidPointer(hookftw::context* ctx, const char* regName)
    {
        uint64_t value = GetRegisterByName(ctx, regName);
        return IsMemoryReadable((void*)value, 1);
    }

    void DumpStack(hookftw::context* ctx, int numQwords)
    {
        if (!ctx) return;

        Log("Stack dump from RSP (0x%lx):", ctx->rsp);

        uint64_t* stack = (uint64_t*)ctx->rsp;
        for (int i = 0; i < numQwords; i++)
        {
            if (!IsMemoryReadable(stack + i, 8))
            {
                LogRaw("  [RSP+0x%02x] <invalid>\n", i * 8);
                break;
            }
            LogRaw("  [RSP+0x%02x] 0x%016lx\n", i * 8, stack[i]);
        }
    }

    uint64_t GetStackValue(hookftw::context* ctx, int offset)
    {
        if (!ctx) return 0;

        uint64_t* addr = (uint64_t*)(ctx->rsp + offset);
        if (!IsMemoryReadable(addr, 8)) return 0;

        return *addr;
    }

    uint64_t GetReturnAddress(hookftw::context* ctx)
    {
        return GetStackValue(ctx, 0);
    }

    void TimerStart(const char* name)
    {
        g_timers[name] = GetTimestampUs();
    }

    void TimerStop(const char* name)
    {
        auto it = g_timers.find(name);
        if (it == g_timers.end())
        {
            Log("Timer '%s' was not started", name);
            return;
        }

        uint64_t elapsed = GetTimestampUs() - it->second;
        Log("Timer '%s': %lu µs (%.3f ms)", name, elapsed, elapsed / 1000.0);
        g_timers.erase(it);
    }

    uint64_t GetTimestampUs()
    {
    #ifdef _WIN32
        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        ULARGE_INTEGER uli;
        uli.LowPart = ft.dwLowDateTime;
        uli.HighPart = ft.dwHighDateTime;
        // FILETIME is in 100-nanosecond intervals since 1601-01-01
        // Convert to microseconds
        return uli.QuadPart / 10;
    #elif __linux
        struct timeval tv;
        gettimeofday(&tv, nullptr);
        return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
    #endif
    }

    void GetTimestampString(char* buffer, size_t bufferSize)
    {
    #ifdef _WIN32
        SYSTEMTIME st;
        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        FileTimeToSystemTime(&ft, &st);

        ULARGE_INTEGER uli;
        uli.LowPart = ft.dwLowDateTime;
        uli.HighPart = ft.dwHighDateTime;
        uint64_t microseconds = (uli.QuadPart / 10) % 1000000;

        snprintf(buffer, bufferSize, "%04d-%02d-%02d %02d:%02d:%02d.%06llu",
                 st.wYear, st.wMonth, st.wDay,
                 st.wHour, st.wMinute, st.wSecond, microseconds);
    #elif __linux
        struct timeval tv;
        gettimeofday(&tv, nullptr);
        time_t nowtime = tv.tv_sec;
        struct tm* nowtm = localtime(&nowtime);
        char tmbuf[64];
        strftime(tmbuf, sizeof(tmbuf), "%Y-%m-%d %H:%M:%S", nowtm);
        snprintf(buffer, bufferSize, "%s.%06ld", tmbuf, tv.tv_usec);
    #endif
    }

    // ============================================================================
    // ANALYSIS HELPERS
    // ============================================================================

    void LogFunctionArgs(hookftw::context* ctx, int count)
    {
        if (!ctx) return;

    #ifdef _WIN32
        Log("Function arguments (x64 Windows ABI):");

        // First 4 arguments are in registers: RCX, RDX, R8, R9
        const char* regNames[] = {"RCX", "RDX", "R8", "R9"};
        uint64_t regValues[] = {
            static_cast<uint64_t>(ctx->rcx),
            static_cast<uint64_t>(ctx->rdx),
            static_cast<uint64_t>(ctx->r8),
            static_cast<uint64_t>(ctx->r9)
        };

        for (int i = 0; i < count && i < 4; i++) {
            LogRaw("  arg[%d] (%s): 0x%016llx", i, regNames[i], regValues[i]);
            if (IsMemoryReadable((void*)regValues[i], 8)) {
                LogRaw(" -> 0x%016llx", *(uint64_t*)regValues[i]);
            }
            LogRaw("\n");
        }

        // Remaining arguments are on stack (at RSP + 0x20 for shadow space + previous args)
        for (int i = 4; i < count; i++) {
            uint64_t value = GetStackValue(ctx, 0x20 + (i - 4) * 8);
            LogRaw("  arg[%d] (stack): 0x%016llx\n", i, value);
        }
    #elif __linux
        Log("Function arguments (x64 SysV ABI):");

        // First 6 arguments are in registers
        const char* regNames[] = {"RDI", "RSI", "RDX", "RCX", "R8", "R9"};
        uint64_t regValues[] = {
            static_cast<uint64_t>(ctx->rdi),
            static_cast<uint64_t>(ctx->rsi),
            static_cast<uint64_t>(ctx->rdx),
            static_cast<uint64_t>(ctx->rcx),
            static_cast<uint64_t>(ctx->r8),
            static_cast<uint64_t>(ctx->r9)
        };

        for (int i = 0; i < count && i < 6; i++)
        {
            LogRaw("  arg[%d] (%s): 0x%016lx", i, regNames[i], regValues[i]);
            if (IsMemoryReadable((void*)regValues[i], 8))
            {
                LogRaw(" -> 0x%016lx", *(uint64_t*)regValues[i]);
            }
            LogRaw("\n");
        }

        // Remaining arguments are on stack
        for (int i = 6; i < count; i++)
        {
            uint64_t value = GetStackValue(ctx, (i - 6) * 8);
            LogRaw("  arg[%d] (stack): 0x%016lx\n", i, value);
        }
    #endif
    }

    void LogPointerContent(const void* ptr, const char* label)
    {
        if (!ptr)
        {
            Log("%s: NULL", label ? label : "Pointer");
            return;
        }

        if (!IsMemoryReadable(ptr, 8))
        {
            Log("%s: %p (not readable)", label ? label : "Pointer", ptr);
            return;
        }

        uint64_t value = *(uint64_t*)ptr;
        Log("%s: %p -> 0x%016lx", label ? label : "Pointer", ptr, value);
    }

    bool LooksLikeCodePointer(uint64_t value)
    {
        // Code is typically in lower memory on Linux
        // This is a heuristic - not perfect
        if (value < 0x400000 || value > 0x7fffffffffff) return false;

        return IsMemoryReadable((void*)value, 1);
    }

    bool LooksLikeHeapPointer(uint64_t value)
    {
        // Heap is typically in mid-range addresses
        if (value < 0x1000000 || value > 0x7fffffffffff) return false;

    #ifdef _WIN32
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery((void*)value, &mbi, sizeof(mbi)) == 0) {
            return false;
        }

        // Check if it's private memory (heap is typically MEM_PRIVATE)
        return mbi.Type == MEM_PRIVATE && mbi.State == MEM_COMMIT;
    #elif __linux
        std::ifstream maps("/proc/self/maps");
        std::string line;

        while (std::getline(maps, line))
        {
            if (line.find("[heap]") != std::string::npos)
            {
                uint64_t start, end;
                if (sscanf(line.c_str(), "%lx-%lx", &start, &end) == 2)
                {
                    if (value >= start && value < end) return true;
                }
            }
        }

        return false;
    #endif
    }

    bool LooksLikeStackPointer(uint64_t value)
    {
    #ifdef _WIN32
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery((void*)value, &mbi, sizeof(mbi)) == 0) {
            return false;
        }

        // Get stack base and limit using NT_TIB (Thread Information Block)
        NT_TIB* tib = (NT_TIB*)NtCurrentTeb();
        if (!tib) return false;

        uint64_t stackBase = (uint64_t)tib->StackBase;
        uint64_t stackLimit = (uint64_t)tib->StackLimit;

        return value >= stackLimit && value < stackBase;
    #elif __linux
        std::ifstream maps("/proc/self/maps");
        std::string line;

        while (std::getline(maps, line))
        {
            if (line.find("[stack]") != std::string::npos)
            {
                uint64_t start, end;
                if (sscanf(line.c_str(), "%lx-%lx", &start, &end) == 2)
                {
                    if (value >= start && value < end) return true;
                }
            }
        }
        return false;
    #endif
    }

    void AnalyzePointer(uint64_t value, const char* label)
    {
        if (label)
        {
            Log("Analyzing pointer: %s = 0x%016lx", label, value);
        }
        else
        {
            Log("Analyzing pointer: 0x%016lx", value);
        }

        if (value == 0)
        {
            LogRaw("  Type: NULL\n");
            return;
        }

        if (LooksLikeStackPointer(value))
        {
            LogRaw("  Type: Stack pointer\n");
        }
        else if (LooksLikeHeapPointer(value))
        {
            LogRaw("  Type: Heap pointer\n");
        }
        else if (LooksLikeCodePointer(value))
        {
            LogRaw("  Type: Code pointer\n");
        }
        else
        {
            LogRaw("  Type: Unknown / Invalid\n");
        }

        if (IsMemoryReadable((void*)value, 8))
        {
            LogRaw("  Readable: Yes\n");
            uint64_t deref = *(uint64_t*)value;
            LogRaw("  Value: 0x%016lx\n", deref);
        }
        else
        {
            LogRaw("  Readable: No\n");
        }
    }

    void QuickLog(hookftw::context* ctx, const char* message)
    {
        if (message)
        {
            Log("Hook hit: %s", message);
        } else
        {
            Log("Hook hit");
        }

        if (ctx)
        {
            LogRaw("  RIP: ~hook address\n");
            LogRaw("  RSP: 0x%016lx\n", ctx->rsp);
            LogRaw("  RDI: 0x%016lx  RSI: 0x%016lx\n", ctx->rdi, ctx->rsi);
        }
    }

    void FullContextDump(hookftw::context* ctx, const char* label)
    {
        if (label)
        {
            Log("============ FULL CONTEXT DUMP: %s ============", label);
        } else
        {
            Log("============ FULL CONTEXT DUMP ============");
        }
        LogAllRegisters(ctx);
        DumpStack(ctx, 16);
        LogFunctionArgs(ctx, 6);
        LogRaw("================================================================================\n");
    }

    uint64_t IncrementHitCount(const void* hookAddress)
    {
        return ++g_hitCounts[hookAddress];
    }

    uint64_t GetHitCount(const void* hookAddress)
    {
        auto it = g_hitCounts.find(hookAddress);
        return (it != g_hitCounts.end()) ? it->second : 0;
    }
}
