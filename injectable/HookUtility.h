#pragma once

#include <cstdio>
#include <cstdint>
#include <string>

#ifdef _WIN32
#include <Windows.h>
#elif __linux
#include <sys/time.h>
#include <unistd.h>
#endif

namespace hookftw {
    struct context;
}

/**
 * @brief HookUtility - A comprehensive utility class for hook development
 *
 * This class provides professional-grade utilities for common hook operations:
 * - Logging to files with timestamps
 * - Memory dumping and inspection
 * - String manipulation and formatting
 * - Data type conversions
 * - Performance measurement
 * - Pointer analysis
 *
 * All methods are static and thread-safe where applicable.
 * Supports both Windows and Linux platforms.
 * Default log file: ./hook.log
 */
namespace HookUtil
{
    /**
     * @brief Set custom log file path (default: /tmp/hook.log)
     */
    void SetLogFile(const char* path);

    /**
     * @brief Log a message with timestamp to the log file
     * @param format Printf-style format string
     */
    void Log(const char* format, ...);

    /**
     * @brief Log a message without timestamp
     */
    void LogRaw(const char* format, ...);

    /**
     * @brief Clear the log file
     */
    void ClearLog();

    /**
     * @brief Log separator line for readability
     */
    void LogSeparator();

    /**
     * @brief Log function entry with timestamp
     */
    void LogFunctionEntry(const char* functionName);

    /**
     * @brief Log function exit with timestamp
     */
    void LogFunctionExit(const char* functionName);

    /**
     * @brief Dump memory region to log in hexdump format
     * @param address Starting address
     * @param size Number of bytes to dump
     * @param label Optional label for the dump
     */
    void DumpMemory(const void* address, size_t size, const char* label = nullptr);

    /**
     * @brief Dump memory with ASCII representation (like hexdump -C)
     */
    void DumpMemoryWithASCII(const void* address, size_t size, const char* label = nullptr);

    /**
     * @brief Check if memory address is readable
     */
    bool IsMemoryReadable(const void* address, size_t size = 1);

    /**
     * @brief Safe memory read - returns false if address is invalid
     */
    bool SafeRead(const void* address, void* buffer, size_t size);

    /**
     * @brief Read null-terminated string safely
     */
    bool SafeReadString(const void* address, char* buffer, size_t maxLength);

    /**
     * @brief Format bytes as hex string (e.g., "48 8B 05 AB CD EF")
     */
    void BytesToHex(const void* data, size_t size, char* output, size_t outputSize);

    /**
     * @brief Format pointer as hex string with 0x prefix
     */
    void FormatPointer(const void* ptr, char* output, size_t outputSize);

    /**
     * @brief Log a formatted hex dump of data
     */
    void LogHex(const void* data, size_t size, const char* label = nullptr);

    /**
     * @brief Convert integer to string (helper for contexts without std::to_string)
     */
    void IntToStr(int64_t value, char* buffer, size_t bufferSize, int base = 10);

    /**
     * @brief Dump the stack from RSP
     * @param ctx Hook context
     * @param numQwords Number of 8-byte values to dump
     */
    void DumpStack(hookftw::context* ctx, int numQwords = 16);

    /**
     * @brief Get value from stack at offset from RSP
     * @param offset Offset in bytes from RSP
     */
    uint64_t GetStackValue(hookftw::context* ctx, int offset);

    /**
     * @brief Get return address from stack (assumes standard calling convention)
     */
    uint64_t GetReturnAddress(hookftw::context* ctx);

    /**
     * @brief Start a named timer
     */
    void TimerStart(const char* name);

    /**
     * @brief Stop a named timer and log elapsed time
     */
    void TimerStop(const char* name);

    /**
     * @brief Get current timestamp in microseconds
     */
    uint64_t GetTimestampUs();

    /**
     * @brief Get formatted timestamp string
     */
    void GetTimestampString(char* buffer, size_t bufferSize);

    /**
     * @brief Log function arguments (handles platform-specific calling conventions)
     * @param ctx Hook context
     * @param count Number of arguments to log
     *
     * Windows x64: Uses RCX, RDX, R8, R9, then stack at RSP+0x20
     * Linux x64 (SysV): Uses RDI, RSI, RDX, RCX, R8, R9, then stack
     */
    void LogFunctionArgs(hookftw::context* ctx, int count);

    /**
     * @brief Attempt to dereference and log what pointer points to
     */
    void LogPointerContent(const void* ptr, const char* label = nullptr);

    /**
     * @brief Check if value looks like a valid code pointer
     */
    bool LooksLikeCodePointer(uint64_t value);

    /**
     * @brief Check if value looks like a valid heap pointer
     */
    bool LooksLikeHeapPointer(uint64_t value);

    /**
     * @brief Check if value looks like a valid stack pointer
     */
    bool LooksLikeStackPointer(uint64_t value);

    /**
     * @brief Analyze and log pointer type
     */
    void AnalyzePointer(uint64_t value, const char* label = nullptr);

    /**
     * @brief Quick log with hook entry information
     */
    void QuickLog(hookftw::context* ctx, const char* message = nullptr);

    /**
     * @brief Full context dump - logs everything useful
     */
    void FullContextDump(hookftw::context* ctx, const char* label = nullptr);

    /**
     * @brief Count how many times hook was hit (per-address tracking)
     */
    uint64_t IncrementHitCount(const void* hookAddress);

    /**
     * @brief Get hit count for specific hook address
     */
    uint64_t GetHitCount(const void* hookAddress);
}
