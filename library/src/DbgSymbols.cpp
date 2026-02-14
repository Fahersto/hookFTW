#include "DbgSymbols.h"
#include <iostream>
#include <fstream>
#include <sstream>

#ifdef _WIN32
#include <Windows.h>
#include <dbghelp.h>
#include <tchar.h>
#elif __linux
#include <map>
#include <string>
#include <link.h>
#include <elf.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <cstring>
#endif

namespace hookftw
{
    bool DbgSymbols::symbolsLoaded_ = false;
    int64_t DbgSymbols::baseAddress_ = 0;

#ifdef __linux
    // Static map to hold symbols on Linux
    static std::map<std::string, uintptr_t> symbolCache_;

    // Get the path to the main executable
    static std::string get_executable_path()
    {
        char buff[4096];
        ssize_t len = readlink("/proc/self/exe", buff, sizeof(buff) - 1);
        if (len != -1)
        {
            buff[len] = '\0';
            return std::string(buff);
        }
        return "";
    }

    // Get base address using dl_iterate_phdr - this is the most reliable method
    static int dl_callback(struct dl_phdr_info *info, size_t size, void *data)
    {
        // The main executable has an empty name
        if (info->dlpi_name == nullptr || info->dlpi_name[0] == '\0')
        {
            *(uintptr_t *) data = info->dlpi_addr;
            return 1; // Stop iteration
        }
        return 0;
    }

    static uintptr_t get_main_executable_base()
    {
        uintptr_t base = 0;
        dl_iterate_phdr(dl_callback, &base);

        // Fallback: parse /proc/self/maps if dl_iterate_phdr returned 0
        // (can happen with some PIE configurations)
        if (base == 0)
        {
            std::string exePath = get_executable_path();
            if (exePath.empty()) return 0;

            std::ifstream maps("/proc/self/maps");
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
                        return std::stoull(base_str, nullptr, 16);
                    }
                }
            }
        }
        return base;
    }
#endif

    /**
     * \brief Loads debug symbols of the current process.
     *
     * @param path to search for the .pdb file. If no path is given the Windows default paths are used.
     */
    DbgSymbols::DbgSymbols(char *path)
    {
        if (!symbolsLoaded_)
        {
            LoadSymbols(path);
#ifdef _WIN32
            char executablePath[MAX_PATH];
            GetModuleFileNameA(NULL, executablePath, MAX_PATH);
            baseAddress_ = SymLoadModuleEx(GetCurrentProcess(), NULL, executablePath, NULL,
                                           (DWORD64) GetModuleHandle(nullptr), 0x7fffffffffffffff, NULL, 0);
#elif __linux
            baseAddress_ = get_main_executable_base();
#endif
            symbolsLoaded_ = true;
        }
    }

    /**
     * \brief Loads debug symbols of the current process.
     *
     * @return <code>true</code> or <code>false</code> depending on success of load operation
     */
    bool DbgSymbols::LoadSymbols(char *path)
    {
#ifdef _WIN32
        SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);

        if (!SymInitialize(GetCurrentProcess(), path, FALSE))
        {
            printf("SymInitialize returned error : %d\n", GetLastError());
            return false;
        }
        symbolsLoaded_ = true;
        return true;
#elif __linux
        // Clear any previous symbols
        symbolCache_.clear();

        // 1. Determine path to executable
        std::string exePath;
        if (path)
        {
            exePath = path;
        }
        else
        {
            exePath = get_executable_path();
            if (exePath.empty())
            {
                printf("DbgSymbols: Failed to determine executable path\n");
                return false;
            }
        }

        int fd = open(exePath.c_str(), O_RDONLY);
        if (fd < 0)
        {
            printf("DbgSymbols: Failed to open %s\n", exePath.c_str());
            return false;
        }

        struct stat st;
        if (fstat(fd, &st) < 0)
        {
            close(fd);
            printf("DbgSymbols: Failed to stat %s\n", exePath.c_str());
            return false;
        }

        // Sanity check file size
        if (st.st_size < (off_t) sizeof(Elf64_Ehdr))
        {
            close(fd);
            printf("DbgSymbols: File too small to be valid ELF\n");
            return false;
        }

        void *mem = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (mem == MAP_FAILED)
        {
            close(fd);
            printf("DbgSymbols: Failed to mmap %s\n", exePath.c_str());
            return false;
        }

        bool success = false;

        // Parse ELF header
        Elf64_Ehdr *ehdr = static_cast<Elf64_Ehdr *>(mem);

        // Validate ELF magic
        if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0)
        {
            printf("DbgSymbols: Not a valid ELF file\n");
            goto cleanup;
        }

        // Validate ELF class (64-bit)
        if (ehdr->e_ident[EI_CLASS] != ELFCLASS64)
        {
            printf("DbgSymbols: Only 64-bit ELF files are supported\n");
            goto cleanup;
        }

        // Validate section header offset and count
        if (ehdr->e_shoff == 0 || ehdr->e_shnum == 0)
        {
            printf("DbgSymbols: No section headers found\n");
            goto cleanup;
        }

        // Bounds check: ensure section header table is within file
        if (ehdr->e_shoff + (ehdr->e_shnum * sizeof(Elf64_Shdr)) > (size_t) st.st_size)
        {
            printf("DbgSymbols: Section header table extends beyond file\n");
            goto cleanup;
        }

        {
            Elf64_Shdr *shdr = reinterpret_cast<Elf64_Shdr *>(static_cast<char *>(mem) + ehdr->e_shoff);

            // Find symtab and strtab
            Elf64_Shdr *symtab = nullptr;
            Elf64_Shdr *strtab = nullptr;

            // Scan for symbol table - prefer SHT_SYMTAB over SHT_DYNSYM
            for (uint16_t i = 0; i < ehdr->e_shnum; i++)
            {
                if (shdr[i].sh_type == SHT_SYMTAB)
                {
                    symtab = &shdr[i];
                    // Validate sh_link
                    if (shdr[i].sh_link < ehdr->e_shnum)
                    {
                        strtab = &shdr[shdr[i].sh_link];
                    }
                    break;
                }
                // Fallback to SHT_DYNSYM if no SHT_SYMTAB found
                if (shdr[i].sh_type == SHT_DYNSYM && symtab == nullptr)
                {
                    symtab = &shdr[i];
                    if (shdr[i].sh_link < ehdr->e_shnum)
                    {
                        strtab = &shdr[shdr[i].sh_link];
                    }
                }
            }

            if (symtab == nullptr || strtab == nullptr)
            {
                printf("DbgSymbols: No symbol table found (binary may be stripped)\n");
                goto cleanup;
            }

            // Bounds check: ensure symbol table is within file
            if (symtab->sh_offset + symtab->sh_size > (size_t) st.st_size)
            {
                printf("DbgSymbols: Symbol table extends beyond file\n");
                goto cleanup;
            }

            // Bounds check: ensure string table is within file
            if (strtab->sh_offset + strtab->sh_size > (size_t) st.st_size)
            {
                printf("DbgSymbols: String table extends beyond file\n");
                goto cleanup;
            }

            Elf64_Sym *symbols = reinterpret_cast<Elf64_Sym *>(static_cast<char *>(mem) + symtab->sh_offset);
            const char *strings = static_cast<char *>(mem) + strtab->sh_offset;
            size_t strTabSize = strtab->sh_size;
            size_t count = symtab->sh_size / sizeof(Elf64_Sym);

            for (size_t i = 0; i < count; i++)
            {
                // Validate string index is within string table
                if (symbols[i].st_name >= strTabSize)
                {
                    continue;
                }

                if (symbols[i].st_name != 0 && symbols[i].st_value != 0)
                {
                    const char *name = strings + symbols[i].st_name;
                    // Verify null termination within bounds
                    bool validString = false;
                    for (size_t j = symbols[i].st_name; j < strTabSize; j++)
                    {
                        if (strings[j] == '\0')
                        {
                            validString = true;
                            break;
                        }
                    }
                    if (!validString) continue;

                    // Check if function or object
                    unsigned char symType = ELF64_ST_TYPE(symbols[i].st_info);
                    if (symType == STT_FUNC || symType == STT_OBJECT)
                    {
                        symbolCache_[name] = symbols[i].st_value;
                    }
                }
            }

            success = true;
            printf("DbgSymbols: Loaded %zu symbols from %s\n", symbolCache_.size(), exePath.c_str());
        }

    cleanup:
        munmap(mem, st.st_size);
        close(fd);

        if (success)
        {
            symbolsLoaded_ = true;
        }
        return success;
#endif
    }

    /**
     * \brief Resolves the address of a symbol by its name.
     *
     * @return address of the symbols or nullptr if the symbol name could not be found.
     */
    int8_t *DbgSymbols::GetAddressBySymbolName(const char *name)
    {
        if (!symbolsLoaded_)
        {
            printf("Symbols are not loaded\n");
            return nullptr;
        }

#ifdef _WIN32
        // based on https://docs.microsoft.com/en-us/windows/win32/debug/using-dbghelp
        TCHAR szSymbolName[MAX_SYM_NAME];
        ULONG64 buffer[(sizeof(SYMBOL_INFO) +
                        MAX_SYM_NAME * sizeof(TCHAR) +
                        sizeof(ULONG64) - 1) /
                       sizeof(ULONG64)];
        PSYMBOL_INFO pSymbol = (PSYMBOL_INFO) buffer;

        _tcscpy_s(szSymbolName, MAX_SYM_NAME, TEXT(name));
        pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        pSymbol->MaxNameLen = MAX_SYM_NAME;
        pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        pSymbol->MaxNameLen = MAX_SYM_NAME;

        if (SymFromName(GetCurrentProcess(), name, pSymbol))
        {
            int8_t *base = (int8_t *) baseAddress_;
            int8_t *symbolAddress = (int8_t *) pSymbol->Address;
            int8_t *symbolBase = (int8_t *) pSymbol->ModBase;

            return symbolAddress - symbolBase + base;
        }

        printf("SymFromName returned error : %d\n", GetLastError());
        return nullptr;
#elif __linux
        auto it = symbolCache_.find(name);
        if (it != symbolCache_.end())
        {
            return (int8_t *) (it->second + baseAddress_);
        }
        return nullptr;
#endif
    }

#ifdef _WIN32
    BOOL CALLBACK EnumSymProc(PSYMBOL_INFO pSymInfo, ULONG SymbolSize, PVOID UserContext)
    {
        UNREFERENCED_PARAMETER(UserContext);
        char buffer[5000];
        sprintf(buffer, "%llx %4u %s\n", pSymInfo->Address, SymbolSize, pSymInfo->Name);
        printf(buffer);
        return TRUE;
    }
#endif

    /**
     * \brief Enumerates all symbols in the binary and writes them to a log file.
     */
    void DbgSymbols::EnumerateSymbols()
    {
        if (!symbolsLoaded_)
        {
            return;
        }

#ifdef _WIN32
        const char *allInImageName = "*";
        const char *allInEveryModule = "*!*";

        char executablePath[MAX_PATH];
        GetModuleFileNameA(NULL, executablePath, MAX_PATH);
        auto base_addr = (size_t) SymLoadModuleEx(GetCurrentProcess(), NULL, executablePath, NULL, NULL,
                                                  0x7fffffffffffffff, NULL, 0);
        SymEnumSymbols(GetCurrentProcess(), base_addr, allInEveryModule, EnumSymProc, NULL);
#elif __linux
        for (auto const &[name, addr]: symbolCache_)
        {
            printf("%lx %s\n", addr + baseAddress_, name.c_str());
        }
#endif
    }
}
