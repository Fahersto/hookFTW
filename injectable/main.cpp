#include <cstdio>
#include <string>

#ifdef _WIN32
#include <Windows.h>
#elif __linux
#include <fstream>
#include <sstream>
#endif

#include "DbgSymbols.h"
#include "MidfunctionHook.h"
#include "HookUtility.h"


// these seem to be initialized in time
bool compileFlag_skipOriginalFunction = false;
uintptr_t compileFlag_hookAddressOffset = 0;


// Get the base address of the main executable (handles ASLR)
int8_t* get_main_executable_base() {
#ifdef _WIN32
    // On Windows, get the base address of the main executable
    return (int8_t*)GetModuleHandle(NULL);
#elif __linux
    std::ifstream maps("/proc/self/maps");
    std::string line;
    while (std::getline(maps, line)) {
        if (line.find("r-xp") != std::string::npos) {
            // Look for the main executable (first executable mapping)
            std::istringstream iss(line);
            std::string addr_range;
            iss >> addr_range;
            size_t dash = addr_range.find('-');
            if (dash != std::string::npos) {
                std::string base_str = addr_range.substr(0, dash);
                return (int8_t*)std::stoull(base_str, nullptr, 16);
            }
        }
    }
    return 0;
#endif
}

// The big issue here is that this function is called before variables ("at the top of the file") are initialized (LD_PRELOAD)
void Hook() {
    // WARNING: Moving this anywhere else will crash. We need MidfunctionHook to be valid because it contains context for the trampoline.
    // Moving it outside of this function will cause it to crash too. No idea why. Maybe some static initialization order fiasco?
    static hookftw::MidfunctionHook midfunctionHook;

    // this needs to be a string and life here to to be initialized in time. No idea why.
    // const char is initialized later it seems
    std::string compileFlag_functionName = "";

    int8_t* baseAddress = get_main_executable_base();

    hookftw::DbgSymbols dbgSymbols;
    dbgSymbols.EnumerateSymbols();

    int8_t* hookAddress = nullptr;

    // If function name is provided, resolve it using DbgSymbols
    if (!compileFlag_functionName.empty()) {
        hookAddress = dbgSymbols.GetAddressBySymbolName(compileFlag_functionName.c_str());
        if (!hookAddress) {
            printf("Failed to resolve function name: %s\n", compileFlag_functionName.c_str());
            return;
        }
        printf("Resolved function '%s' to address: %p\n", compileFlag_functionName.c_str(), hookAddress);
    }

    // Otherwise, if hook address offset is provided, calculate final address with ASLR
    else if (compileFlag_hookAddressOffset != 0) {
        hookAddress = (int8_t*)(baseAddress + compileFlag_hookAddressOffset);
        printf("Calculated hook address: base %p + offset 0x%lx = %p\n",
               (void*)baseAddress, compileFlag_hookAddressOffset, hookAddress);
    }
    else {
        printf("No function name or hook address offset specified\n");
        return;
    }

    midfunctionHook.Hook(
        hookAddress,
        [](hookftw::context* ctx) {
            // __CUSTOM_CODE_PLACEHOLDER__
            if (compileFlag_skipOriginalFunction) {
                ctx->SkipOriginalFunction();
            }
        }
    );
}

#ifdef _WIN32
// Windows DLL entry point
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            Hook();
            break;
        case DLL_PROCESS_DETACH:
            // Unhooking is an issue
            break;
    }
    return TRUE;
}
#elif __linux
// Linux constructor/destructor attributes
extern "C" void __attribute__((constructor)) library_init() {
    Hook();
}

extern "C" void __attribute__((destructor)) library_fini() {
    // Unhooking is an issue
}
#endif
