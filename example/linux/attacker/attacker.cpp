#include "MidfunctionHook.h"
#include "DbgSymbols.h"
#include <cstdio>
#include <cstring>
#include <atomic>
#include <dlfcn.h>

extern "C" void __attribute__((constructor)) library_init() {
    printf("[attacker] Injected!\n");
    fflush(stdout);
    // Use dlsym to get CalculateInput address (fallback if DbgSymbols fails)
    void* handle = dlopen(nullptr, RTLD_LAZY);
    int8_t* addr = (int8_t*)dlsym(handle, "CalculateInput");
    dlclose(handle);
    if (!addr) {
        printf("[attacker] Could not resolve CalculateInput symbol with dlsym!\n");
        fflush(stdout);
        return;
    }
    printf("[attacker] CalculateInput address (dlsym): %p\n", addr);
    fflush(stdout);
    hookftw::MidfunctionHook hook;
    hook.Hook(addr, [](hookftw::context* ctx) {
        ctx->PrintRegister();
    });
}
