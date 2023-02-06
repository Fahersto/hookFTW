![hookftw banner](img/hookftw_banner.png)
![example workflow](https://github.com/fahersto/hookFTW/actions/workflows/cmake.yml/badge.svg)
# hookFTW - hook for the win(dows)
A hooking library for Windows (32/64 Bit) with Linux support.

## Setting up using CMAKE
1. Clone including submodules:
```
git clone --recursive https://github.com/Fahersto/hookFTW.git
```
2. Build the library using CMAKE.

## Setting up manually
1. Clone including submodules:
```
git clone --recursive https://github.com/Fahersto/hookFTW.git
```
2. Build hookFTW
	- Include headers: hookftw/library/src
	- Link hookftw.lib
	- Link Zydis.lib
	
## Documentation
HookFTW uses doxygen to generate its documentation. The Doxyfile is provided in this repository. A prebuild version can be found here: https://hookftw.fahersto.de/

## Usage example

### Detour Hook
```C++
// proxy function we change the control flow to
int hookedCalculate(int x) 
{ 
	printf("calculate called, returning %d\n", x); 
	return x; 
}

// defining a type to be able to invoke the trampoline as function
using originalFunction = int(__fastcall*) (int x);

// use a detour hook. Note that this hooking methods only supports hooking at a start of a function.
hookftw::Detour detourHook;
originalFunction originalCalculate = (originalFunction)detourHook.Hook(target, (int8_t*)hookedCalculate);

// call original function
originalFunction(10);
```

---

### Midfunction Hook
Using a lamba:
```C++
// use a midfunction hook. In this example we pass the proxy function as a lambda.
hookftw::MidfunctionHook prologHook;
prologHook.Hook(
	targetAddress,
	[](hookftw::context* ctx) {
		printf("inside hooked function\n"); 
		ctx->PrintRegister();
	}
);
```

Using a function pointer:
```C++
// use a midfunction hook. In this example we pass the proxy function as a lambda.

void proxyFunction(hookftw::context* ctx){
	printf("inside hooked function\n"); 
	ctx->PrintRegister();
}

hookftw::MidfunctionHook prologHook;
prologHook.Hook(targetAddress, proxyFunction);
);
```

---

### Vectored Exception Handler Hook
```C++
int hookedCalculate(int x) 
{ 
	printf("calculate called, returning %d\n", x); 
	return x; 
}

hookftw::VEHHook vehHook;
vehHook.Hook(targetAddress, (int8_t*)hookedCalculate);
```

---

### Virtual Function Table Hook
```C++
// this address needs to be a pointer to a virtual function table 
int8_t** vftable = nullptr;

hookftw::VFTHook vftHook(vftable);

// in this example we hook the fourth function in the vftable
vftHook.Hook(3, (int8_t*)hookedCalculate)
```

---

### Import Address Table Hook
```C++
using orignalMessageBox = BOOL(WINAPI*)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
orignalMessageBox oMessage;

int WINAPI hkMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
	printf("hkMessageBoxA!\n");
	return oMessage(hWnd, lpText, lpCaption, uType);
}

hookftw::IATHook iatHook;
oMessage = (orignalMessageBox)iatHook.Hook("User32.dll", "MessageBoxA", (int8_t*)hkMessageBoxA);
```
