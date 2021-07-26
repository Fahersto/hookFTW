![hookftw banner](img/hookftw_banner.png)
# hookFTW - hooking for the win(dows)
A hooking library for Windows (32/64 Bit).

## Setting up using CMAKE
1. Clone including submodules:
```
git clone --recursive git@git.fslab.de:fstotz2s/hookftw.git
```
2. Build the library using CMAKE.

## Setting up manually
1. Clone including submodules:
```
git clone --recursive https://git.fslab.de/fstotz2s/hookftw.git
```
2. Build hookFTW
	- Include headers: hookftw/library/src
	- Link hookftw.lib
	- Link Zydis.lib
	
## Documentation
work in progress

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