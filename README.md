![hookftw banner](img/hookftw_banner.png)
# hookftw - hooking for the win(dows)
A hooking library for Windows (32/64 Bit)

# How to install
Clone including submodules (zydis).

# Documentation
work in progress

# Usage example
```C++
int squareThenSum(int x, int y)
{
	return x * x + y * y;
}

//To be used at the start address of the function
hookftw::FuncStartHook funcStartHook(
	squareThenSum, //start of the function
	[](hookftw::context* ctx){
		printf("Inside FuncStartHook\n");
		printf("CallOriginal %d\n", ctx->CallOriginal<int>(2, 3));
	}
);

//hook at arbitrary address within the function
hookftw::Hook hook(
	squareThenSum + 0x5,
	[](hookftw::registers* registers) {
		printf("Inside the hooked function\n");
	}
);

```