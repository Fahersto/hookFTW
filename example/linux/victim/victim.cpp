#include <cstdint>
#include <ctime>
#include <iostream>

#include "Detour.h"
#include "MidfunctionHook.h"


int8_t* original = nullptr;

int hkInput()
{
	return 1337;
}

int CalculateInput(int arg1)
{
	int input = 0;
	int x,y,z;
	x = input * 4711;
	y = x  + input / 2;
	z = x * y + 3;
	return z * z * arg1;
}

int main()
{
	printf("Clean: %d\n", CalculateInput(1));

	/*
	hookftw::Detour detour;
	detour.Hook((int8_t*)CalculateInput, (int8_t*)hkInput);
	int calculated = CalculateInput();
	printf("Detour hooked: %d\n", CalculateInput());
	detour.Unhook();
	printf("Detour unhooked: %d\n", CalculateInput());
	*/
	hookftw::MidfunctionHook midfunctionHook;
	midfunctionHook.Hook((int8_t*)CalculateInput, [](hookftw::context* ctx) {
		ctx->PrintRegister();
		ctx->rdi = 10;
		ctx->CallOriginal<int,int>(1);
	} );
	printf("Midfunction hooked: %d\n", CalculateInput(1));
	midfunctionHook.Unhook();
	printf("Midfunction unhooked: %d\n", CalculateInput(1));
	return 0;
}