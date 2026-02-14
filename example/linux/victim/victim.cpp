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
	int result = 4711;
	result = CalculateInput(1);
	printf("Clean: %d\n", result);
	return 0;
}