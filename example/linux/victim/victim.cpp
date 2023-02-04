#include <cstdint>
#include <iostream>

#include <Detour.h>

int8_t* original = nullptr;

int hkInput()
{
	return 1337;
}

int CalculateInput()
{
	int input = 0;
	printf("Gimme a number: ");
	scanf("%d", &input);

	printf("Scanned input %d", input);

	int x,y,z;
	x = input * 4711;
	y = x  + input / 2;
	z = x * y + 3;
	return z * z;
}

int main()
{
	hookftw::Detour detour;
	detour.Hook((int8_t*)CalculateInput, (int8_t*)hkInput);
	return CalculateInput();
}