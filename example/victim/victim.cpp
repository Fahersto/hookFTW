#include <cstdio>
#include <Windows.h>
#include <vector>

int sum(int x, int y, int z)
{
	return x * y + z * z;
}

int calculation(int x)
{
	int z = x * 3;
	int t = z - 2;
	int y = z + t;
	int k = t + z;
	if (k < 2)
	{
		k *= 3;
		return z * y - k;
	}
	if (calculation(y+k) > 10 + sum(y,k,k))
	{
		//std::vector<int> numbers;
		for (int k = 10; t < k; k++)
		{
			if (k>100)
			{
				break;
			}
			else
			{
				//numbers.push_back(k);
			}
		}
	}
	x += sum(y, k, k);
	if (x < 3 && y +k > 6 && 8 < y && k < z)
	{
		if (z++ < 3 || k - 3 + 5 > t)
		{
			return x * k + z;
		}
	}
	return x * x + z - t + k * 3 - y;
}

int main()
{
	printf("aslr: %p calculationOffset: %p calculation: %p\n", GetModuleHandle(NULL), (BYTE*)calculation - (BYTE*)GetModuleHandle(NULL), calculation);
	while (true)
	{
		const int value = 2;
		printf("%d calculation = %d\n", value, calculation(value));
		Sleep(1000);
	}
}