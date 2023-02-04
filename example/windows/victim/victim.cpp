#include <cstdio>
#include <Windows.h>
#include <vector>

class Animal
{
public:
	virtual void MakeSound() = 0;
};

class Cow : public Animal
{
public:
	void MakeSound() override
	{
		printf("\t[Cow] - Copy on write\n");
	}
};

class Cat : public Animal
{
public:
	void MakeSound() override
	{
		printf("\t[Cat] - concatenate files and print on the standard output\n");
	}
};

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

int calculate(int x)
{
	int returnVal = x * 2 + 3;
	returnVal ^= x;
	return returnVal * 5;
}

int __stdcall stdCallFunc(int x, int y, int z)
{
	return x * x + y * y + z * z;
}

int __fastcall fastCallFunc(int x, int y, int z)
{
	return x * x + y * y + z * z;
}

int __cdecl cdeclCallFunc(int x, int y, int z)
{
	return x * x + y * y + z * z;
}


int main()
{
	printf("aslr: %p calculationOffset: %p calculation: %p\n", GetModuleHandle(NULL), (BYTE*)calculation - (BYTE*)GetModuleHandle(NULL), calculation);

	std::vector<Animal*> animals;
	Cow cow;
	Cat cat;
	animals.push_back(&cow);
	animals.push_back(&cat);

	printf("cow address: %p\n", &cow);
	printf("cat address: %p\n", &cat);
	while (true)
	{
		const int value = 2;
		printf("%d calculation = %d\n", value, calculation(value));

		int test = 1337;
		test = calculate(1337);
		printf("calculate = %d\n", test);

		printf("stdCallFunc = %d\n", stdCallFunc(2,3,5));
		printf("cdeclCallFunc = %d\n", cdeclCallFunc(2, 3, 5));
		printf("fastCallFunc = %d\n", fastCallFunc(2, 3, 5));

		printf("Animals\n");
		for (auto& animal : animals)
		{
			animal->MakeSound();
		}
		
		printf("aslr: %p\n", (BYTE*)GetModuleHandle(NULL));

		Sleep(1000);
	}
}