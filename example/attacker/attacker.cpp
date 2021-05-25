#include <Windows.h>


#include <Disassembler.h>
#include <Hook.h>
#include <FuncStartHook.h>
#include <Logger.h>
#include <DbgSymbols.h>


int answerToLife(int x)
{
	printf("42\n");
	return x;
}

#if _WIN64
DWORD __stdcall Run(LPVOID hModule)
{
	//Create debugging console
	//hookftw::Logger::OpenDebuggingConsole("hookftw");

	//Offsets in victim.exe x32
	int8_t* baseAddressOfProcess = (int8_t*)GetModuleHandle(NULL);
	int8_t* calcFunctionStart = baseAddressOfProcess + 0x13F0;

	//Offsets in victim.exe x64
	int8_t* calcFunctionStart_x64 = baseAddressOfProcess + 0x13A0;

	int8_t* answerToLifeStart = (int8_t*)GetModuleHandleA("example.dll") + 0x1ed0;

	hookftw::DbgSymbols dbgSymbols;
	dbgSymbols.EnumerateSymbols();
	
	hookftw::FuncStartHook prologHook(
		dbgSymbols.GetAddressBySymbolName("assignTest"),
		[](hookftw::context* ctx) {
			printf("Inside FuncStartHook\n");

			ctx->registers.rax = 0x4711;
			ctx->SkipOriginalFunction();

			//ctx->ChangeControllFlow(123213);

			//printf("CallOriginal %d\n", ctx->CallOriginal<int>(2));
			//printf("CallOriginal %d\n", ctx->CallOriginal<int>(3));
		}
	);

	/*
	
	hookftw::Hook hook(
		dbgSymbols.GetAddressBySymbolName("calculation"),
		[](hookftw::registers* registers) {
			printf("Inside the hooked function\n");
		}
	);
	*/
	
	/*
	hookftw::FuncStartHook prologHook(
		calcFunctionStart_x64,
		[](hookftw::context* ctx){
			//printf("Inside FuncStartHook\n");

		ctx->SkipOriginalFunction();
			//ctx->ChangeControllFlow(123213);

			//printf("CallOriginal %d\n", ctx->CallOriginal<int>(2));
			//printf("CallOriginal %d\n", ctx->CallOriginal<int>(3));
		}
	);
	*/

	while (true)
	{
		if (GetAsyncKeyState(VK_F1) & 0x1)
		{
			prologHook.Unhook();
			break;
		}
		if (GetAsyncKeyState(VK_F2) & 0x1)
		{
			answerToLife(0x300);
			printf("answerToLife %p\n", answerToLife);
		}
		if (GetAsyncKeyState(VK_F4) & 0x8000)
		{
			break;
		}
		Sleep(1);
	}

	//hookftw::Logger::CloseDebuggingConsole();
	FreeLibraryAndExitThread(static_cast<HMODULE>(hModule), 0);
	return TRUE;
}
#elif _WIN64
DWORD __stdcall Run(LPVOID hModule)
{
	//Create debugging console
	hookftw::Logger::OpenDebuggingConsole("hookftw - x64 Debug");

	//Offsets in victim.exe
	int8_t* baseAddressOfProcess = (int8_t*)GetModuleHandle(NULL);
	int8_t* calcFunctionStart = baseAddressOfProcess + 0x29A0;
	int8_t* withJNL = baseAddressOfProcess + 0x29BE;
	int8_t* includesCall = baseAddressOfProcess + 0x29D9;
	int8_t* Loopne = baseAddressOfProcess + 0x91C4;
	int8_t* ripRel = baseAddressOfProcess + 0x27fd;

	//Load debug symbols
	hookftw::DbgSymbols symbols;
	int8_t* gameUpdateStep = symbols.GetAddressBySymbolName("MainLoop::gameUpdateStep");


	hookftw::Disassembler disassembler;
	//disassembler.Analyse((int8_t*)GetModuleHandle(NULL) + 0x149, 0x6000);

	hookftw::Hook hook(
		gameUpdateStep,
		[](hookftw::registers* registers) {
		printf("Inside the hooked function\n");
	}
	);

	/*
	hookftw::FuncStartHook prologHook(
		functionStart,
		[](hookftw::context* ctx){
			//ctx->SkipCall();
			printf("Inside FuncStartHook\n");
			//printf("CallOriginal %d\n", ctx->CallOriginal<int>(2));
			//printf("CallOriginal %d\n", ctx->CallOriginal<int>(3));
		}
	);
	*/

	while (true)
	{
		if (GetAsyncKeyState(VK_F1) & 0x1)
		{
			hook.Unhook();
			break;
		}
		if (GetAsyncKeyState(VK_F4) & 0x8000)
		{
			break;
		}
		Sleep(1);
	}

	hookftw::Logger::CloseDebuggingConsole();
	FreeLibraryAndExitThread(static_cast<HMODULE>(hModule), 0);
	return TRUE;
}
#endif


BOOL __stdcall DllMain(HINSTANCE hModule, DWORD dwReason, LPVOID lpReserved)
{
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hModule);
		CreateThread(nullptr, 0, Run, hModule, 0, nullptr);
		break;

	case DLL_PROCESS_DETACH:
		break;
	default:
		break;
	}
	return TRUE;
}