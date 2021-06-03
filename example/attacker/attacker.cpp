#include <Windows.h>



#include <FuncStartHook.h>
#include <Logger.h>
#include <DbgSymbols.h>
#include <Decoder.h>


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
	int8_t* calcFunctionStart = baseAddressOfProcess + 0x13C0;
	int8_t* calcFunctionRelocateCall = baseAddressOfProcess + 0x13FC;
	int8_t* calcFunctionRelocateJnl = baseAddressOfProcess + 0x13E2;
	int8_t* relocateRipRelative = baseAddressOfProcess + 0x14a0;
	int8_t* relocateRipRelaitveCall = baseAddressOfProcess + 0x159b; //call that directly references the rip register (ff 15 rel32) instead of being relative to the position of the next instruction (e8 rel32)
	int8_t* ripRelCmp = baseAddressOfProcess + 0x14a0;

	int8_t* answerToLifeStart = (int8_t*)GetModuleHandleA("example.dll") + 0x1ed0;

	
	hookftw::Decoder decoder;
	auto relativeInstructions = decoder.FindRelativeInstructionsOfType(baseAddressOfProcess, hookftw::RelativeInstruction::CALL, 0x2000);

	printf("[Info] relative instructions\n");
	for (auto& instruction : relativeInstructions)
	{
		printf("\t%p\n", instruction);
	}
	
	
	hookftw::DbgSymbols dbgSymbols;
	//dbgSymbols.EnumerateSymbols();

	hookftw::FuncStartHook funcStartHook(
		relocateRipRelaitveCall,
		[](hookftw::context* ctx) {
			printf("Inside FuncStartHook\n");
			//ctx->PrintRegister();
			//printf("rsp at hook address: %llx\n", ctx->GetRspAtHookAddress());
			//ctx->ChangeControllFlow(123213);
			//ctx->SkipOriginalFunction();
			//ctx->rax = ctx->CallOriginal<int>(2);
	}
	);
	
	/*
	hookftw::FuncStartHook prologHook(
		dbgSymbols.GetAddressBySymbolName("calculation"),
		[](hookftw::context* ctx) {
			printf("Inside FuncStartHook\n");
			//ctx->ChangeControllFlow(123213);
			ctx->SkipOriginalFunction();
			ctx->registers.rax = ctx->CallOriginal<int>(2);
		}
	);
	*/

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
			funcStartHook.Unhook();
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
#elif _WIN32
DWORD __stdcall Run(LPVOID hModule)
{
	//Create debugging console
	//hookftw::Logger::OpenDebuggingConsole("hookftw - x64 Debug");

	//Offsets in victim.exe
	int8_t* baseAddressOfProcess = (int8_t*)GetModuleHandle(NULL);
	int8_t* calcFunctionStart = baseAddressOfProcess + 0x29A0;


	//Load debug symbols
	hookftw::DbgSymbols dbgSymbols;


	hookftw::Decoder decoder;
	auto relativeInstructions = decoder.FindRelativeInstructionsOfType(baseAddressOfProcess, hookftw::RelativeInstruction::CALL, 0x2000);

	
	hookftw::FuncStartHook assignTestHook(
		dbgSymbols.GetAddressBySymbolName("calculation"),
		[](hookftw::context* ctx) {
			//ctx->PrintRegister();
			//printf("esp at hook address: %llx\n", ctx->GetEspAtHookAddress());
			ctx->SkipOriginalFunction();
			ctx->eax = ctx->CallOriginal<int>(1337);
		}
	);

	while (true)
	{
		if (GetAsyncKeyState(VK_F1) & 0x1)
		{
			assignTestHook.Unhook();
			//calculationHook.Unhook();
			break;
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