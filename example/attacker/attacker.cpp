#include <Windows.h>


#include <MidfunctionHook.h>
#include <Detour.h>
#include <VFTHook.h>
#include <Logger.h>
#include <DbgSymbols.h>
#include <Decoder.h>
#include <VEHHook.h>


int answerToLife(int x)
{
	printf("42\n");
	return x;
}

int hookedCalculate(int x) 
{ 
	printf("calculate called, returning %d\n", x); 
	return x; 
}


void hkSound()
{
	printf("hkSound\n");
}

int _cdecl hkGetNumber()
{
	//printf("hkGetNumber\n");
	return rand();
}

void proxyFunction(hookftw::context* ctx){
	printf("inside hooked function\n"); 
	ctx->PrintRegister();
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

	int8_t* relocateRipRelative = baseAddressOfProcess + 0x14a0;
	int8_t* relocateRipRelaitveCall = baseAddressOfProcess + 0x159b; //call that directly references the rip register (ff 15 rel32) instead of being relative to the position of the next instruction (e8 rel32)
	int8_t* ripRelCmp = baseAddressOfProcess + 0x14a0;

	int8_t* answerToLifeStart = (int8_t*)GetModuleHandleA("example.dll") + 0x1ed0;

	hookftw::Decoder decoder;

	/*
	auto relativeInstructions = decoder.FindRelativeInstructionsOfType(baseAddressOfProcess, hookftw::RelativeInstruction::RIP_RELATIV, 0x2000);

	printf("[Info] relative instructions\n");
	for (auto& instruction : relativeInstructions)
	{
		printf("\t%p\n", instruction);
	}
	*/

	hookftw::DbgSymbols dbgSymbols;
	//dbgSymbols.EnumerateSymbols();

	//hookftw::Detour assignDetour;
	//assignDetour.Hook(dbgSymbols.GetAddressBySymbolName("assignTest"), (int8_t*)hkAssign);

	/*
	hookftw::Hook funcStartHook(
		relocateRipRelaitveCall,
		[](hookftw::context* ctx) {
			printf("Inside FuncStartHook\n");
			//ctx->PrintRegister();
			//ctx->ChangeControllFlow(123213);
			//ctx->SkipOriginalFunction();
			//ctx->rax = ctx->CallOriginal<int>(2);
	}
	);
	*/

	hookftw::MidfunctionHook midfunctionHook;
	midfunctionHook.Hook(
		dbgSymbols.GetAddressBySymbolName("stdCallFunc"),
		//baseAddressOfProcess + 0x1b4e, //call
		//baseAddressOfProcess + 0x1b3f, //je
		[](hookftw::context* ctx) {
			ctx->PrintRegister();
			//*(int32_t*)(ctx->esp + 0x4) = 0x2;
			//ctx->SkipOriginalFunction();
			ctx->rax = ctx->CallOriginal<int>(hookftw::CallingConvention::stdcall_call, 2, 3, 5);
		}
	);

	//int8_t* target = baseAddressOfProcess + 0x1c0b; //victim.exe+1C0B - 48 8D 0D 26B00000     - lea rcx,[victim.exe+CC38] 
	int8_t* target = baseAddressOfProcess + 0x1c76; //a couple of regular moves

	/*
	hookftw::MidfunctionHook prologHook;
	prologHook.Hook(
		//baseAddressOfProcess + 0x3206,
		target,
		[](hookftw::context* ctx) {
			ctx->PrintRegister();
		}
	);

	hookftw::Detour detourHook;
	detourHook.Hook(target, (int8_t*)hookedCalculate);
	
	int8_t** vftable = nullptr;
	hookftw::VFTHook vftHook(vftable);
	vftHook.Hook(3, (int8_t*)hookedCalculate);
	*/


	//hookftw::VEHHook vehHook;
	//vehHook.Hook(baseAddressOfProcess + 0x1210, (int8_t*)hkGetNumber);
	//vehHook.Hook(dbgSymbols.GetAddressBySymbolName("calculate"), (int8_t*)hkCalculate);
	//hookftw::VEHHook vehHook2(*(int8_t**)dbgSymbols.GetAddressBySymbolName("Cow::`vftable'"), (int8_t*)hkSound);


	/*
	
	hookftw::Hook hook(
		dbgSymbols.GetAddressBySymbolName("calculation"),
		[](hookftw::registers* registers) {
			printf("Inside the hooked function\n");
		}
	);
	*/
	
	/*
	hookftw::Hook prologHook(
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
			//assignDetour.Unhook();
			//vehHook.Unhook();
			//vehHook2.Unhook();
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


void hookedCow()
{
	printf("\t[Cow] - hooked - makes muuuh\n");
}

void hookedCat()
{
	printf("\t[Cat] - hooked - makes meow\n");
}

DWORD __stdcall Run(LPVOID hModule)
{
	//Create debugging console
	//hookftw::Logger::OpenDebuggingConsole("hookftw - x64 Debug");

	//Offsets in victim.exe
	int8_t* baseAddressOfProcess = (int8_t*)GetModuleHandle(NULL);
	int8_t* calcFunctionStart = baseAddressOfProcess + 0x29A0;

	int8_t* directHookedCalc = (int8_t*)GetModuleHandle("example.dll"); + 0x1E20;


	//Load debug symbols
	hookftw::DbgSymbols dbgSymbols;
	//dbgSymbols.EnumerateSymbols();

	hookftw::Decoder decoder;
	//auto relativeInstructions = decoder.FindRelativeInstructionsOfType(baseAddressOfProcess, hookftw::RelativeInstruction::CALL, 0x2000);

	/*
	int8_t* target = (int8_t*)hookedCalculate - 0x1429 + 0x1d80;
	hookftw::Detour assignDetour;
	assignDetour.Hook(dbgSymbols.GetAddressBySymbolName("calculate"), (int8_t*)target);
	*/

	
	/*
	hookftw::MidfunctionHook midfunctionHook;
	midfunctionHook.Hook(
		dbgSymbols.GetAddressBySymbolName("fastCallFunc"),
		//baseAddressOfProcess + 0x1b4e, //call
		//baseAddressOfProcess + 0x1b3f, //je
		[](hookftw::context* ctx) {
			ctx->PrintRegister();
			//*(int32_t*)(ctx->esp + 0x4) = 0x2;
			//ctx->SkipOriginalFunction();
			ctx->eax = ctx->CallOriginal<int>(hookftw::CallingConvention::fastcall_call, 2,3,5);
		}
	);
	*/

	/*
	hookftw::Hook assignTestHook(
		dbgSymbols.GetAddressBySymbolName("assignTest"),
		[](hookftw::context* ctx) {
			ctx->PrintRegister();
			ctx->SkipOriginalFunction();
			ctx->eax = ctx->CallOriginal<int>(2);
		}
	);
	*/
	

	hookftw::VEHHook vehHook;
	vehHook.Hook(dbgSymbols.GetAddressBySymbolName("calculate"), (int8_t*)hookedCalculate);
	
	
	hookftw::VFTHook cowVmtHook((int8_t**)dbgSymbols.GetAddressBySymbolName("Cow::`vftable'"));
	cowVmtHook.Hook(0, (int8_t*)hookedCow);

	hookftw::VFTHook catVmtHook((int8_t**)dbgSymbols.GetAddressBySymbolName("Cat::`vftable'"));
	catVmtHook.Hook(0, (int8_t*)hookedCat);
	

	while (true)
	{
		if (GetAsyncKeyState(VK_F1) & 0x1)
		{
			//cowVmtHook.Unhook();
			//catVmtHook.Unhook();
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