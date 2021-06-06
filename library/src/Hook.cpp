#include "Hook.h"

#include <cassert>
#include <vector>

#include <Zydis/Zydis.h>
#include <Zydis/DecoderTypes.h>

#include "Decoder.h"

namespace hookftw
{
	/**
	 * Attempts to allocate a trampoline_ within +-2gb range of the hook so we only need 5 bytes to hook (jmp rel32) instead of 14 (jmp[rip+0] int64_t, only in x64)
	 */
	void Hook::AllocateTrampoline(int8_t* hookAddress)
	{
		//TODO respect lower and upper bound of relative instrucions
		int requiredBytes = 5;

		//allocate the trampoline_. We need to allocate this first so we know how many bytes we need to overwrite (5 or 14 Bytes)
		SYSTEM_INFO systemInfo;
		GetSystemInfo(&systemInfo);
		int allocationAttemps = 0;
		int iterations = 0;

		printf("[Info] - FuncStartHook - Attempting to allocate trampoline within +-2GB range\n");
		while (!trampoline_)
		{
			iterations++;
			//TODO is this calculation correct?
			int8_t* targetAddress = sourceAddress_ + 2147483647 - (allocationAttemps++ * systemInfo.dwPageSize);
			if (targetAddress > 0)
			{
				//Try to allocate trampoline_ within "JMP rel32" range so we can hook by overwriting 5 Bytes instead of 14 Bytes
				trampoline_ = (int8_t*)VirtualAlloc(targetAddress, systemInfo.dwPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			}
			else
			{
				//If we couldn't allocate within +-2GB range let the system allocate the memory page anywhere and use and absolute jump. JMP [RIP+0] 0x1122334455667788 (14 Bytes)
				trampoline_ = (int8_t*)VirtualAlloc(NULL, systemInfo.dwPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
				requiredBytes = 14;
				printf("[Warning] - FuncStartHook - Could not allocate trampoline within desired range. We currently can't relocate rip-relative instructions in this case!\n");
			}
		}
		printf("[Info] - FuncStartHook - Allocated trampoline at %p (using %d attempts)\n", trampoline_, iterations);
	}

#if _WIN64
	void Hook::GenerateTrampolineAndApplyHook(int8_t* sourceAddress, int hookLength, std::vector<int8_t> relocatedBytes, void __fastcall proxy(context* ctx))
	{
		const int stubLength = 419;
		const int controlFlowStubLength = 33;
		const int proxyFunctionAddressIndex = 215;

		//compensates for all the changes to the stack before the proxy function is called
		//this way we get the rsp value time 
		const int rspCompenstaion = 384;

		//const int saveRaxAddress = 180;
		const int thisAddress = 179;
		const int saveRspAddress = 193;
		const int restoreRspAddress = 227;

		//5 bytes for jmp rel32
		//14 bytes are required to place JMP[rip+0x] 0x1122334455667788
		//TODO flag for when we need 14 bytes (because trampoline out of range)
		const int bytesRequiredForPlacingHook = 5;
		
		assert(hookLength >= bytesRequiredForPlacingHook); 
		
		//1. save xmm registers
		//2. save general purpose registers
		//3. align the stack to 16 bytes
		//4. call proxy function
		//5. restore all registers
		//6. jump back to orignal function
		BYTE stub[stubLength] = {
			0x9C,														//pushfq	
			0x48, 0x83, 0xEC, 0x10,										//sub    rsp,0x10
			0xF3, 0x44, 0x0F, 0x7F, 0x3C, 0x24,							//movdqu XMMWORD PTR [rsp],xmm15
			0x48, 0x83, 0xEC, 0x10,										//sub    rsp,0x10
			0xF3, 0x44, 0x0F, 0x7F, 0x34, 0x24,							//movdqu XMMWORD PTR [rsp],xmm14
			0x48, 0x83, 0xEC, 0x10,										//sub    rsp,0x10
			0xF3, 0x44, 0x0F, 0x7F, 0x2C, 0x24,							//movdqu XMMWORD PTR [rsp],xmm13
			0x48, 0x83, 0xEC, 0x10,										//sub    rsp,0x10
			0xF3, 0x44, 0x0F, 0x7F, 0x24, 0x24,							//movdqu XMMWORD PTR [rsp],xmm12
			0x48, 0x83, 0xEC, 0x10,										//sub    rsp,0x10
			0xF3, 0x44, 0x0F, 0x7F, 0x1C, 0x24,							//movdqu XMMWORD PTR [rsp],xmm11
			0x48, 0x83, 0xEC, 0x10,										//sub    rsp,0x10
			0xF3, 0x44, 0x0F, 0x7F, 0x14, 0x24,							//movdqu XMMWORD PTR [rsp],xmm10
			0x48, 0x83, 0xEC, 0x10,										//sub    rsp,0x10
			0xF3, 0x44, 0x0F, 0x7F, 0x0C, 0x24,							//movdqu XMMWORD PTR [rsp],xmm9
			0x48, 0x83, 0xEC, 0x10,										//sub    rsp,0x10
			0xF3, 0x44, 0x0F, 0x7F, 0x04, 0x24,							//movdqu XMMWORD PTR [rsp],xmm8
			0x48, 0x83, 0xEC, 0x10,										//sub    rsp,0x10
			0xF3, 0x0F, 0x7F, 0x3C, 0x24,								//movdqu XMMWORD PTR [rsp],xmm7
			0x48, 0x83, 0xEC, 0x10,										//sub    rsp,0x10
			0xF3, 0x0F, 0x7F, 0x34, 0x24,								//movdqu XMMWORD PTR [rsp],xmm6
			0x48, 0x83, 0xEC, 0x10,										//sub    rsp,0x10
			0xF3, 0x0F, 0x7F, 0x2C, 0x24,								//movdqu XMMWORD PTR [rsp],xmm5
			0x48, 0x83, 0xEC, 0x10,										//sub    rsp,0x10
			0xF3, 0x0F, 0x7F, 0x24, 0x24,								//movdqu XMMWORD PTR [rsp],xmm4
			0x48, 0x83, 0xEC, 0x10,										//sub    rsp,0x10
			0xF3, 0x0F, 0x7F, 0x1C, 0x24,								//movdqu XMMWORD PTR [rsp],xmm3
			0x48, 0x83, 0xEC, 0x10,										//sub    rsp,0x10
			0xF3, 0x0F, 0x7F, 0x14, 0x24,								//movdqu XMMWORD PTR [rsp],xmm2
			0x48, 0x83, 0xEC, 0x10,										//sub    rsp,0x10
			0xF3, 0x0F, 0x7F, 0x0C, 0x24,								//movdqu XMMWORD PTR [rsp],xmm1
			0x48, 0x83, 0xEC, 0x10,										//sub    rsp,0x10
			0xF3, 0x0F, 0x7F, 0x04, 0x24,								//movdqu XMMWORD PTR [rsp],xmm0
			0x41, 0x57,													//push   r15
			0x41, 0x56,													//push   r14
			0x41, 0x55,													//push   r13
			0x41, 0x54,													//push   r12
			0x41, 0x53,													//push   r11
			0x41, 0x52,													//push   r10
			0x41, 0x51,													//push   r9
			0x41, 0x50,													//push   r8
			0x57,														//push   rdi
			0x56,														//push   rsi
			0x55,														//push   rbp
			0x53,														//push   rbx
			0x52,														//push   rdx
			0x51,														//push   rcx
			0x50,														//push   rax
			0x54,														//push	 rsp
			0x48, 0xB8, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,	//mov	 rax, this 
			0x50,														//push	 rax
			0x48, 0x89, 0xE1,											//mov    rcx, rsp					//make first argument point at the stack
			0x48, 0xB8, 88, 77, 66, 55, 44, 33, 22, 11,					//mov	 rax, addressOfLocal		//save rsp because we don't know if we substract bytes to get the correct alignment before the call
			0x48, 0x89, 0x20,											//mov	 [rax], rsp
			0x48, 0x0F, 0xBA, 0xF4, 0x03,								//btr	 rsp, 3						(align stack to 16 bytes before call)
			0x48, 0x83, 0xEC, 0x20,										//sub    rsp,0x20					(allocate shadow space)
			0x48, 0xB8, 88, 77, 66, 55, 44, 33, 22, 11,					//movabs rax,0x1122334455667788		(use register to have an absolute 8 byte call)
			0xFF, 0xD0,													//call   rax						(call proxy function)
			0x48, 0xB8, 88, 77, 66, 55, 44, 33, 22, 11,					//mov rax, addressOforiginalRspLocalVariable. We restore rsp like this because we don't know if stack was aligned to 16 byte beforehand
			0x48, 0x8B, 0x20,											//mov rsp, [rax]
			0x48, 0x83, 0xC4, 0x8,										//add    rsp, 0x8	//compensate for the "push rax" before saving rsp
			0x5c,														//pop	 rsp
			0x58,														//pop    rax
			0x59,														//pop    rcx
			0x5A,														//pop    rdx
			0x5B,														//pop    rbx
			0x5D,														//pop    rbp
			0x5E,														//pop    rsi
			0x5F,														//pop    rdi
			0x41, 0x58,													//pop    r8
			0x41, 0x59,													//pop    r9
			0x41, 0x5A,													//pop    r10
			0x41, 0x5B,													//pop    r11
			0x41, 0x5C,													//pop    r12
			0x41, 0x5D,													//pop    r13
			0x41, 0x5E,													//pop    r14
			0x41, 0x5F,													//pop    r15
			0xF3, 0x0F, 0x6F, 0x04, 0x24,								//movdqu xmm0,XMMWORD PTR[rsp]
			0x48, 0x83, 0xC4, 0x10,										//add    rsp,0x10
			0xF3, 0x0F, 0x6F, 0x0C, 0x24,								//movdqu xmm1,XMMWORD PTR[rsp]
			0x48, 0x83, 0xC4, 0x10,										//add    rsp,0x10
			0xF3, 0x0F, 0x6F, 0x14, 0x24,								//movdqu xmm2,XMMWORD PTR[rsp]
			0x48, 0x83, 0xC4, 0x10,										//add    rsp,0x10
			0xF3, 0x0F, 0x6F, 0x1C, 0x24,								//movdqu xmm3,XMMWORD PTR[rsp]
			0x48, 0x83, 0xC4, 0x10,										//add    rsp,0x10
			0xF3, 0x0F, 0x6F, 0x24, 0x24,								//movdqu xmm4,XMMWORD PTR[rsp]
			0x48, 0x83, 0xC4, 0x10,										//add    rsp,0x10
			0xF3, 0x0F, 0x6F, 0x2C, 0x24,								//movdqu xmm5,XMMWORD PTR[rsp]
			0x48, 0x83, 0xC4, 0x10,										//add    rsp,0x10
			0xF3, 0x0F, 0x6F, 0x34, 0x24,								//movdqu xmm6,XMMWORD PTR[rsp]
			0x48, 0x83, 0xC4, 0x10,										//add    rsp,0x10
			0xF3, 0x0F, 0x6F, 0x3C, 0x24,								//movdqu xmm7,XMMWORD PTR[rsp]
			0x48, 0x83, 0xC4, 0x10,										//add    rsp,0x10
			0xF3, 0x44, 0x0F, 0x6F, 0x04, 0x24,							//movdqu xmm8,XMMWORD PTR[rsp]
			0x48, 0x83, 0xC4, 0x10,										//add    rsp,0x10
			0xF3, 0x44, 0x0F, 0x6F, 0x0C, 0x24,							//movdqu xmm9,XMMWORD PTR[rsp]
			0x48, 0x83, 0xC4, 0x10,										//add    rsp,0x10
			0xF3, 0x44, 0x0F, 0x6F, 0x14, 0x24,							//movdqu xmm10,XMMWORD PTR[rsp]
			0x48, 0x83, 0xC4, 0x10,										//add    rsp,0x10
			0xF3, 0x44, 0x0F, 0x6F, 0x1C, 0x24,							//movdqu xmm11,XMMWORD PTR[rsp]
			0x48, 0x83, 0xC4, 0x10,										//add    rsp,0x10
			0xF3, 0x44, 0x0F, 0x6F, 0x24, 0x24,							//movdqu xmm12,XMMWORD PTR[rsp]
			0x48, 0x83, 0xC4, 0x10,										//add    rsp,0x10
			0xF3, 0x44, 0x0F, 0x6F, 0x2C, 0x24,							//movdqu xmm13,XMMWORD PTR[rsp]
			0x48, 0x83, 0xC4, 0x10,										//add    rsp,0x10
			0xF3, 0x44, 0x0F, 0x6F, 0x34, 0x24,							//movdqu xmm14,XMMWORD PTR[rsp]
			0x48, 0x83, 0xC4, 0x10,										//add    rsp,0x10
			0xF3, 0x44, 0x0F, 0x6F, 0x3C, 0x24,							//movdqu xmm15,XMMWORD PTR[rsp]
			0x48, 0x83, 0xC4, 0x10,										//add    rsp,0x20
			0x9D														//popfq
		};
		
		//used to the controll flow after the hook can be changed (for example skip oroginal call)
		int8_t controllFlowStub[controlFlowStubLength] = {
			0x48, 0xA3, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,	//movabs ds:0x1122334455667788,rax
			0x48, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,	//movabs rax,0x1122334455667788
			0xFF, 0x30,													//push   QWORD PTR [rax]
			0x48, 0xA1, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,	//movabs rax, [0x1122334455667788]  addr. of local saved rax
			0xC3														//ret
		};
		*(int64_t*)&controllFlowStub[2] = (int64_t)&savedRax_;

		//save original bytes
		originalBytes_ = new int8_t[hookLength];
		memcpy(originalBytes_, sourceAddress, hookLength);

		//allocate space for stub + space for RELLOCATED bytes + jumpback
		//trampoline_ = (int8_t*)VirtualAlloc(NULL, stubLength + relocatedBytes.size() + controlFlowStubLength, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		
		returnAddressFromTrampoline_ = (int64_t)(trampoline_ + stubLength +  controlFlowStubLength);
		
		//insert address of the value to return code execution after hook
		*(int64_t*)&controllFlowStub[12] = (int64_t)&returnAddressFromTrampoline_;

		//insert address of member variable to save RAX
		*(int64_t*)&controllFlowStub[24] = (int64_t)&savedRax_;

		//copy stub to trampoline_
		memcpy(trampoline_, stub, stubLength);
	
		//save address after the stub so we can call the function without running into our hook again
		addressToCallFunctionWithoutHook_ = &trampoline_[stubLength + controlFlowStubLength];

		//copy controllFlow stub
		memcpy(&trampoline_[stubLength], controllFlowStub, controlFlowStubLength);
		
		//copy relocated original bytes to trampoline
		memcpy(&trampoline_[stubLength + controlFlowStubLength], relocatedBytes.data(), relocatedBytes.size());

		//in x64bit we always do an absoolute 8 byte jump. This way the trampoline does not need to be in +-2bg range.
		//In such cases relocation of rip-relative instructions is not supported
		const int stubJumpBackLength = 14;
		int8_t jmpBackStub[stubJumpBackLength] = {
			0xff, 0x25, 0x0, 0x0, 0x0,0x0,					//JMP[rip + 0]
			0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88	//absolute address of jump
		};
		*(int64_t*)&jmpBackStub[6] = (int64_t )&sourceAddress_[hookLength];
		memcpy(&trampoline_[stubLength + controlFlowStubLength + relocatedBytes.size()], jmpBackStub, stubJumpBackLength);
		
		//insert address of proxy function to call instruction
		*(int64_t*)&trampoline_[thisAddress] = (int64_t)this;
		*(int64_t*)&trampoline_[proxyFunctionAddressIndex] = (int64_t)proxy;
		*(int64_t*)&trampoline_[saveRspAddress] = (int64_t)&originalRsp_;
		*(int64_t*)&trampoline_[restoreRspAddress] = (int64_t)&originalRsp_;

		//write jump from trampoline_ to original code
		//*(int64_t*)&trampoline_[stubLength + rellocatedBytesLength + 6] = (int64_t)&sourceAddress_[hookLength];

		//make page of original code writeable
		DWORD pageProtection;
		VirtualProtect(sourceAddress, hookLength, PAGE_READWRITE, &pageProtection);

		//write JMP from original code to trampoline_
		sourceAddress[0] = 0xe9;										//opcodes = JMP rel32
		*(uint32_t*)(&sourceAddress[1]) = (int32_t)((int64_t)trampoline_ - (int64_t)sourceAddress - 5);

		//NOP left over bytes
		for (int i = bytesRequiredForPlacingHook; i < hookLength; i++)
		{
			sourceAddress[i] = 0x90;
		}

		//restore page protection of original code
		VirtualProtect(sourceAddress, hookLength, pageProtection, &pageProtection);
	}
#elif _WIN32
void Hook::GenerateTrampolineAndApplyHook(int8_t* sourceAddress, int hookLength, std::vector<int8_t> relocatedBytes, void __fastcall proxy(context* ctx))
{
	const int stubLength = 160;
	const int controlFlowStubLength = 18;
	const int proxyFunctionAddressIndex = 80;

	const int thisAddress = 73;
	//const int saveRspAddress = 196;
	//const int restoreRspAddress = 230;

	const int jmpStubLength = 5;
		
	//5 bytes are required to place JMP 0x11223344
	assert(hookLength >= jmpStubLength);

	//1. save all registers
	//2. call proxy function
	//3. restore all registers
	//4. jump back to orignal function
	BYTE stub[stubLength] = {
		0x83, 0xEC, 0x10,				//sub    esp,0x10
		0xf3, 0x0f, 0x7f, 0x3c, 0x24,	//movdqu XMMWORD PTR [esp],xmm7
		0x83, 0xEC, 0x10,				//sub    esp,0x10
		0xf3, 0x0f, 0x7f, 0x34, 0x24,	//movdqu XMMWORD PTR [esp],xmm6
		0x83, 0xEC, 0x10,				//sub    esp,0x10
		0xf3, 0x0f, 0x7f, 0x2c, 0x24,	//movdqu XMMWORD PTR [esp],xmm5
		0x83, 0xEC, 0x10,				//sub    esp,0x10
		0xf3, 0x0f, 0x7f, 0x24, 0x24,	//movdqu XMMWORD PTR [esp],xmm4
		0x83, 0xEC, 0x10,				//sub    esp,0x10
		0xf3, 0x0f, 0x7f, 0x1c, 0x24,	//movdqu XMMWORD PTR [esp],xmm3
		0x83, 0xEC, 0x10,				//sub    esp,0x10
		0xf3, 0x0f, 0x7f, 0x14, 0x24,	//movdqu XMMWORD PTR [esp],xmm2
		0x83, 0xEC, 0x10,				//sub    esp,0x10
		0xf3, 0x0f, 0x7f, 0x0c, 0x24,	//movdqu XMMWORD PTR [esp],xmm1
		0x83, 0xEC, 0x10,				//sub    esp,0x10
		0xf3, 0x0f, 0x7f, 0x04, 0x24,	//movdqu XMMWORD PTR [esp],xmm0
		0x57,							//push   edi
		0x56,							//push   esi
		0x55,							//push   ebp
		0x53,							//push   ebx
		0x52,							//push   edx
		0x51,							//push   ecx
		0x50,							//push   eax
		0x54,							//push	 esp		//save esp so we can overwrite register values

		0xB8, 0x44, 0x33, 0x22, 0x11,	//mov	 eax, this 
		0x50,							//push	 eax
		
		0x89, 0xE1,						//mov    ecx,esp
		0xE8, 0x44, 0x33, 0x22, 0x11,	//call   11223344

		0x83, 0xC4, 0x04,				//add    esp,0x4
		
		0x5C,							//pop	 esp
		0x58,							//pop    eax
		0x59,							//pop    ecx
		0x5A,							//pop    edx			
		0x5B,							//pop    ebx
		0x5D,							//pop    ebp
		0x5E,							//pop    esi
		0x5F,							//pop    edi
		0xf3, 0x0f, 0x6f, 0x04, 0x24,	//movdqu xmm0,XMMWORD PTR [esp]
		0x83, 0xC4, 0x10,				//add    esp,0x10
		0xf3, 0x0f, 0x6f, 0x0c, 0x24,	//movdqu xmm1,XMMWORD PTR [esp]
		0x83, 0xC4, 0x10,				//add    esp,0x10
		0xf3, 0x0f, 0x6f, 0x14, 0x24,	//movdqu xmm2,XMMWORD PTR [esp]
		0x83, 0xC4, 0x10,				//add    esp,0x10
		0xf3, 0x0f, 0x6f, 0x1c, 0x24,	//movdqu xmm3,XMMWORD PTR [esp]
		0x83, 0xC4, 0x10,				//add    esp,0x10
		0xf3, 0x0f, 0x6f, 0x24, 0x24,	//movdqu xmm4,XMMWORD PTR [esp]
		0x83, 0xC4, 0x10,				//add    esp,0x10
		0xf3, 0x0f, 0x6f, 0x2c, 0x24,	//movdqu xmm5,XMMWORD PTR [esp]
		0x83, 0xC4, 0x10,				//add    esp,0x10
		0xf3, 0x0f, 0x6f, 0x34, 0x24,	//movdqu xmm6,XMMWORD PTR [esp]
		0x83, 0xC4, 0x10,				//add    esp,0x10
		0xf3, 0x0f, 0x6f, 0x3c, 0x24,	//movdqu xmm7,XMMWORD PTR [esp]
		0x83, 0xC4, 0x10				//add    esp,0x10
	};

	BYTE stubJumpBack[jmpStubLength] = { 0xE9, 0x11, 0x22, 0x33, 0x44 };	//jmp 1122335a (back to original code)

	//write jump from trampoline to original code
	*(int32_t*)&stubJumpBack[1] = (int32_t)&sourceAddress[hookLength] - (int32_t)&trampoline_[stubLength + controlFlowStubLength + relocatedBytes.size()] - jmpStubLength;
		

	int8_t controllFlowStub[controlFlowStubLength] = {
		0xA3, 0x44, 0x33, 0x22, 0x11,	//mov ds : 0x11223344,eax
		0xB8, 0x44, 0x33, 0x22, 0x11,	//mov eax,0x11223344
		0xFF, 0x30,						//push DWORD PTR [eax]
		0xA1, 0x44, 0x33, 0x22, 0x11,	//mov eax,ds:0x11223344
		0xC3							//ret
	};
	*(int32_t*)&controllFlowStub[1] = (int32_t)&savedRax_; //TODO rax.. this is 32bit
	returnAddressFromTrampoline_ = (int32_t)(trampoline_ + stubLength + controlFlowStubLength);
		
	//insert address of the value to return code execution after hook
	*(int32_t*)&controllFlowStub[6] = (int32_t)&returnAddressFromTrampoline_;

	//insert address of member variable to save RAX
	*(int32_t*)&controllFlowStub[13] = (int32_t)&savedRax_;
		
	//save original bytes
	originalBytes_ = new int8_t[hookLength];
	memcpy(originalBytes_, sourceAddress, hookLength);

	//copy stub to trampoline
	memcpy(trampoline_, stub, stubLength);
		

	//insert address of proxy function to call instruction
	*(int32_t*)&trampoline_[proxyFunctionAddressIndex + 1] = (int32_t)proxy - (int32_t)&trampoline_[proxyFunctionAddressIndex] - jmpStubLength;
	*(int32_t*)&trampoline_[thisAddress] = (int32_t)this; //insert this


	//save address after the stub so we can call the function without running into our hook again
	addressToCallFunctionWithoutHook_ = &trampoline_[stubLength + controlFlowStubLength];

	//copy controllFlow stub
	memcpy(&trampoline_[stubLength], controllFlowStub, controlFlowStubLength);

	//copy relocated original bytes to trampoline
	memcpy(&trampoline_[stubLength + controlFlowStubLength], relocatedBytes.data(), relocatedBytes.size());

	//copy relocated original bytes to trampoline_
	memcpy(&trampoline_[stubLength + controlFlowStubLength], relocatedBytes.data(), relocatedBytes.size());

	//copy jump back to original code
	memcpy(&trampoline_[stubLength + controlFlowStubLength + relocatedBytes.size()], stubJumpBack, jmpStubLength);



		
		
	//make trampoline executable
	DWORD pageProtection;
	VirtualProtect(trampoline_, stubLength + hookLength + jmpStubLength, PAGE_EXECUTE_READWRITE, &pageProtection);

	//make page of original code writeable
	VirtualProtect(sourceAddress, hookLength, PAGE_READWRITE, &pageProtection);

	//write jump from original code to trampoline
	sourceAddress[0] = 0xE9; //JMP
	*(int32_t*)&sourceAddress[1] = (int32_t)(trampoline_ - sourceAddress) - jmpStubLength;

	//NOP left over bytes
	for (int i = jmpStubLength; i < hookLength; i++)
	{
		sourceAddress[i] = 0x90;
	}

	//restore page protection of original code
	VirtualProtect(sourceAddress, hookLength, pageProtection, &pageProtection);
}
#endif
	
	/**
	 * Creates a hook.
	 *
	 * @param sourceAddress Address to apply the hook to
	 * @param proxy Function to be executed when hook is called
	 */
	Hook::Hook(int8_t* sourceAddress, void __fastcall proxy(context* ctx))
		: savedRax_(0)
	{
		Decoder decoder;

		//TODO we currently assume that we can reach the trampole with rel32.
		//TODO if that is not the case we also run into problems when relocation rip-relative instructions which have a rel32 displacement
		//TODO fixing those instructions is probably out of scope
		int lengthWithoutCuttingInstructionsInHalf = decoder.GetLengthOfInstructions(sourceAddress, 5);

		//remember hook address and length for unhooking
		this->hookLength_ = lengthWithoutCuttingInstructionsInHalf;
		this->sourceAddress_ = sourceAddress;

		//TODO issue trampoline_ is not wihthing range.. because we dont even try it to allocate it in range
		//TODO check fir rip relative instructions if we can reach original targets with rel32
		int64_t lowestRelativeAddress = 0;
		int64_t hightestRelativeAddress = 0;
		if(!decoder.CalculateBoundsOfRelativeAddresses(sourceAddress, lengthWithoutCuttingInstructionsInHalf, &lowestRelativeAddress, &hightestRelativeAddress))
		{
			printf("[Error] - FuncStartHook - Could not calculate bounds of relate instructions replaced by hook!\n");
			return;
		}

		printf("[Info] - FuncStartHook - bounds of relative addresses accessed [%llx, %llx]\n", lowestRelativeAddress, hightestRelativeAddress);

		//TODO get trampoline_ here (make sure +-2bg range from hook and in bounds
		AllocateTrampoline(sourceAddress);

		std::vector<int8_t> relocatedBytes = decoder.Relocate(sourceAddress, lengthWithoutCuttingInstructionsInHalf, trampoline_);
		if (relocatedBytes.empty())
		{
			printf("[Error] - FuncStartHook - Relocation of bytes replaced by hook failed\n");
		}
		
		//2. Get trampoline_ stub
		//3. Add rellocated instructions to trampoline_
		//4. Apply hook
		GenerateTrampolineAndApplyHook(sourceAddress, lengthWithoutCuttingInstructionsInHalf, relocatedBytes, proxy);
	}

	/**
	 * Get a version of the hooked function that can be called without recursively running in the hook again
	 *
	 * @return Address of function to call
	 */
	int8_t* Hook::GetCallableVersionOfOriginal()
	{
		return addressToCallFunctionWithoutHook_;
	}

	/**
	 * Restores the original function by copying back the original bytes of the hooked function that where overwritten by placing the hook.
	 */
	void Hook::Unhook()
	{
		//make page writeable
		DWORD dwback;
		VirtualProtect(sourceAddress_, hookLength_, PAGE_READWRITE, &dwback);

		//copy back original bytes
		memcpy(sourceAddress_, originalBytes_, hookLength_);

		//restore page protection
		VirtualProtect(sourceAddress_, hookLength_, dwback, &dwback);

		//clean up allocated memory
		delete[] originalBytes_;

		//memory leak but enables unhooking inside hooked function and makes it threadsafe?
		//delete[] trampoline_;
	}

	void Hook::ChangeReturn(int64_t returnValue)
	{
		returnAddressFromTrampoline_ = returnValue;
	}

	void Hook::SkipOriginalFunction()
	{
		//this is the location of the RET instruction at the end of the trampoline_
		//TODO hardcoding the size here at a random location is bad
		//this will cause the RET at the end of the trampoline (but before relocated instructions) to return to itself.
		//The next execution of the same RET instruciton will then take the return address pushed on the stack by the caller of the hooked funciton, therefore skipping the call.

#if _WIN64
		returnAddressFromTrampoline_ = (int64_t)(trampoline_ + 0x1be + hookLength_);
#elif _WIN32

		returnAddressFromTrampoline_ = (int64_t)(trampoline_ + 0xa9 + hookLength_);
#endif
	}
}
