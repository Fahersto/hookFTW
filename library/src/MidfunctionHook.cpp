#include "MidfunctionHook.h"

#include <cassert>
#include <vector>

#include <Zydis/Zydis.h>
#include <Zydis/DecoderTypes.h>

#include "Decoder.h"

namespace hookftw
{
#if _WIN64

	/**
	 * Populates the trampoline stubs and writes and hooks the target function by placing a JMP
	 *
	 * @param sourceAddress Address to apply the hook to
	 * @param hookLength amount of bytes to overwrite with the hook
	 * @param relocatedBytes relocated bytes overwritten by placing the hook JMP
	 * @param proxy Function to be executed when hook is called
	 */
	void MidfunctionHook::ApplyHook(int8_t* sourceAddress, int hookLength, std::vector<int8_t> relocatedBytes, void __fastcall proxy(context* ctx))
	{
		const int stubLength = 434;
		const int controlFlowStubLength = 33;
		const int proxyFunctionAddressIndex = 231;

		// address of RET is the last instruction in the control flow stub
		addressOfRET = trampoline_ + stubLength + controlFlowStubLength - 1;

		// compensates for all the changes to the stack before the proxy function is called
		// this way we get the rsp value time 
		const int rspCompenstaion = 400;

		const int thisAddress = 195;
		const int saveRspAddress = 209;
		const int restoreRspAddress = 243;

		int bytesRequiredForPlacingHook = 0;

		// restrictedRelocation_ is true when the trampoline could not be allocated withing +-2GB range
		if (restrictedRelocation_)
		{
			// 14 bytes are required to place JMP[rip+0x] 0x1122334455667788
			bytesRequiredForPlacingHook = 14;
		}
		else
		{
			// 5 bytes for jmp rel32
			bytesRequiredForPlacingHook = 5;
		}

		// ensure we got the hooklength needed to place the required jump
		assert(hookLength >= bytesRequiredForPlacingHook);

		// 1. save xmm registers
		// 2. save general purpose registers
		// 3. align the stack to 16 bytes
		// 4. call proxy function
		// 5. restore all registers
		// 6. jump back to orignal function
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

			// calculcate RSP at time of call (the trampoline has already modified the rsp by all these pushes)
			0x48, 0x83, 0xEC, 0x08,										//sub    rsp,0x8
			0x48, 0x89, 0xE0,											//mov    rax,rsp
			0x48, 0x05, 0x88, 0x01, 0x00, 0x00,							//add    rax,0x188
			0x48, 0x89, 0x04, 0x24,										//mov    QWORD PTR [rsp],rax	

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
			0x48, 0x83, 0xC4, 0x10,										//add    rsp, 0x10	//compensate for the "push rax" before saving rspand for not popping the calculating RSP at the time of hooking back
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

		// used to the controll flow after the hook can be changed (for example skip oroginal call)
		int8_t controllFlowStub[controlFlowStubLength] = {
			0x48, 0xA3, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,	//movabs ds:0x1122334455667788,rax
			0x48, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,	//movabs rax,0x1122334455667788
			0xFF, 0x30,													//push   QWORD PTR [rax]
			0x48, 0xA1, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,	//movabs rax, [0x1122334455667788]  addr. of local saved rax
			0xC3														//ret
		};
		*(int64_t*)&controllFlowStub[2] = (int64_t)&savedRax_;

		// save original bytes
		originalBytes_ = new int8_t[hookLength];
		memcpy(originalBytes_, sourceAddress, hookLength);

		returnAddressFromTrampoline_ = (int64_t)(trampoline_ + stubLength + controlFlowStubLength);

		// insert address of the value to return code execution after hook
		*(int64_t*)&controllFlowStub[12] = (int64_t)&returnAddressFromTrampoline_;

		// insert address of member variable to save RAX
		*(int64_t*)&controllFlowStub[24] = (int64_t)&savedRax_;

		// copy stub to trampoline_
		memcpy(trampoline_, stub, stubLength);

		// save address after the stub so we can call the function without running into our hook again
		addressToCallFunctionWithoutHook_ = &trampoline_[stubLength + controlFlowStubLength];

		// copy controllFlow stub
		memcpy(&trampoline_[stubLength], controllFlowStub, controlFlowStubLength);

		// copy relocated original bytes to trampoline
		memcpy(&trampoline_[stubLength + controlFlowStubLength], relocatedBytes.data(), relocatedBytes.size());

		// in x64bit we always do an absolute 8 byte jump. This way the trampoline does not need to be in +-2bg range.
		// in such cases relocation of rip-relative instructions is not supported
		const int stubJumpBackLength = 14;
		int8_t jmpBackStub[stubJumpBackLength] = {
			0xff, 0x25, 0x0, 0x0, 0x0,0x0,					//JMP[rip + 0]
			0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88	//absolute address of jump
		};

		// write jump from trampoline_ to original code
		*(int64_t*)&jmpBackStub[6] = (int64_t)&sourceAddress_[hookLength];
		memcpy(&trampoline_[stubLength + controlFlowStubLength + relocatedBytes.size()], jmpBackStub, stubJumpBackLength);

		// insert address of proxy function to call instruction
		*(int64_t*)&trampoline_[thisAddress] = (int64_t)this;
		*(int64_t*)&trampoline_[proxyFunctionAddressIndex] = (int64_t)proxy;
		*(int64_t*)&trampoline_[saveRspAddress] = (int64_t)&originalRsp_;
		*(int64_t*)&trampoline_[restoreRspAddress] = (int64_t)&originalRsp_;

		// make page of original code writeable
		DWORD pageProtection;
		VirtualProtect(sourceAddress, hookLength, PAGE_READWRITE, &pageProtection);

		if (restrictedRelocation_)
		{
			const int stubJumpToTrampolineLength = 14;
			int8_t jmpToTrampolineStub[stubJumpToTrampolineLength] = {
				0xff, 0x25, 0x0, 0x0, 0x0,0x0,					//JMP[rip + 0]
				0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88	//absolute address of jump
			};
			*(int64_t*)&jmpToTrampolineStub[6] = (int64_t)trampoline_;
			memcpy(sourceAddress, jmpToTrampolineStub, stubJumpToTrampolineLength);
		}
		else
		{
			// write JMP from original code to trampoline_
			sourceAddress[0] = 0xe9;							//opcodes = JMP rel32
			*(uint32_t*)(&sourceAddress[1]) = (int32_t)((int64_t)trampoline_ - (int64_t)sourceAddress - 5);
		}

		// NOP left over bytes to improve readability of resulting assembly
		for (int i = bytesRequiredForPlacingHook; i < hookLength; i++)
		{
			sourceAddress[i] = 0x90;
		}

		// restore page protection of original code
		VirtualProtect(sourceAddress, hookLength, pageProtection, &pageProtection);
	}
#elif _WIN32
	/**
	 * Populates the trampoline stubs and writes and hooks the target function by placing a JMP
	 *
	 * @param sourceAddress Address to apply the hook to
	 * @param hookLength amount of bytes to overwrite with the hook
	 * @param relocatedBytes relocated bytes overwritten by placing the hook JMP
	 * @param proxy Function to be executed when hook is called
	 */
	void MidfunctionHook::ApplyHook(int8_t* sourceAddress, int hookLength, std::vector<int8_t> relocatedBytes, void __fastcall proxy(context* ctx))
	{
		const int stubLength = 173;
		const int controlFlowStubLength = 18;
		const int proxyFunctionAddressIndex = 93;

		const int thisAddress = 86;

		const int jmpStubLength = 5;

		// address of RET is the last instruction in the control flow stub
		addressOfRET = trampoline_ + stubLength + controlFlowStubLength - 1;

		// 5 bytes are required to place JMP 0x11223344
		assert(hookLength >= jmpStubLength);

		// 1. save all registers
		// 2. call proxy function
		// 3. restore all registers
		// 4. jump back to orignal function
		BYTE stub[stubLength] = {
			0x9c,							//pushfd
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

			//"push" calculated esp on hook beginnign (make up for all the changes to esp in this trampoline so far)
			0x83, 0xEC, 0x04,				//sub    esp,0x4
			0x89, 0xE0,						//mov    eax,esp
			0x05, 0xA4, 0x00, 0x00, 0x00,	//add    eax,0xA4
			0x89, 0x04, 0x24,				//mov    DWORD PTR [esp],eax

			0xB8, 0x44, 0x33, 0x22, 0x11,	//mov	 eax, this 
			0x50,							//push	 eax

			0x89, 0xE1,						//mov    ecx,esp
			0xE8, 0x44, 0x33, 0x22, 0x11,	//call   11223344

			//comptensate for not popping recalulated esp and pushing Hook thisptr
			0x83, 0xC4, 0x08,				//add    esp,0x8

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
			0x83, 0xC4, 0x10,				//add    esp,0x10
			0x9d							//popfd	
		};

		BYTE stubJumpBack[jmpStubLength] = { 0xE9, 0x11, 0x22, 0x33, 0x44 };	//jmp 1122335a (back to original code)

		// write jump from trampoline to original code
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

		// insert address of the value to return code execution after hook
		*(int32_t*)&controllFlowStub[6] = (int32_t)&returnAddressFromTrampoline_;

		// insert address of member variable to save RAX
		*(int32_t*)&controllFlowStub[13] = (int32_t)&savedRax_;

		// save original bytes
		originalBytes_ = new int8_t[hookLength];
		memcpy(originalBytes_, sourceAddress, hookLength);

		// copy stub to trampoline
		memcpy(trampoline_, stub, stubLength);

		// insert address of proxy function to call instruction
		*(int32_t*)&trampoline_[proxyFunctionAddressIndex + 1] = (int32_t)proxy - (int32_t)&trampoline_[proxyFunctionAddressIndex] - jmpStubLength;
		*(int32_t*)&trampoline_[thisAddress] = (int32_t)this; //insert this

		// save address after the stub so we can call the function without running into our hook again
		addressToCallFunctionWithoutHook_ = &trampoline_[stubLength + controlFlowStubLength];

		// copy controllFlow stub
		memcpy(&trampoline_[stubLength], controllFlowStub, controlFlowStubLength);

		// copy relocated original bytes to trampoline
		memcpy(&trampoline_[stubLength + controlFlowStubLength], relocatedBytes.data(), relocatedBytes.size());

		// copy relocated original bytes to trampoline_
		memcpy(&trampoline_[stubLength + controlFlowStubLength], relocatedBytes.data(), relocatedBytes.size());

		// copy jump back to original code
		memcpy(&trampoline_[stubLength + controlFlowStubLength + relocatedBytes.size()], stubJumpBack, jmpStubLength);

		// make trampoline executable
		DWORD pageProtection;
		VirtualProtect(trampoline_, stubLength + hookLength + jmpStubLength, PAGE_EXECUTE_READWRITE, &pageProtection);

		// flush instruction cache for new executable region to ensure cache coherency
		FlushInstructionCache(GetModuleHandle(NULL), trampoline_, stubLength + controlFlowStubLength + relocatedBytes.size()  + jmpStubLength);

		// make page of original code writeable
		VirtualProtect(sourceAddress, hookLength, PAGE_READWRITE, &pageProtection);

		// write jump from original code to trampoline
		sourceAddress[0] = 0xE9; //JMP
		*(int32_t*)&sourceAddress[1] = (int32_t)(trampoline_ - sourceAddress) - jmpStubLength;

		// NOP left over bytes
		for (int i = jmpStubLength; i < hookLength; i++)
		{
			sourceAddress[i] = 0x90;
		}

		// restore page protection of original code
		VirtualProtect(sourceAddress, hookLength, pageProtection, &pageProtection);
	}
#endif
	MidfunctionHook::MidfunctionHook()
		: savedRax_(0)
	{
#ifdef _WIN64
		// stub + controlFlow
		// TODO avoid defining the same constants multiple times
		staticTrampolineLength_ = 434 + 33;
#elif _WIN32
		staticTrampolineLength_ = 173 + 18;
#endif
	}

	/**
	 * Creates a midfunction hook.
	 *
	 * @param sourceAddress Address to apply the hook to
	 * @param proxy Function to be executed when hook is called
	 */
	void MidfunctionHook::Hook(int8_t* sourceAddress, void __fastcall proxy(context* ctx))
	{
		this->sourceAddress_ = sourceAddress;
		
		Decoder decoder;
		trampoline_ = decoder.HandleTrampolineAllocation(sourceAddress, &restrictedRelocation_);
		if (!trampoline_)
		{
			return;
		}

		this->hookLength_ = decoder.GetLengthOfInstructions(sourceAddress, 5);

#ifdef _WIN64
		if (restrictedRelocation_)
		{
			// restricted relocation means that we couldn't allocate the trampoline within +-2GB range
			// for 64 bit we can still hook using an aboslute jmp that requires 14 bytes
			this->hookLength_ = decoder.GetLengthOfInstructions(sourceAddress, 14);
		}
#endif
		// the trampoline has a part with static length (save registers, call proxy, restore registers, control flow) followed by a part with dynamic length (relocated bytes).
		// we need to know where the dynamic parts start to relocate rip-relative memory accesses
		int8_t* startOfRelocation = trampoline_ + staticTrampolineLength_ + 1;

		std::vector<int8_t> relocatedBytes = decoder.Relocate(sourceAddress, this->hookLength_, startOfRelocation, restrictedRelocation_);
		if (relocatedBytes.empty())
		{
			printf("[Error] - MidfunctionHook - Relocation of bytes replaced by hook failed\n");
			return;
		}
		//Fills the newly allocated trampoline with instructions and redirects the code flow to it 
		ApplyHook(sourceAddress, this->hookLength_, relocatedBytes, proxy);
	}


	/**
	 * Get a version of the hooked function that can be called without recursively running in the hook again
	 *
	 * @return Address of function to call
	 */
	int8_t* MidfunctionHook::GetCallableVersionOfOriginal()
	{
		return addressToCallFunctionWithoutHook_;
	}

	/**
	 * Restores the original function by copying back the original bytes of the hooked function that where overwritten by placing the hook.
	 */
	void MidfunctionHook::Unhook()
	{
		// make page writeable
		DWORD dwback;
		VirtualProtect(sourceAddress_, hookLength_, PAGE_READWRITE, &dwback);

		// copy back original bytes
		memcpy(sourceAddress_, originalBytes_, hookLength_);

		// restore page protection
		VirtualProtect(sourceAddress_, hookLength_, dwback, &dwback);

		// clean up allocated memory
		delete[] originalBytes_;

		// clean up memory. This is why we can't unhook from inside the hooked function.
		delete[] trampoline_;
	}

	void MidfunctionHook::ChangeReturn(int64_t returnValue)
	{
		returnAddressFromTrampoline_ = returnValue;
	}

	/**
	 * Skips the invocation of the original call of the hooked function by executing a RET instruction to return the the hooked functions caller.
	 */
	void MidfunctionHook::SkipOriginalFunction()
	{
		// this is the location of the RET instruction at the end of the trampoline_
		// this will cause the RET at the end of the trampoline (but before relocated instructions) to return to itself.
		// the next execution of the same RET instruciton will then take the return address pushed on the stack by the caller of the hooked funciton, therefore skipping the call.
		returnAddressFromTrampoline_ = (int64_t)addressOfRET;
	}
}
