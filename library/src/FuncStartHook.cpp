#include "FuncStartHook.h"

#include <cassert>

#include <Zydis/Zydis.h>
#include <Zydis/DecoderTypes.h>

namespace hookftw
{
	void FuncStartHook::GenerateTrampolineAndApplyHook(int8_t* sourceAddress, int hookLength, int8_t* rellocatedBytes,
		int rellocatedBytesLength, void proxy(context* ctx))
	{
		const int stubLength = 422;
		const int controlFlowStubLength = 33;
		const int proxyFunctionAddressIndex = 218;

		//const int saveRaxAddress = 180;
		const int thisAddress = 180;
		const int saveRspAddress = 196;
		const int restoreRspAddress = 230;

		//14 bytes are required to place JMP[rip+0x] 0x1122334455667788
		assert(hookLength >= 14);

		
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
			0x54,														//push	 rsp
			0x48, 0xB8, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,	//mov	 rax, this 
			0x50,														//push	 rax
			//0x48, 0x89, 0xE1,											//mov    rcx,rsp					//make first argument point at a
			0x48, 0x8D, 0x4C, 0x24, 0x0 ,								//lea    rcx,[rsp - 0x8] make first argument point at a
			0x48, 0xB8, 88, 77, 66, 55, 44, 33, 22, 11,					//mov	 rax, addressOfLocal			//save rsp
			0x48, 0x89, 0x20,											//mov	 [rax], rsp
			0x48, 0x0F, 0xBA, 0xF4, 0x03,								//btr	 rsp, 3						(align stack to 16 bytes before call)
			0x48, 0x83, 0xEC, 0x20,										//sub    rsp,0x20					(allocate shadow space)
			0x48, 0xB8, 88, 77, 66, 55, 44, 33, 22, 11,					//movabs rax,0x1122334455667788		(use register to have an absolute 8 byte call)
			0xFF, 0xD0,													//call   rax						(call proxy function)
			0x48, 0xB8, 88, 77, 66, 55, 44, 33, 22, 11,					//mov rax, addressOforiginalRspLocalVariable. We restore rsp like this because we don't know if stack was aligned to 16 byte beforehand
			0x48, 0x8B, 0x20,											//mov rsp, [rax]
			0x48, 0x83, 0xC4, 0x10,										//add    rsp,0x10	
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
		*(int64_t*)&controllFlowStub[2] = (int64_t)&savedRax;

		//save original bytes
		originalBytes = new int8_t[hookLength];
		memcpy(originalBytes, sourceAddress, hookLength);

		//allocate space for stub + space for RELLOCATED bytes + jumpback
		trampoline = (int8_t*)VirtualAlloc(NULL, stubLength + rellocatedBytesLength + controlFlowStubLength, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		
		returnAddressFromTrampoline = (int64_t)(trampoline + stubLength +  controlFlowStubLength);
		
		//insert address of the value to return code execution after hook
		*(int64_t*)&controllFlowStub[12] = (int64_t)&returnAddressFromTrampoline;

		//insert address of member variable to save RAX
		*(int64_t*)&controllFlowStub[24] = (int64_t)&savedRax;

		//remember hook address and length for unhooking
		this->hookLength = hookLength;
		this->sourceAddress = sourceAddress;

		//copy stub to trampoline
		memcpy(trampoline, stub, stubLength);
	
		//save address after the stub so we can call the function without running into our hook again
		addressToCallFunctionWithoutHook = &trampoline[stubLength + controlFlowStubLength];

		//copy jump back to original code
		memcpy(&trampoline[stubLength], controllFlowStub, controlFlowStubLength);
		
		//copy original bytes to trampoline
		memcpy(&trampoline[stubLength + controlFlowStubLength], rellocatedBytes, rellocatedBytesLength);

		const int stubJumpBackLength = 14;
		int8_t jmpBackStub[stubJumpBackLength] = {
			0xff, 0x25, 0x0, 0x0, 0x0,0x0,					//JMP[rip + 0]
			0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88	//absolute address of jump
		};
		*(int64_t*)&jmpBackStub[6] = (int64_t )&sourceAddress[hookLength];
		memcpy(&trampoline[stubLength + controlFlowStubLength + rellocatedBytesLength], jmpBackStub, stubJumpBackLength);

		//insert address of proxy function to call instruction
		*(int64_t*)&trampoline[thisAddress] = (int64_t)this;
		*(int64_t*)&trampoline[proxyFunctionAddressIndex] = (int64_t)proxy;
		*(int64_t*)&trampoline[saveRspAddress] = (int64_t)&originalRsp;
		*(int64_t*)&trampoline[restoreRspAddress] = (int64_t)&originalRsp;

		//write jump from trampoline to original code
		//*(int64_t*)&trampoline[stubLength + rellocatedBytesLength + 6] = (int64_t)&sourceAddress[hookLength];

		//make page of original code writeable
		DWORD pageProtection;
		VirtualProtect(sourceAddress, hookLength, PAGE_READWRITE, &pageProtection);

		//write JMP from original code to trampoline
		sourceAddress[0] = 0xFF;										//opcodes = JMP [rip+0]
		sourceAddress[1] = 0x25;										//opcodes = JMP [rip+0]
		*(uint32_t*)(&sourceAddress[2]) = 0;							//relative distance from RIP (+0) 
		*(uint64_t*)(&sourceAddress[2 + 4]) = (uint64_t)trampoline;		//destination to jump to

		//NOP left over bytes
		for (int i = 14; i < hookLength; i++)
		{
			sourceAddress[i] = 0x90;
		}

		//restore page protection of original code
		VirtualProtect(sourceAddress, hookLength, pageProtection, &pageProtection);
	}

	/**
	 * Creates a hook.
	 *
	 * @param sourceAddress Address to apply the hook to
	 * @param proxy Function to be executed when hook is called
	 */
	FuncStartHook::FuncStartHook(int8_t* sourceAddress, void proxy(context* ctx))
		: savedRax(0)
	{
		//1. rellocated instructions until we have minimum of 14 bytes
		int8_t relloInstr[1000]; //TODO fixed size
		ZyanU8* data = (ZyanU8*)sourceAddress;

		// Initialize decoder context
		ZydisDecoder decoder;
		ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
		ZyanUSize offset = 0;

		int relativeInstructions = 0;
		ZydisDecodedInstruction currentInstruction;
		int relloInstrOffset = 0;
		while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, data + offset, 15, &currentInstruction)) && offset < 14) //only need 14 bytes
		{
			int8_t* nextFreeByte = relloInstr + relloInstrOffset;
			if (currentInstruction.attributes & ZYDIS_ATTRIB_IS_RELATIVE)
			{
				ZyanU64 originalJumpTarget;
				ZydisCalcAbsoluteAddress(&currentInstruction, currentInstruction.operands, (ZyanU64)(data + offset), &originalJumpTarget);

				memcpy(nextFreeByte, data + offset, currentInstruction.length);
				nextFreeByte[1] = 0x2; //jump over. Change last byte.. this is hardcoded to instructions with 1 byte offset
				//
				//
				//jump after jcc instruction because jcc is not taken
				nextFreeByte[currentInstruction.length] = 0xEB;									//opcodes = JMP [rip+0]
				nextFreeByte[currentInstruction.length + 1] = 0xE;								//opcodes = JMP [rip+0]
				
				//jump for when jcc is taken
				nextFreeByte[currentInstruction.length + 2] = 0xFF;								//opcodes = JMP [rip+0]
				nextFreeByte[currentInstruction.length + 3] = 0x25;								//opcodes = JMP [rip+0]
				*(uint32_t*)&nextFreeByte[currentInstruction.length + 4] = 0;					//relative distance from RIP (+0) 
				*(uint64_t*)&nextFreeByte[currentInstruction.length + 8] = originalJumpTarget;	//destination to jump to

				relloInstrOffset += currentInstruction.length + 2 + 14;							//original instruction + 2x jmp [rip]; 8byteAddress
			}
			else
			{
				//Just copy
				memcpy(nextFreeByte, data + offset, currentInstruction.length);
				relloInstrOffset += currentInstruction.length;
			}
			offset += currentInstruction.length;
		}

		//2. Get trampoline stub
		//3. Add rellocated instructions to trampoline
		//4. Apply hook
		GenerateTrampolineAndApplyHook(sourceAddress, offset, relloInstr, relloInstrOffset, proxy);
	}

	/**
	 * Get a version of the hooked function that can be called without recursively running in the hook again
	 *
	 * @return Address of function to call
	 */
	int8_t* FuncStartHook::GetCallableVersionOfOriginal()
	{
		return addressToCallFunctionWithoutHook;
	}

	/**
	 * Restores the original function by copying back the original bytes of the hooked function that where overwritten by placing the hook.
	 */
	void FuncStartHook::Unhook()
	{
		//make page writeable
		DWORD dwback;
		VirtualProtect(sourceAddress, hookLength, PAGE_READWRITE, &dwback);

		//copy back original bytes
		memcpy(sourceAddress, originalBytes, hookLength);

		//restore page protection
		VirtualProtect(sourceAddress, hookLength, dwback, &dwback);

		//clean up allocated memory
		delete[] originalBytes;

		//memory leak but enables unhooking inside hooked function and makes it threadsafe?
		//delete[] trampoline;
	}

	void FuncStartHook::ChangeReturn(int64_t returnValue)
	{
		returnAddressFromTrampoline = returnValue;
	}

	void FuncStartHook::SkipOriginalFunction()
	{
		//this is the location of the RET instruction at the end of the trampoline
		returnAddressFromTrampoline = (int64_t)(trampoline + 0x1b5 + hookLength); 
	}
}
