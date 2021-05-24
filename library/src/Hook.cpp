#include "Hook.h"

#include "Disassembler.h"

#include <cassert>

#include <Zydis/Zydis.h>
#include <Zydis/DecoderTypes.h>

namespace hookftw
{
	void Hook::GenerateTrampolineAndApplyHook(int8_t* sourceAddress, int hookLength, std::vector<int8_t> rellocatedBytes, void __fastcall proxy(registers* registers))
	{
		const int stubLength = 404;
		const int stubJumpBackLength = 14;
		const int proxyFunctionAddressIndex = 204;

		const int saveRspAddress = 182;
		const int restoreRspAddress = 216;

		int64_t originalRsp = 0;

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
			
			0x48, 0x89, 0xE1,											//mov    rcx,rsp					(first arg = registers on stack (fastcall))
			
			0x48, 0xB8, 88, 77, 66, 55, 44, 33, 22, 11,					//mov rax, addressOfLocal  //save rsp
			0x48, 0x89, 0x20,											//mov [rax], rsp
			0x48, 0x0F, 0xBA, 0xF4, 0x03,								//btr	 rsp, 3						(align stack to 16 bytes before call)
			0x48, 0x83, 0xEC, 0x20,										//sub    rsp,0x20					(allocate shadow space)
			0x48, 0xB8, 88, 77, 66, 55, 44, 33, 22, 11,					//movabs rax,0x1122334455667788		(use register to have an absolute 8 byte call)
			0xFF, 0xD0,													//call   rax						(call proxy function)
			0x48, 0xB8, 88, 77, 66, 55, 44, 33, 22, 11,					//mov rax, addressOforiginalRspLocalVariable. We restore rsp like this because we don't know if stack was aligned to 16 byte beforehand
			0x48, 0x8B, 0x20,											//mov rsp, [rax]
			
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
			0x48, 0x83, 0xC4, 0x10,										//add    rsp,0x10
			0x9D														//popfq
		};

		int8_t stubJumpBack[stubJumpBackLength] = {
			0xff, 0x25, 0x0, 0x0, 0x0,0x0,					//JMP[rip + 0]
			0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88	//absolute address of jump
		};

		//remember for unhooking
		this->hookLength = hookLength;
		this->sourceAddress = sourceAddress;

		//save original bytes
		originalBytes = new int8_t[hookLength];
		memcpy(originalBytes, sourceAddress, hookLength);

		//copy stub to trampoline
		memcpy(trampoline, stub, stubLength);

		//copy original bytes to trampoline
		memcpy(&trampoline[stubLength], rellocatedBytes.data(), rellocatedBytes.size());

		//copy jump back to original code
		memcpy(&trampoline[stubLength + rellocatedBytes.size()], stubJumpBack, stubJumpBackLength);

		//insert address of proxy function to call instruction
		*(int64_t*)&trampoline[proxyFunctionAddressIndex] = (int64_t)proxy;
		*(int64_t*)&trampoline[saveRspAddress] = (int64_t)&originalRsp;
		*(int64_t*)&trampoline[restoreRspAddress] = (int64_t)&originalRsp;

		//write jump from trampoline to original code
		*(int64_t*)&trampoline[stubLength + rellocatedBytes.size() + 6] = (int64_t)&sourceAddress[hookLength];

		//make page of original code writeable
		DWORD pageProtection;
		VirtualProtect(sourceAddress, hookLength, PAGE_READWRITE, &pageProtection);


		int jumpToTrampolineLength = 5;
		const int jmpRel32ByteSize = 5; //JMP rel32
		if (abs((int64_t)trampoline - (int64_t)sourceAddress) < 2147483647 - jmpRel32ByteSize)
		{
			//write JMP rel32
			sourceAddress[0] = 0xe9;						
			*(uint32_t*)(&sourceAddress[1]) = (int32_t)((int64_t)trampoline - (int64_t)sourceAddress - 5);
		}
		else
		{
			jumpToTrampolineLength = 14;
			//write JMP from original code to trampoline
			sourceAddress[0] = 0xFF;										//opcodes = JMP [rip+0]
			sourceAddress[1] = 0x25;										//opcodes = JMP [rip+0]
			*(uint32_t*)(&sourceAddress[2]) = 0;							//relative distance from RIP (+0) 
			*(uint64_t*)(&sourceAddress[2 + 4]) = (uint64_t)trampoline;		//destination to jump to (-5 for JMP rel32 instruction size)
		}


		//NOP left over bytes
		for (int i = jumpToTrampolineLength; i < hookLength; i++)
		{
			sourceAddress[i] = 0x90;
		}

		//restore page protection of original code
		VirtualProtect(sourceAddress, hookLength, pageProtection, &pageProtection);
	}

#if _WIN32
	/**
	* Hooks a function at the given address.
	*
	* \note This function is not threadsafe. If the function that is being hooked is running the instructions that are replaced for hooking the behavior is undefined and the application is likely to crash.
	* \warning Places that can't be hooked currently:
	*	- Locations where the original binary jumps to
	*	- Locations where instruction would have to be rellocated
	* @param sourceAddress Address to apply the hook to
	* @param proxy Function callback to be executed when hook is called
	*/
	Hook::Hook(int8_t* sourceAddress, void __fastcall proxy(registers* regs))
		: originalBytes(nullptr), sourceAddress(nullptr), trampoline(nullptr), hookLength(0)
	{
		const int stubLength = 151;
		const int stubJumpBackLength = 5;
		const int indexOfAddressOfCall = 74;
		const int jmpInstructionLength = 5;


		ZydisDecoder decoder;
		ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_ADDRESS_WIDTH_32);
		ZyanUSize offset = 0;

		ZydisDecodedInstruction currentInstruction;

		//decode instructions until >= 5 bytes are reached (JMP 0x11223344), so we don't cut instructions in half
		while (offset < jmpInstructionLength)
		{
			if (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, sourceAddress + offset, 15, &currentInstruction)))
			{
				offset += currentInstruction.length;
			}
			else
			{
				printf("ERROR: Couldn't disassemble address %llx\n", sourceAddress + offset);
				return;
			}
		}

		hookLength = offset;

		//5 bytes are required to place JMP 0x11223344
		assert(hookLength >= stubJumpBackLength);

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
			0x89, 0xE1,						//mov    ecx,esp
			0xE8, 0x44, 0x33, 0x22, 0x11,	//call   11223344
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

		BYTE stubJumpBack[stubJumpBackLength] = { 0xE9, 0x84, 0x77, 0x66, 0x55 };	//jmp 1122335a (back to original code)

		//remember for unhooking
		this->hookLength = hookLength;
		this->sourceAddress = sourceAddress;

		//save original bytes
		originalBytes = new int8_t[hookLength];
		memcpy(originalBytes, sourceAddress, hookLength);
		
		//allocate space for stub + space for overwritten bytes + jumpback
		//in 32bit we expect to always be able to jump to the trampoline and back to the original code with a JMP rel32. Is this assumnption correct?
		trampoline = (int8_t*)VirtualAlloc(NULL, stubLength + hookLength + stubJumpBackLength, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		
		//copy stub to trampoline
		memcpy(trampoline, stub, stubLength);

		//copy original bytes to trampoline
		memcpy(&trampoline[stubLength], originalBytes, hookLength);

		//copy jump back to original code
		memcpy(&trampoline[stubLength + hookLength], stubJumpBack, hookLength);

		//insert address of proxy function to call instruction
		*(int32_t*)&trampoline[indexOfAddressOfCall + 1] = (int32_t)proxy - (int32_t)&trampoline[indexOfAddressOfCall] - jmpInstructionLength;

		//write jump from trampoline to original code
		*(int32_t*)&trampoline[stubLength + hookLength + 1] = (int32_t)&sourceAddress[hookLength] - (int32_t)&trampoline[stubLength + hookLength] - jmpInstructionLength;

		//make trampoline executable
		DWORD pageProtection;
		VirtualProtect(trampoline, stubLength + hookLength + stubJumpBackLength, PAGE_EXECUTE_READWRITE, &pageProtection);

		//make page of original code writeable
		VirtualProtect(sourceAddress, hookLength, PAGE_READWRITE, &pageProtection);

		//write jump from original code to trampoline
		sourceAddress[0] = 0xE9; //JMP
		*(int32_t*)&sourceAddress[1] = (int32_t)(trampoline - sourceAddress) - jmpInstructionLength;

		//NOP left over bytes
		for (int i = stubJumpBackLength; i < hookLength; i++)
		{
			sourceAddress[i] = 0x90;
		}

		//restore page protection of original code
		VirtualProtect(sourceAddress, hookLength, pageProtection, &pageProtection);
	}
#elif _WIN64
	/**
	 * Hooks a function at the given address.
	 *
	 * \note This function is not threadsafe. If the function that is being hooked is running the instructions that are replaced for hooking the behavior is undefined and the application is likely to crash.
	 * \warning Places that can't be hooked currently:
	 *	- Locations where the original binary jumps to
	 *	- RIP relative memory instructions (mov, lea)
	 * @param sourceAddress Address to apply the hook to
	 * @param proxy Function callback to be executed when hook is called
	 */
	Hook::Hook(int8_t* sourceAddress, void __fastcall proxy(registers* regs))
		: originalBytes(nullptr), sourceAddress(nullptr), trampoline(nullptr), hookLength(0)
	{
		int requiredBytes = 5;

		//allocate the trampoline. We need to allocate this first so we know how many bytes we need to overwrite (5 or 14 Bytes)
		SYSTEM_INFO systemInfo;
		GetSystemInfo(&systemInfo);
		int allocationAttemps = 0;
		while (!trampoline)
		{
			//TODO is this calculation correct?
			int8_t* targetAddress = sourceAddress + 2147483647 - (allocationAttemps++ * systemInfo.dwPageSize);
			if (targetAddress > 0)
			{
				//Try to allocate trampoline within "JMP rel32" range so we can hook by overwriting 5 Bytes instead of 14 Bytes
				trampoline = (int8_t*)VirtualAlloc(targetAddress, systemInfo.dwPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			}
			else
			{
				//If we couldn't allocate within +-2GB range let the system allocate the memory page anywhere and use and absolute jump. JMP [RIP+0] 0x1122334455667788 (14 Bytes)
				trampoline = (int8_t*)VirtualAlloc(NULL, systemInfo.dwPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
				requiredBytes = 14;
			}
		}

		//1. rellocated instructions until we reached the requiredBytes (5 or 14 Bytes)
		// Initialize decoder context
		ZydisDecoder decoder;
		ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
		ZyanUSize offset = 0;

		ZydisDecodedInstruction currentInstruction;

		std::vector<int8_t> rellocatedBytes;
		while (offset < requiredBytes)
		{
			if (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, sourceAddress + offset, 15, &currentInstruction)))
			{
				if (currentInstruction.attributes & ZYDIS_ATTRIB_IS_RELATIVE)
				{
					Disassembler::RellocateInstruction(currentInstruction, sourceAddress + offset, rellocatedBytes);
				}
				else
				{
					//just copy the original bytes
					rellocatedBytes.insert(rellocatedBytes.end(), sourceAddress + offset, sourceAddress + offset + currentInstruction.length);
				}
				offset += currentInstruction.length;
			}
			else
			{
				printf("ERROR: Couldn't disassemble address %llx\n", sourceAddress + offset);
				return;
			}
		}

		//2. Get trampoline stub
		//3. Add rellocated instructions to trampoline
		//4. Apply hook
		GenerateTrampolineAndApplyHook(sourceAddress, offset, rellocatedBytes, proxy);
	}
#endif
	/**
	 * Restores the original function by copying back the original bytes of the hooked function that where overwritten by placing the hook.
	 *
	 * \note This function is not threadsafe. If the function that is being hooked is running the instructions that are replaced for unhooking the behavior is undefined and the application is likely to crash.
	 */
	void Hook::Unhook()
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

		SYSTEM_INFO systemInfo;
		GetSystemInfo(&systemInfo);
		
		//memory leak but enables unhooking inside hooked function and makes it threadsafe?
		VirtualFree(trampoline, systemInfo.dwPageSize, MEM_RELEASE);
	}
}
