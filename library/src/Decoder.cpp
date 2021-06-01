#include "Decoder.h"


#include <cstdio>
#include <Zydis/Zydis.h>


namespace hookftw
{
	void* Decoder::_zydisDecoder = nullptr;
	
	bool IsBranchInstruction(ZydisDecodedInstruction& instruction)
	{
		switch (instruction.mnemonic)
		{
		case ZYDIS_MNEMONIC_JB:
		case ZYDIS_MNEMONIC_JBE:
		case ZYDIS_MNEMONIC_JCXZ:
		case ZYDIS_MNEMONIC_JECXZ:
		case ZYDIS_MNEMONIC_JKNZD:
		case ZYDIS_MNEMONIC_JKZD:
		case ZYDIS_MNEMONIC_JL:
		case ZYDIS_MNEMONIC_JLE:
		case ZYDIS_MNEMONIC_JMP:
		case ZYDIS_MNEMONIC_JNB:
		case ZYDIS_MNEMONIC_JNBE:
		case ZYDIS_MNEMONIC_JNL:
		case ZYDIS_MNEMONIC_JNLE:
		case ZYDIS_MNEMONIC_JNO:
		case ZYDIS_MNEMONIC_JNP:
		case ZYDIS_MNEMONIC_JNS:
		case ZYDIS_MNEMONIC_JNZ:
		case ZYDIS_MNEMONIC_JO:
		case ZYDIS_MNEMONIC_JP:
		case ZYDIS_MNEMONIC_JRCXZ:
		case ZYDIS_MNEMONIC_JS:
		case ZYDIS_MNEMONIC_JZ:
		case ZYDIS_MNEMONIC_LOOP:
		case ZYDIS_MNEMONIC_LOOPE:
		case ZYDIS_MNEMONIC_LOOPNE:
			return true;
		default:
			return false;
		}
	}

	bool IsRipRelativeMemoryInstruction(ZydisDecodedInstruction& instruction)
	{
		//https://software.intel.com/content/www/us/en/develop/download/intel-64-and-ia-32-architectures-sdm-combined-volumes-2a-2b-2c-and-2d-instruction-set-reference-a-z.html
		return instruction.attributes & ZYDIS_ATTRIB_HAS_MODRM && instruction.raw.modrm.mod == 0 && instruction.raw.modrm.rm == 5;
	}


	void RelocateCallInstruction(ZydisDecodedInstruction& instruction, int8_t* instructionAddress, std::vector<int8_t>& rellocatedbytes)
	{
		ZyanU64 originalJumpTarget;
		ZydisCalcAbsoluteAddress(&instruction, instruction.operands, (ZyanU64)instructionAddress, &originalJumpTarget);

		const int rellocatedCallInstructionsLength = 12;
		int8_t rellocatedCallInstructions[rellocatedCallInstructionsLength] = {
			0x48, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,			//movabs rax, 0x1122334455667788
			0xFF, 0xD0															//call   rax
		};
		*(uint64_t*)&rellocatedCallInstructions[2] = originalJumpTarget;
		rellocatedbytes.insert(rellocatedbytes.end(), rellocatedCallInstructions, rellocatedCallInstructions + rellocatedCallInstructionsLength);

		//the program can return to the return address pushed on the stack (at time of the call) at any time.
		//if the hook is removed (and therefore the trampoline freed) the return address might not contain valid code --> crash
		printf("[Warning] - Decoder relocated a call instruction. Unhooking is not safe!\n");
	}

	void RelocateBranchInstruction(ZydisDecodedInstruction& instruction, int8_t* instructionAddress, std::vector<int8_t>& rellocatedbytes)
	{
		ZyanU64 originalJumpTarget;
		ZydisCalcAbsoluteAddress(&instruction, instruction.operands, (ZyanU64)instructionAddress, &originalJumpTarget);

		rellocatedbytes.insert(rellocatedbytes.end(), instructionAddress, instructionAddress + instruction.length);
		rellocatedbytes[rellocatedbytes.size() - 1] = 0x2;

		const int elementSizeInBytes = instruction.operands[0].element_size / 8;
		//suppport jcc rel8, jcc rel16, jcc rel32. JCC always has the offset in its first operand. Fill remmaining bytes with '0'
		for (int i = 0; i < elementSizeInBytes - 1; i++)
		{
			rellocatedbytes.push_back(0x0);
		}

		//jmp after jcc instruction because jcc is not taken
		rellocatedbytes.push_back(0xEB);			//jmp    0x10
		rellocatedbytes.push_back(0xE);				//

		//jmp for when jcc is taken
		rellocatedbytes.push_back(0xFF);			//opcodes = JMP [rip+0]
		rellocatedbytes.push_back(0x25);			//
		rellocatedbytes.push_back(0x0);				//
		rellocatedbytes.push_back(0x0);				//
		rellocatedbytes.push_back(0x0);				//
		rellocatedbytes.push_back(0x0);				//

		rellocatedbytes.insert(rellocatedbytes.end(), &originalJumpTarget, &originalJumpTarget + 8); //destination to jump to: 8 Bytes
		printf("[Info] - Decoder relocated a branch instruction\n");
	}

	void RelocateRipRelativeMemoryInstruction(ZydisDecodedInstruction& instruction, int8_t* instructionAddress, std::vector<int8_t>& rellocatedbytes)
	{
		const int8_t* absoluteAddress = instructionAddress + instruction.length + instruction.raw.disp.value;

		ZyanU64 originalJumpTarget;
		ZydisCalcAbsoluteAddress(&instruction, instruction.operands, (ZyanU64)instructionAddress, &originalJumpTarget);

		//the displacement is always 32byte displacement. (instruction.instruction.raw.disp.size

		//TODO check if we could sucessfully rellocate (if trampoline is too far away rel32 may not be enough)

		printf("[Info] - Decoder rellocated a rip-relative memory instruction NOT IMPLEMENTED\n");
		printf("\tabsoluteAddress %p, originalJumpTarget %llx\n", absoluteAddress, originalJumpTarget);
	}

	Decoder::Decoder()
	{
		static ZydisDecoder decoder; 
		if (!_zydisDecoder)
		{
			_zydisDecoder = &decoder;
#ifdef _WIN64
			ZyanStatus status = ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
#elif _WIN32
			ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_ADDRESS_WIDTH_32);
#else
			printf("Error: Unsupported decoder architecture\n");
#endif
		}
	}

	/* Instructions that need to be rellocated
	 * 32bit:
		- call
		- jcc
		- loopne
		- XBEGIN

	   64bit:
		-call
		- jcc
		- loopne
		- XBEGIN
		- instructions that use ModR / M addressing(rip relative)
	 */
	std::vector<int8_t> Decoder::Relocate(int8_t* source, int length)
	{
		const int MAXIMUM_INSTRUCTION_LENGTH = 15;
		std::vector<int8_t> relocatedbytes;

		int amountOfBytesRellocated = 0;

		//we will atleast rellocate "length" bytes. To avoid splitting an instruction we might rellocate more.
		while (amountOfBytesRellocated < length)
		{
			ZydisDecodedInstruction instruction;
			int8_t* currentAddres = source + amountOfBytesRellocated;
			
			ZyanStatus decodeResult = ZydisDecoderDecodeBuffer((ZydisDecoder*)_zydisDecoder, currentAddres, MAXIMUM_INSTRUCTION_LENGTH, &instruction);
			if (decodeResult != ZYAN_STATUS_SUCCESS)
			{
				printf("ERROR: decoder could not decode instruction\n");
				return std::vector<int8_t>();
			}
			if (instruction.mnemonic == ZYDIS_MNEMONIC_CALL) 
			{
				//handle relocation of call instructions
				RelocateCallInstruction(instruction, currentAddres, relocatedbytes);
			}
			else if (IsBranchInstruction(instruction))	
			{
				//handle relocation of branch instructions (jcc, loopcc)
				RelocateBranchInstruction(instruction, currentAddres, relocatedbytes);
			}
			else if (IsRipRelativeMemoryInstruction(instruction))	
			{
				//handle relocation of rip-relative memory addresses (x64 only)
				RelocateRipRelativeMemoryInstruction(instruction, currentAddres, relocatedbytes);
			}
			else
			{
				//if its just copy the original bytes
				relocatedbytes.insert(relocatedbytes.end(), currentAddres, currentAddres + instruction.length);
			}
			amountOfBytesRellocated += instruction.length;
		}
		return relocatedbytes;
	}
}