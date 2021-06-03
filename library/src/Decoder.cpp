#include "Decoder.h"


#include <cstdio>
#include <Zydis/Zydis.h>


namespace hookftw
{
	void* Decoder::_zydisDecoder = nullptr;

	bool IsCallInstruction(ZydisDecodedInstruction& instruction)
	{
		return instruction.mnemonic == ZYDIS_MNEMONIC_CALL;
	}
	
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
		//Table 2-2. 32-Bit Addressing Forms with the ModR/M Byte 
		return instruction.attributes & ZYDIS_ATTRIB_HAS_MODRM && 
			instruction.raw.modrm.mod == 0 && instruction.raw.modrm.rm == 5; //disp32 see table
	}

	void RelocateCallInstruction(ZydisDecodedInstruction& instruction, int8_t* instructionAddress, std::vector<int8_t>& rellocatedbytes)
	{
		//TODO check if all types of calls can be relocated
		//TODO there are for example call instructions that make use of  the ModRM byte
		//TODO Call gate is a problem for now

		//for e8 call use ZydisCalcAbsoluteAddress
		//copy all other calls with the expection of
		//	- Mod 00, RM 101
		//  - these only occur with digit /2 & /3, so mod/rm values of 0x15 & 0x1D
		//		- from looking at the table these always seems to derefernce the address
		ZyanU64 originalJumpTarget;
		if (instruction.attributes & ZYDIS_ATTRIB_HAS_MODRM)
		{
			//FF /3 CALL m16:32
			if (instruction.raw.modrm.mod == 0)
			{
				if (instruction.raw.modrm.rm == 5) //disp32 see ModR/M table (intel manual)
				{
					ZydisCalcAbsoluteAddress(&instruction, instruction.operands, (ZyanU64)instructionAddress, &originalJumpTarget);
					originalJumpTarget = *(int64_t*)originalJumpTarget;
				}
				else
				{
					printf("[Error] - There should be no rip-relative call instruction with a R/M value other than 5\n");
				}
			}
			else
			{
				printf("[Error] - There should be no rip-relative call instruction with a mod value other than 0\n");
			}
		}
		else
		{
			//CALL rel16, CALL rel32, CALL ptr16:16, CALL ptr16:32
			ZydisCalcAbsoluteAddress(&instruction, instruction.operands, (ZyanU64)instructionAddress, &originalJumpTarget);
		}
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

		rellocatedbytes.insert(rellocatedbytes.end(), (int8_t*)&originalJumpTarget, (int8_t*)&originalJumpTarget + 8); //destination to jump to: 8 Bytes
		printf("[Info] - Decoder relocated a branch instruction\n");
	}

	void RelocateRipRelativeMemoryInstruction(ZydisDecodedInstruction& instruction, int8_t* instructionAddress, int8_t* relocatedInstructionAddress, std::vector<int8_t>& rellocatedbytes)
	{
		int8_t* tmpBuffer = (int8_t*)malloc(instruction.length);
		
		//copy original instruction
		memcpy(tmpBuffer, instructionAddress, instruction.length);
		
		//calculate the absolute address of the rip-relative address
		const int8_t* absoluteAddress = instructionAddress + instruction.length + instruction.raw.disp.value;

		const int32_t relocatedRelativeAddress = absoluteAddress - relocatedInstructionAddress - instruction.length;

		//write relocated realtive address to the relocated instrucions displacement
		*(int32_t*)&tmpBuffer[instruction.raw.disp.offset] = relocatedRelativeAddress;
		
		//TODO check if we could sucessfully rellocate (if trampoline is too far away rel32 may not be enough)

		//add bytes of relocated instructions to relocated instuctions
		rellocatedbytes.insert(rellocatedbytes.end(), tmpBuffer, tmpBuffer + instruction.length);

		free(tmpBuffer);
		printf("[Info] - Decoder rellocated a rip-relative memory instruction\n");
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
		- loopcc
		- XBEGIN //not handled

	   64bit:
		-call
		- jcc
		- loopcc
		- XBEGIN //not handled
		- instructions that use ModR/M addressing (rip relative)
	 */
	/**
	 * Creates a vector containing rellocated instructions. These instructions are not yet written to the targetAddress.
	 * We need need to know the targetAddress to relocate rip-relative instructions.
	 * We do generate a vector<int8_t> of relocated instructions instead of writing them directly to the target address
	 * to first check if the entire relocation succeeds before writing to the target
	 */
	std::vector<int8_t> Decoder::Relocate(int8_t* sourceAddress, int length, int8_t* targetAddress)
	{
		//TODO random constant at random location. This constant changes if changes are made to the trampoline..
		const int offsetOfRelocatedBytesinTrampoline = 455;
		int8_t* relocationAddress = targetAddress + offsetOfRelocatedBytesinTrampoline;
		std::vector<int8_t> relocatedbytes;

		int amountOfBytesRellocated = 0;

		//we will atleast rellocate "length" bytes. To avoid splitting an instruction we might rellocate more.
		while (amountOfBytesRellocated < length)
		{
			ZydisDecodedInstruction instruction;
			int8_t* currentAddress = sourceAddress + amountOfBytesRellocated;
			
			ZyanStatus decodeResult = ZydisDecoderDecodeBuffer((ZydisDecoder*)_zydisDecoder, currentAddress, MAXIMUM_INSTRUCTION_LENGTH, &instruction);
			if (decodeResult != ZYAN_STATUS_SUCCESS)
			{
				printf("ERROR: decoder could not decode instruction\n");
				return std::vector<int8_t>();
			}
			//the order here matters. We start with most specific relocations. There are for example call instructions that use the ModRM byte and therefore are also rip-relative memory addresses
			if (IsCallInstruction(instruction))
			{
				//handle relocation of call instructions
				RelocateCallInstruction(instruction, currentAddress, relocatedbytes);
			}
			else if (IsBranchInstruction(instruction))	
			{
				//handle relocation of branch instructions (jcc, loopcc)
				RelocateBranchInstruction(instruction, currentAddress, relocatedbytes);
			}
			else if (IsRipRelativeMemoryInstruction(instruction))	 
			{
				//handle relocation of rip-relative memory addresses (x64 only)
				RelocateRipRelativeMemoryInstruction(instruction, currentAddress, relocationAddress + relocatedbytes.size(), relocatedbytes);
			}
			else if (instruction.mnemonic == ZYDIS_MNEMONIC_XBEGIN)
			{
				//XBEGIN causes undefined opcode exception on most computers as intel removed it form the underlying microcode architecture due to security concerns(Zombieload 2 Attack)
				//and even physically removed support for it on never processors
				//additionally windows (and linux) allow for disabling tsx support
				//we expect to never encounter this instruction
				printf("[ERROR]: decoder encountered XBEGIN instruction which is a relative but unhandled instruction!\n"); 
				return std::vector<int8_t>();
			}
			else
			{
				//if its just copy the original bytes
				relocatedbytes.insert(relocatedbytes.end(), currentAddress, currentAddress + instruction.length);
			}
			amountOfBytesRellocated += instruction.length;
		}
		return relocatedbytes;
	}

	int Decoder::GetLengthOfInstructions(int8_t* sourceAddress, int length)
	{
		int byteCount = 0;

		//we will atleast rellocate "length" bytes. To avoid splitting an instruction we might rellocate more.
		while (byteCount < length)
		{
			ZydisDecodedInstruction instruction;
			int8_t* currentAddress = sourceAddress + byteCount;

			ZyanStatus decodeResult = ZydisDecoderDecodeBuffer((ZydisDecoder*)_zydisDecoder, currentAddress, MAXIMUM_INSTRUCTION_LENGTH, &instruction);
			if (decodeResult != ZYAN_STATUS_SUCCESS)
			{
				printf("ERROR: decoder could not decode instruction\n");
				return 0;
			}
			byteCount += instruction.length;
		}
		return byteCount;
	}

	std::vector<int8_t*> Decoder::FindRelativeInstructionsOfType(int8_t* startAddress, RelativeInstruction type, int length)
	{
		std::vector<int8_t*> foundInstructions;
		int offset = 0;
		ZyanStatus decodeResult = ZYAN_STATUS_FAILED;
		//we will atleast rellocate "length" bytes. To avoid splitting an instruction we might rellocate more.
		do
		{
			ZydisDecodedInstruction instruction;
			int8_t* currentAddress = startAddress + offset;

			decodeResult = ZydisDecoderDecodeBuffer((ZydisDecoder*)_zydisDecoder, currentAddress, MAXIMUM_INSTRUCTION_LENGTH, &instruction);
			if (decodeResult != ZYAN_STATUS_SUCCESS)
			{
				printf("ERROR: decoder could not decode instruction\n");
				offset += instruction.length;
				continue;
			}

			bool typeFound = false;
			switch (type)
			{
			case RelativeInstruction::CALL:
				if(IsCallInstruction(instruction))
				{
					typeFound = true;
				}
				break;
			case RelativeInstruction::BRANCH:
				if (IsBranchInstruction(instruction))
				{
					typeFound = true;
				}
				break;
			case RelativeInstruction::RIP_RELATIV:
				if (IsRipRelativeMemoryInstruction(instruction))
				{
					typeFound = true;
				}
				break;
			}
			if (typeFound)
			{
				foundInstructions.push_back(currentAddress);
			}
			offset += instruction.length;
		} while (decodeResult == ZYAN_STATUS_SUCCESS || offset < length);
		printf("[Warning] - decoder couln't find relative instruction of desired type in %d bytes\n", offset);
		return foundInstructions;
	}

	/**
	 * Calculates the lowest and highest realtive accesses. These have to be taken into consideration when creating the trampoline
	 * as we can only relocate rip-relative intructions if they can access their original target with "relocated rip" + rel32
	 */
	bool Decoder::CalculateBoundsOfRelativeAddresses(int8_t* sourceAddress, int length, int64_t* lowestAddress, int64_t* highestAddress)
	{
		int byteCount = 0;
		uint64_t tmpLowestAddress = 0xffffffffffffffff;
		uint64_t tmpHighestAddress = 0;
		
		//we will atleast rellocate "length" bytes. To avoid splitting an instruction we might rellocate more.
		while (byteCount < length)
		{
			ZydisDecodedInstruction instruction;
			int8_t* currentAddress = sourceAddress + byteCount;

			ZyanStatus decodeResult = ZydisDecoderDecodeBuffer((ZydisDecoder*)_zydisDecoder, currentAddress, MAXIMUM_INSTRUCTION_LENGTH, &instruction);
			if (decodeResult != ZYAN_STATUS_SUCCESS)
			{
				printf("ERROR: decoder could not decode instruction\n");
				return false;
			}

			//skip non relative instructions
			if (!(instruction.attributes & ZYDIS_ATTRIB_IS_RELATIVE))
			{
				byteCount += instruction.length;
				continue;
			}

			//calculate the absolute target address of the relative instruction
			ZyanU64 absoluteTargetAddress;
			ZydisCalcAbsoluteAddress(&instruction, instruction.operands, (ZyanU64)currentAddress, &absoluteTargetAddress);

			if (absoluteTargetAddress < tmpLowestAddress)
			{
				tmpLowestAddress = absoluteTargetAddress;
			}

			if (absoluteTargetAddress > tmpHighestAddress)
			{
				tmpHighestAddress = absoluteTargetAddress;
			}
			
			byteCount += instruction.length;
		}
		*lowestAddress = tmpLowestAddress;
		*highestAddress = tmpHighestAddress;
		return true;
	}
}
