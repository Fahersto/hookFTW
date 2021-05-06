#include "Disassembler.h"

#include <cinttypes>
#include <cstdio>
#include <string>



#include <Zydis/Zydis.h>
#include <Zydis/DecoderTypes.h>


namespace hookftw
{
	/**
	 * Prints the given instruction to console
	 */
	void Disassembler::PrintInstruction(ZyanU64 runtime_address, ZydisDecodedInstruction instruction)
	{
		ZydisFormatter formatter;
		ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

		char buffer[256];
		printf("[%llx]", runtime_address);
		ZydisFormatterFormatInstruction(&formatter, &instruction, buffer, sizeof(buffer), runtime_address);
		puts(buffer);
	}

	/**
	 * Rellocates an instruction
	 *
	 *  @param currentInstruction The instruction to be rellocated
	 *  @param instructionAddress Address of the instruction to be rellocated
	 *  @param rellocatedInstructions Vector to store the rellocated instructions
	 */
	void Disassembler::RellocateInstruction(const ZydisDecodedInstruction& currentInstruction, int8_t* instructionAddress, std::vector<int8_t>& rellocatedInstructions)
	{
		ZyanU64 originalJumpTarget;
		ZydisCalcAbsoluteAddress(&currentInstruction, currentInstruction.operands, (ZyanU64)instructionAddress, &originalJumpTarget);

		if (currentInstruction.meta.category == ZYDIS_CATEGORY_COND_BR || currentInstruction.meta.category == ZYDIS_CATEGORY_UNCOND_BR)//JCC? or rip relative?
		{
			rellocatedInstructions.insert(rellocatedInstructions.end(), instructionAddress, instructionAddress + currentInstruction.length);
			rellocatedInstructions[rellocatedInstructions.size() - 1] = 0x2;

			auto elementSizeInBytes = currentInstruction.operands[0].element_size / 8;
			//suppport jcc rel8, jcc rel16, jcc rel32. JCC always has the offset in its first operand
			for (int i = 0; i < elementSizeInBytes - 1; i++)
			{
				rellocatedInstructions.push_back(0x0);
			}

			//jmp after jcc instruction because jcc is not taken
			rellocatedInstructions.push_back(0xEB);				//jmp    0x10
			rellocatedInstructions.push_back(0xE);				//
						
			//jmp for when jcc is taken
			rellocatedInstructions.push_back(0xFF);				//opcodes = JMP [rip+0]
			rellocatedInstructions.push_back(0x25);				//
			rellocatedInstructions.push_back(0x0);				//
			rellocatedInstructions.push_back(0x0);				//
			rellocatedInstructions.push_back(0x0);				//
			rellocatedInstructions.push_back(0x0);				//

			rellocatedInstructions.insert(rellocatedInstructions.end(), (BYTE*)&originalJumpTarget, (BYTE*)&originalJumpTarget + 8); //destination to jump to: 8 Bytes
		}


		/////////
		/////////
		///

		switch (currentInstruction.meta.category)
		{
		case ZYDIS_CATEGORY_UNCOND_BR:
				printf("ZYDIS_CATEGORY_UNCOND_BR\n");
				PrintInstruction((ZyanU64)instructionAddress, currentInstruction);
			break;
		case ZYDIS_CATEGORY_COND_BR:
			printf("ZYDIS_CATEGORY_COND_BR\n");
			switch (currentInstruction.mnemonic)
			{
				case ZYDIS_MNEMONIC_LOOP:
					printf("\tZYDIS_MNEMONIC_LOOP\n\t\t");
					PrintInstruction((ZyanU64)instructionAddress, currentInstruction);	//Decrement rcx; jump short if count ≠ 0.
					break;
				case ZYDIS_MNEMONIC_LOOPE:
					printf("\tZYDIS_MNEMONIC_LOOPE\n\t\t");
					PrintInstruction((ZyanU64)instructionAddress, currentInstruction);	//Decrement rcx; jump short if count ≠ 0 and ZF = 1
					break;
				case ZYDIS_MNEMONIC_LOOPNE:
					printf("\tZYDIS_MNEMONIC_LOOPNE\n\t\t");
					PrintInstruction((ZyanU64)instructionAddress, currentInstruction);	//Decrement rcx; jump short if count ≠ 0 and ZF = 0
					break;
				default:
					printf("\tUNHANDLED ZYDIS_CATEGORY_COND_BR MNEMONIC\n\t\t");
					PrintInstruction((ZyanU64)instructionAddress, currentInstruction);
					break;
			}
			break;
		case ZYDIS_CATEGORY_CALL:
		{
			//rellocate call
			const int rellocatedCallInstructionsLength = 12;
			int8_t rellocatedCallInstructions[rellocatedCallInstructionsLength] = {
				0x48, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,			//movabs rax, 0x1122334455667788
				0xFF, 0xD0															//call   rax
			};
			*(uint64_t*)&rellocatedCallInstructions[2] = originalJumpTarget;
			rellocatedInstructions.insert(rellocatedInstructions.end(), rellocatedCallInstructions, rellocatedCallInstructions + rellocatedCallInstructionsLength);
			break;
		}
		default:
			printf("UNHANDLED CATEGORY\n\t");
			PrintInstruction((ZyanU64)instructionAddress, currentInstruction);
			break;
		}
	}

	/**
	 * Disassembles intructions
	 *
	 * @param address Address to start disassembling
	 * @param byteCount amount of bytes to disassemble
	 */
	void Disassembler::Analyse(int8_t* address, size_t byteCount)
	{
		ZyanU8* data = (ZyanU8*)address;

		// Initialize decoder context
		ZydisDecoder decoder;
		ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);


		// Loop over the instructions in our buffer.
		// The runtime-address (instruction pointer) is chosen arbitrary here in order to better visualize relative addressing
		ZyanU64 runtime_address = (ZyanU64)address;
		ZyanUSize offset = 0;
		ZydisDecodedInstruction instruction;

		int relativeInstructions = 0;
		while (offset < byteCount)
		{
			//TODO LOOK AT ZydisCalcAbsoluteAddress do understand implementaion
			ZyanU64 originalJumpTarget;
			ZydisCalcAbsoluteAddress(&instruction, instruction.operands, (ZyanU64)(data + offset), &originalJumpTarget);
			ZydisDecoderDecodeBuffer(&decoder, data + offset, byteCount - offset, &instruction);
			ZyanU8* currAddress = data + offset;
			if (instruction.attributes & ZYDIS_ATTRIB_IS_RELATIVE)
			{
				switch (instruction.meta.category)
				{
				case ZYDIS_CATEGORY_UNCOND_BR:
					PrintInstruction(runtime_address, instruction);
					break;
				case ZYDIS_CATEGORY_COND_BR:
					switch (instruction.mnemonic)
					{
					case ZYDIS_MNEMONIC_LOOP:
						PrintInstruction(runtime_address, instruction);	//Decrement rcx; jump short if count ≠ 0.
						break;
					case ZYDIS_MNEMONIC_LOOPE:
						PrintInstruction(runtime_address, instruction);	//Decrement rcx; jump short if count ≠ 0 and ZF = 1
						break;
					case ZYDIS_MNEMONIC_LOOPNE:
						PrintInstruction(runtime_address, instruction);	////Decrement rcx; jump short if count ≠ 0 and ZF = 0
						break;
					default:
						printf("\tUNHANDLED ZYDIS_CATEGORY_COND_BR: ");
						PrintInstruction(runtime_address, instruction);
						break;
					}
					break;
				case ZYDIS_CATEGORY_CALL:
					printf("ZYDIS_CATEGORY_CALL: ");
					PrintInstruction(runtime_address, instruction);
					break;
				default:
					printf("UNHANDLED CATEGORY: ");
					PrintInstruction(runtime_address, instruction);
					break;
				}
			}
			offset += instruction.length;
			runtime_address += instruction.length;
		}
		printf("~~ total relative instructions %d ~~\n", relativeInstructions);
	}

}