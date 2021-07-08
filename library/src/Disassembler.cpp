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
	void Disassembler::PrintInstruction(int64_t runtime_address, void* instruction)
	{
		ZydisFormatter formatter;
		ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

		char buffer[256];
		printf("[%llx]", runtime_address);
		ZydisFormatterFormatInstruction(&formatter, (ZydisDecodedInstruction*)instruction, buffer, sizeof(buffer), runtime_address);
		puts(buffer);
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

		#ifdef _WIN64
				ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
		#elif _WIN32
				ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_ADDRESS_WIDTH_32);
		#else
				printf("[Error] - Disassembler - Unsupported architecture\n");
		#endif
		


		// Loop over the instructions in our buffer.
		// The runtime-address (instruction pointer) is chosen arbitrary here in order to better visualize relative addressing
		ZyanU64 runtime_address = (ZyanU64)address;
		ZyanUSize offset = 0;
		ZydisDecodedInstruction instruction;

		while (offset < byteCount)
		{
			ZyanU64 originalJumpTarget;
			ZydisCalcAbsoluteAddress(&instruction, instruction.operands, (ZyanU64)(data + offset), &originalJumpTarget);
			ZydisDecoderDecodeBuffer(&decoder, data + offset, byteCount - offset, &instruction);
			ZyanU8* currAddress = data + offset;
			switch (instruction.meta.category)
			{
			case ZYDIS_CATEGORY_UNCOND_BR:
				PrintInstruction(runtime_address, &instruction);
				break;
			case ZYDIS_CATEGORY_COND_BR:
				switch (instruction.mnemonic)
				{
				case ZYDIS_MNEMONIC_LOOP:
					PrintInstruction(runtime_address, &instruction);	//Decrement rcx; jump short if count ≠ 0.
					break;
				case ZYDIS_MNEMONIC_LOOPE:
					PrintInstruction(runtime_address, &instruction);	//Decrement rcx; jump short if count ≠ 0 and ZF = 1
					break;
				case ZYDIS_MNEMONIC_LOOPNE:
					PrintInstruction(runtime_address, &instruction);	////Decrement rcx; jump short if count ≠ 0 and ZF = 0
					break;
				default:
					printf("\tUNHANDLED ZYDIS_CATEGORY_COND_BR: ");
					PrintInstruction(runtime_address, &instruction);
					break;
				}
				break;
			case ZYDIS_CATEGORY_CALL:
				printf("ZYDIS_CATEGORY_CALL: ");
				PrintInstruction(runtime_address, &instruction);
				break;
			default:
				//printf("UNHANDLED CATEGORY: ");
				PrintInstruction(runtime_address, &instruction);
				break;
			}
			offset += instruction.length;
			runtime_address += instruction.length;
		}
	}

}