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
		printf("%s\n", buffer);
	}

	/**
	 * Disassembles intructions
	 *
	 * @param address Address to start disassembling
	 * @param byteCount amount of bytes to disassemble
	 */
	void Disassembler::PrintInstructions(int8_t* address, size_t byteCount)
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
		// loop over the instructions in our buffer.
		// the runtime-address (instruction pointer) is chosen arbitrary here in order to better visualize relative addressing
		ZyanU64 runtime_address = (ZyanU64)address;
		ZyanUSize offset = 0;
		ZydisDecodedInstruction instruction;

		while (offset < byteCount)
		{
			ZydisDecoderDecodeBuffer(&decoder, data + offset, byteCount - offset, &instruction);

			PrintInstruction(runtime_address, &instruction);

			offset += instruction.length;
			runtime_address += instruction.length;
		}
	}

}