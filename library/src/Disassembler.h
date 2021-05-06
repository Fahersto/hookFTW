#pragma once

#include <cstdint>
#include <vector>
#include <Windows.h>
#include <Zydis/DecoderTypes.h>

#include "Zydis/Formatter.h"

namespace hookftw
{
	/**
	 * \brief Disassembles the target binary and provides utilities to work with assembly instructions
	 *
	 * Disassembles the target binary.
	 */
	class Disassembler
	{
	public:
		static void PrintInstruction(ZyanU64 runtime_address, ZydisDecodedInstruction instruction);
		static void RellocateInstruction(const ZydisDecodedInstruction& currentInstruction, int8_t* instructionAddress, std::vector<int8_t>& rellocatedInstructions);
		void Analyse(int8_t* address, size_t byteCount);
	};
}
