#pragma once

#include <cstdint>
#include <vector>


namespace hookftw
{
	enum class RelativeInstruction
	{
		CALL,
		BRANCH, // jcc, loopcc
		RIP_RELATIV
	};
	class Instruction;

	/**
	 * \brief Decodes the target binary and provides utilities to work with assembly instructions
	 *
	 * Uses the Zydis Disassembler to analyse and/or relocate assembler instructions.
	 */
	class Decoder
	{
		// we use a void pointer here since we can't forward declare the ZydisDecoder c typedef struct
		// we do not want to include the zydis headers here since we then have to link against zydis (and not only hookFTW) when using hookFTW
		static void* _zydisDecoder;

		const int MAXIMUM_INSTRUCTION_LENGTH = 15;
	public:
		Decoder();
	
		void PrintInstructions(int8_t* address, int32_t byteCount);
		int GetLengthOfInstructions(int8_t* sourceAddress, int length);
		std::vector<int8_t*> FindRelativeInstructionsOfType(int8_t* startAddress, RelativeInstruction type, int length);
		bool CalculateRipRelativeMemoryAccessBounds(int8_t* sourceAddress, int length, int64_t* lowestAddress, int64_t* highestAddress);
		std::vector<int8_t> Relocate(int8_t* sourceAddress, int length, int8_t* targetAddress, bool restrictedRelocation = false);
	};
}