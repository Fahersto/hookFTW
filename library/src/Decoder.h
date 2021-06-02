#pragma once

#include <cstdint>
#include <vector>


namespace hookftw
{
	enum class RelativeInstruction
	{
		CALL,
		BRANCH, //jcc, loopcc
		RIP_RELATIV
	};
	class Instruction;
	class Decoder
	{
		//we use a void pointer here since we can't forward declare the ZydisDecoder c typedef struct
		//we do not want to include the zydis headers here since we then have to link against zydis (and not only hookftw) when using hookftw
		static void* _zydisDecoder;

		const int MAXIMUM_INSTRUCTION_LENGTH = 15;
	public:
		Decoder();
	
		int GetLengthOfInstructions(int8_t* sourceAddress, int length);
		int8_t* FindNextRelativeInstructionOfType(int8_t* startAddress, RelativeInstruction type, int length);
		bool CalculateBoundsOfRelativeAddresses(int8_t* sourceAddress, int length, int64_t* lowestAddress, int64_t* highestAddress);
		std::vector<int8_t> Relocate(int8_t* sourceAddress, int length, int8_t* targetAddress);
	};
}