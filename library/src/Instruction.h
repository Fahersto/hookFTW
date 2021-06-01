


#include <cstdint>


enum InstructionType
{
	REGULAR,
	CALL,
	BRANCH,
	RIPRELATIVEMEMORY
};

class Instruction
{
	InstructionType _instructionType;
	int8_t _length;

	Instruction(InstructionType instructionType, int8_t length);
};