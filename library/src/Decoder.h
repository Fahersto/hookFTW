#pragma once

#include <cstdint>
#include <vector>


namespace hookftw
{
	class Instruction;
	class Decoder
	{
		static void* _zydisDecoder;
	public:
		Decoder();
		std::vector<int8_t> Relocate(int8_t* source, int length);
	};
}