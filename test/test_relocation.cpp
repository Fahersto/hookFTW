#include <Windows.h>
#include <cstdint>

#include <Disassembler.h>
#include <Decoder.h>





//64bit
const int callsLength = 40;
int8_t calls[callsLength] =
{
	0xe8, 0x11, 0x22, 0x33, 0x44,				//E8 cd --> CALL rel32							--> call 0x44332216

	//ff /2 calls with different ModR/M values
	0xFF, 0x10,									//FF /2 --> CALL with ModR/M [register]			--> call [rax]
	0xFF, 0x14, 0x0A,							//FF /2 --> Call with ModR/M + SIB Byte			--> call QWORD PTR [rdx+rcx*1]
	0xFF, 0x15, 0x11, 0x22, 0x33, 0x44,
	0xFF, 0x50, 0x11,							//FF /2 --> Call with ModR/M [register]+disp8	--> call QWORD PTR [rax+0x11]
	0xFF, 0x90, 0x11, 0x22, 0x33, 0x44,			//FF /2 --> Call with ModR/M [register]+disp32	--> call QWORD PTR[rax + 0x44332211]
	0xFF, 0xD0,									//FF /2 --> CALL with ModR/M register			--> call rax

	//ff /3 calls
	0xFF, 0x98, 0x11, 0x22, 0x33, 0x44,			//FF /3 -->		  call FWORD PTR [rax+0x44332211] // FWORD = 16 bit selector + 32 bit offset
	0x48, 0xFF, 0x98, 0x11, 0x22, 0x33, 0x44	//FF /3 --> rex.W call FWORD PTR [rax+0x44332211]
};


//As we handle all JCC using the same method we just 
const int jumpsLength = 8;
int8_t jumps[jumpsLength] =
{
	0x77, 0x11,							//JA rel8
	//0x0F, 0x87, 0x11, 0x22,			//JA rel16 is not valid for 64 bit (jcc rel16 isn't)
	0x0F, 0x87, 0x00, 0x00, 0x00, 0x00	//JA rel32
};

const int loopLength = 6;
int8_t loops[loopLength] =
{
	0xE2, 0x11,	//LOOP rel8
	0xE1, 0x11,	//LOOPE rel8
	0xE0, 0x11	//LOOPNE rel8
};


void TestRelocation(int8_t* instructions, int instructionsLength)
{
	hookftw::Disassembler disassembler;

	//Print original instructions
	disassembler.Analyse(instructions, instructionsLength);

	//Allocate space to relocate instructions to
	int8_t* trampoline = (int8_t*)VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	hookftw::Decoder decoder;
	
	//relocate instructions
	auto relocatedInstructions = decoder.Relocate(instructions, instructionsLength, trampoline);

	//copy relocated instructions to trampoline
	memcpy(trampoline, relocatedInstructions.data(), relocatedInstructions.size());

	//Print relocation result
	disassembler.Analyse(trampoline, relocatedInstructions.size());
}


int main()
{
	printf("~~~ Testing relocation of CALL ~~~ \n");
	TestRelocation(calls, callsLength);
	printf("\n");

	printf("~~~ Testing relocation of Jcc ~~~ \n");
	TestRelocation(jumps, jumpsLength);
	printf("\n");

	printf("~~~ Testing relocation of LOOPcc ~~~ \n");
	TestRelocation(loops, loopLength);
	printf("\n");
}