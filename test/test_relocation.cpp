#include <cstdio>
#include <cstdint>
#include <cstring>

#include <Decoder.h>


/**
*	This program tests relocation of predefined instructions.
*	THe results of the relocation have to be inspected manually.
*/

#ifdef __x86_64
const int callsLength = 40;
uint8_t calls[callsLength] =
{
	0xe8, 0x11, 0x22, 0x33, 0x44,				// E8 cd --> CALL rel32							--> call 0x44332216

	// ff /2 calls with different ModR/M values
	0xFF, 0x10,									// FF /2 --> CALL with ModR/M [register]			--> call [rax]
	0xFF, 0x14, 0x0A,							// FF /2 --> Call with ModR/M + SIB Byte			--> call QWORD PTR [rdx+rcx*1]
	0xFF, 0x15, 0x11, 0x22, 0x33, 0x44,			// rip-relative call								--> call QWORD PTR[rip + 0x44332211]
	0xFF, 0x50, 0x11,							// FF /2 --> Call with ModR/M [register]+disp8		--> call QWORD PTR [rax+0x11]
	0xFF, 0x90, 0x11, 0x22, 0x33, 0x44,			// FF /2 --> Call with ModR/M [register]+disp32		--> call QWORD PTR[rax + 0x44332211]
	0xFF, 0xD0,									// FF /2 --> CALL with ModR/M register				--> call rax

	// ff /3 calls
	0xFF, 0x98, 0x11, 0x22, 0x33, 0x44,			// FF /3 --> call FWORD PTR [rax+0x44332211] // FWORD = 16 bit selector + 32 bit offset
	0x48, 0xFF, 0x98, 0x11, 0x22, 0x33, 0x44	// FF /3 --> rex.W call FWORD PTR [rax+0x44332211]
};

// as we handle all JCC using the same method we just 
const int jumpsLength = 35;
uint8_t jumps[jumpsLength] =
{
	0x77, 0x11,									// JA rel8
	0x0F, 0x87, 0x11, 0x00, 0x00, 0x00,			// JA rel32
	0xEB, 0x11,									// JMP rel8
	0xE9, 0x11, 0x22, 0x33, 0x44,				// JMP rel32
	0xFF, 0x24, 0xc5, 0x11, 0x22, 0x33, 0x44,	// JMP r/m64 (jmp r/m sib; FF /4)
	0xFF, 0x25, 0x11, 0x22, 0x33, 0x44,			// FF /5
	0x48, 0xFF, 0x25, 0x11, 0x22, 0x33, 0x44	// REX.W FF /5
};

const int loopLength = 6;
uint8_t loops[loopLength] =
{
	0xE2, 0x11,	// LOOP	  rel8
	0xE1, 0x11,	// LOOPE  rel8
	0xE0, 0x11	// LOOPNE rel8
};

const int ripRelativeLength = 36;
uint8_t ripRelative[ripRelativeLength] =
{
	0x29, 0x2D, 0xF5, 0xE9, 0x28, 0x7C,							// sub DWORD PTR [rip+0x7c28e9f5],ebp
	0xC7, 0x05, 0xF3, 0xCE, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,	// mov DWORD PTR [rip+0xcef3],0x1
	0x89, 0x05, 0x90, 0x97, 0x00, 0x00,							// mov DWORD PTR [rip+0x9790],eax
	0x48, 0x8D, 0x0D, 0x79, 0x89, 0x00, 0x00,					// lea rcx,[rip+0x8979]
	0x48, 0x3B, 0x0D, 0xE1, 0x9A, 0x00, 0x00					// cmp rcx,QWORD PTR [rip+0x9ae1]
};

// we define this here to be in +-2 GB range without having to deal with trampoline allocation
const int relocatedBytesLength = 200;
int8_t relocatedBytes[relocatedBytesLength];

void TestRelocation(int8_t* instructions, int instructionsLength)
{
	hookftw::Decoder decoder;

	// print original instructions
	printf("Original instructions: \n");
	decoder.PrintInstructions(instructions, instructionsLength);

	// relocate instructions
	auto relocatedInstructions = decoder.Relocate(instructions, instructionsLength, relocatedBytes);

	memcpy(relocatedBytes, relocatedInstructions.data(), relocatedInstructions.size());

	// print relocation result
	printf("Relocated instructions: \n");
	decoder.PrintInstructions(relocatedBytes, relocatedInstructions.size());

	memset(relocatedBytes, 0, relocatedBytesLength);
}

int main()
{
	printf("~~~ 64 bit relocation test ~~~ \n\n");
	printf("~~~ Testing relocation of CALL ~~~ \n");
	TestRelocation((int8_t*)calls, callsLength);
	printf("\n");

	printf("~~~ Testing relocation of Jcc ~~~ \n");
	printf("~~~ Zydis can't reasonably print the mixture of code and data that 14 byte jumps use.\nCheatEngine generates a pseudo instruction to capture the semantics of the instuction ~~~ \n");
	TestRelocation((int8_t*)jumps, jumpsLength);
	printf("\n");

	printf("~~~ Testing relocation of LOOPcc ~~~ \n");
	printf("~~~ Zydis can't reasonably print the mixture of code and data that 14 byte jumps use.\nCheatEngine generates a pseudo instruction to capture the semantics of the instuction ~~~ \n");
	TestRelocation((int8_t*)loops, loopLength);
	printf("\n");

	printf("~~~ Testing relocation of RIP-relative memory accesses ~~~ \n");
	TestRelocation((int8_t*)ripRelative, ripRelativeLength);
	printf("\n");
}

#elif _WIN32
const int callsLength = 33;
int8_t calls[callsLength] =
{
	0xe8, 0x11, 0x22, 0x33, 0x44,				// E8 cd --> CALL rel32							--> call 0x44332216

	// ff /2 calls with different ModR/M values
	0xFF, 0x10,									// FF /2 --> CALL with ModR/M [register]			--> call [eax]
	0xFF, 0x14, 0x0A,							// FF /2 --> Call with ModR/M + SIB Byte			--> call DWORD PTR [edx+ecx*1]
	0xFF, 0x15, 0x11, 0x22, 0x33, 0x44,			//												--> call DWORD PTR ds : 0x44332211
	0xFF, 0x50, 0x11,							// FF /2 --> Call with ModR/M [register]+disp8	--> call DWORD PTR [eax+0x11]
	0xFF, 0x90, 0x11, 0x22, 0x33, 0x44,			// FF /2 --> Call with ModR/M [register]+disp32	--> call DWORD PTR[eax + 0x44332211]
	0xFF, 0xD0,									// FF /2 --> CALL with ModR/M register			--> call eax

	// ff /3 calls
	0xFF, 0x98, 0x11, 0x22, 0x33, 0x44,			// FF /3 -->		  call FWORD PTR [eax+0x44332211] // FWORD = 16 bit selector + 32 bit offset
};

// as we handle all JCC using the same method we just 
const int jumpsLength = 37;
int8_t jumps[jumpsLength] =
{
	0x77, 0x11,									// JA rel8
	0x66, 0x0F, 0x87, 0x11, 0x22,				// JA rel16 
	0x0F, 0x87, 0x11, 0x22, 0x33, 0x44,			// JA rel32
	0xEB, 0x11,									// JMP rel8
	0x66, 0xE9, 0x11, 0x22,						// JMP rel16
	0xE9, 0x11, 0x22, 0x33, 0x44,				// JMP rel32
	0xFF, 0x24, 0xc5, 0x11, 0x22, 0x33, 0x44,	// FF /4   JMP r/m32
	//0xEA, 0x11, 0x22, 0x33, 0x44,				// JMP ptr16:16
	//0xEA, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,	// JMP ptr16:32
	0xFF, 0x25, 0x11, 0x22, 0x33, 0x44			// FF /5
};


const int loopLength = 6;
int8_t loops[loopLength] =
{
	0xE2, 0x11,	// LOOP rel8
	0xE1, 0x11,	// LOOPE rel8
	0xE0, 0x11	// LOOPNE rel8
};

// we use this here to be in +-2 GB range without having to deal with trampoline allocation
const int relocatedResultLength = 200;
int8_t relocatedResult[relocatedResultLength];

void TestRelocation(int8_t* instructions, int instructionsLength)
{
	hookftw::Decoder decoder;

	// print original instructions
	decoder.PrintInstructions(instructions, instructionsLength);

	// relocate instructions
	auto relocatedInstructions = decoder.Relocate(instructions, instructionsLength, relocatedResult);

	memcpy(relocatedResult, relocatedInstructions.data(), relocatedInstructions.size());

	// print relocation result
	decoder.PrintInstructions(relocatedResult, relocatedInstructions.size());

	memset(relocatedResult, 0, relocatedResultLength);
}

int main()
{
	printf("~~~ 32 bit relocation test ~~~ \n\n");
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
#endif