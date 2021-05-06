#pragma once
#include <cstdint>
#include <xmmintrin.h>


namespace hookftw
{
	/**
	 * \brief Registers used in 64 Bit of the x86 instruction set
	 *
	 * The registers can be directly read from and written to inside the hook callback function.
	 */
	struct registers
	{
		int64_t rsp;
		int64_t rax;
		int64_t rcx;
		int64_t rdx;
		int64_t rbx;
		int64_t rbp;
		int64_t rsi;
		int64_t rdi;
		int64_t r8;
		int64_t r9;
		int64_t r10;
		int64_t r11;
		int64_t r12;
		int64_t r13;
		int64_t r14;
		int64_t r15;

		__m128 xmm0;
		__m128 xmm1;
		__m128 xmm2;
		__m128 xmm3;
		__m128 xmm4;
		__m128 xmm5;
		__m128 xmm6;
		__m128 xmm7;
		__m128 xmm8;
		__m128 xmm9;
		__m128 xmm10;
		__m128 xmm11;
		__m128 xmm12;
		__m128 xmm13;
		__m128 xmm14;
		__m128 xmm15;

	};
}