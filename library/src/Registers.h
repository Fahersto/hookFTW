#pragma once
#include <cstdint>
#include <xmmintrin.h>


namespace hookftw
{
#if _WIN64
/**
 * \brief Registers used in 64 Bit of the x86 instruction set
 *
 * The registers can be directly read from and written to inside the hook callback function.
 * TODO fpu registers? (st0 - st7). They seem unused in 64bit though.
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

	void print()
	{
		printf("register:\n\trsp %llx\n\trax %llx\n\trcx %llx\n\trdx %llx\n\trbx %llx\n\trbp %llx\n\trsi %llx\n\trdi %llx\n\tr8 %llx\n\tr9 %llx\n\tr10 %llx\n\tr11 %llx\n\tr12 %llx\n\tr13 %llx\n\tr14 %llx\n\tr15 %llx\n",
			rsp, rax, rcx, rdx, rbx, rbp, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15);
	}
};
#elif _WIN32
	/**
	 * \brief Registers used in 32 Bit of the x86 instruction set
	 *
	 * The registers can be directly read from and written to inside the hook callback function.
	 * TODO fpu registers? (st0 - st7)
	 */
	struct registers
	{
		int32_t esp;
		int32_t eax;
		int32_t ecx;
		int32_t edx;
		int32_t ebx;
		int32_t ebp;
		int32_t esi;
		int32_t edi;

		__m128 xmm0;
		__m128 xmm1;
		__m128 xmm2;
		__m128 xmm3;
		__m128 xmm4;
		__m128 xmm5;
		__m128 xmm6;
		__m128 xmm7;
	};

#endif
}