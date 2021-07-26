#include "Decoder.h"


#include <cstdio>
#include <Windows.h>
#include <Zydis/Zydis.h>


namespace hookftw
{
	void* Decoder::_zydisDecoder = nullptr;

	/**
	 *  \brief Determines if the passed instruction is a x86 call instruction
	 *
	 *	@param instruction instruction to be examined
	 *	@return true if the passed instruction is a call instruction. false otherwhise.
	 */
	bool IsCallInstruction(ZydisDecodedInstruction& instruction)
	{
		return instruction.mnemonic == ZYDIS_MNEMONIC_CALL;
	}

	/**
	 *  \brief Determines if the passed instruction is a x86 branch instruction
	 *
	 *	@param instruction instruction to be examined
	 *	@return true if the passed instruction is a branch instruction instruction (jcc or loopcc). false otherwhise.
	 */
	bool IsBranchInstruction(ZydisDecodedInstruction& instruction)
	{
		switch (instruction.mnemonic)
		{
		case ZYDIS_MNEMONIC_JB:
		case ZYDIS_MNEMONIC_JBE:
		case ZYDIS_MNEMONIC_JCXZ:
		case ZYDIS_MNEMONIC_JECXZ:
		case ZYDIS_MNEMONIC_JKNZD:
		case ZYDIS_MNEMONIC_JKZD:
		case ZYDIS_MNEMONIC_JL:
		case ZYDIS_MNEMONIC_JLE:
		case ZYDIS_MNEMONIC_JMP:
		case ZYDIS_MNEMONIC_JNB:
		case ZYDIS_MNEMONIC_JNBE:
		case ZYDIS_MNEMONIC_JNL:
		case ZYDIS_MNEMONIC_JNLE:
		case ZYDIS_MNEMONIC_JNO:
		case ZYDIS_MNEMONIC_JNP:
		case ZYDIS_MNEMONIC_JNS:
		case ZYDIS_MNEMONIC_JNZ:
		case ZYDIS_MNEMONIC_JO:
		case ZYDIS_MNEMONIC_JP:
		case ZYDIS_MNEMONIC_JRCXZ:
		case ZYDIS_MNEMONIC_JS:
		case ZYDIS_MNEMONIC_JZ:
		case ZYDIS_MNEMONIC_LOOP:
		case ZYDIS_MNEMONIC_LOOPE:
		case ZYDIS_MNEMONIC_LOOPNE:
			return true;
		default:
			return false;
		}
	}

	/**
	 *  \brief Determines if the passed instruction contains a rip-relateive memory access
	 *
	 *	@param instruction instruction to be examined
	 *	@return true if the passed instruction contains a rip-relative memory access (x64 only,). false otherwhise.
	 */
	bool IsRipRelativeMemoryInstruction(ZydisDecodedInstruction& instruction)
	{
		//For reference see: https://software.intel.com/content/www/us/en/develop/download/intel-64-and-ia-32-architectures-sdm-combined-volumes-2a-2b-2c-and-2d-instruction-set-reference-a-z.html
		//Table 2-2. 32-Bit Addressing Forms with the ModR/M Byte (x64 only)
		return instruction.attributes & ZYDIS_ATTRIB_HAS_MODRM &&
			instruction.raw.modrm.mod == 0 && instruction.raw.modrm.rm == 5; //disp32 see table	
	}

	/**
	 *  \brief Relocates a call instruction by calculating its absolute target address
	 *
	 *	@param instruction call instruction to be relocated
	 *	@param instructionAddress original address of the call instruction
	 *	@param rellocatedbytes relocated bytes
	 */
	void RelocateCallInstruction(ZydisDecodedInstruction& instruction, int8_t* instructionAddress, std::vector<int8_t>& rellocatedbytes)
	{
		ZyanU64 originalJumpTarget;
		if (instruction.attributes & ZYDIS_ATTRIB_HAS_MODRM)
		{
			if (instruction.raw.modrm.mod == 0 && instruction.raw.modrm.rm == 5)
			{
#ifdef _WIN64
				// disp32 see ModR/M table (intel manual)
				ZydisCalcAbsoluteAddress(&instruction, instruction.operands, (ZyanU64)instructionAddress, &originalJumpTarget);

				// we can use rax here as it has not to be preserved in function calls
				const int rellocatedCallInstructionsLength = 12;
				int8_t rellocatedCallInstructions[rellocatedCallInstructionsLength] = {
					0x48, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,			//movabs rax, 0x1122334455667788. 
					0xFF, 0x10															//call   [rax]
				};
				*(uint64_t*)&rellocatedCallInstructions[2] = originalJumpTarget;
				rellocatedbytes.insert(rellocatedbytes.end(), rellocatedCallInstructions, rellocatedCallInstructions + rellocatedCallInstructionsLength);
#elif _WIN32
				// just copy original call instruction. There is no rip-relative addressing in 32 bit. The displacement is relative to 0.
				rellocatedbytes.insert(rellocatedbytes.end(), instructionAddress, instructionAddress + instruction.length);
#endif 
			}
			else
			{
				// just copy original call instruction
				rellocatedbytes.insert(rellocatedbytes.end(), instructionAddress, instructionAddress + instruction.length);
			}
		}
		else
		{
			// e8 calls.. CALL rel16, CALL rel32,
			// 9a calls.. CALL ptr16:16, CALL ptr16:32 are not handled (no support for 16 bit architecture)
			ZydisCalcAbsoluteAddress(&instruction, instruction.operands, (ZyanU64)instructionAddress, &originalJumpTarget);

#ifdef _WIN64
			const int rellocatedCallInstructionsLength = 12;
			// we can use rax here as it has not to be preserved in function calls
			int8_t rellocatedCallInstructions[rellocatedCallInstructionsLength] = {
				0x48, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,			//movabs rax, 0x1122334455667788. 
				0xFF, 0xD0															//call   rax
			};
			*(uint64_t*)&rellocatedCallInstructions[2] = originalJumpTarget;
			rellocatedbytes.insert(rellocatedbytes.end(), rellocatedCallInstructions, rellocatedCallInstructions + rellocatedCallInstructionsLength);
#elif _WIN32
			const int rellocatedCallInstructionsLength = 7;
			// we can use eax here as it has not to be preserved in function calls
			int8_t rellocatedCallInstructions[rellocatedCallInstructionsLength] = {
				0xB8, 0x44, 0x33, 0x22, 0x11,			//mov  eax,0x11223344
				0xFF, 0xD0								//call eax
			};
			*(uint32_t*)&rellocatedCallInstructions[1] = originalJumpTarget;
			rellocatedbytes.insert(rellocatedbytes.end(), rellocatedCallInstructions, rellocatedCallInstructions + rellocatedCallInstructionsLength);
#endif
		}

		// the program can return to the return address pushed on the stack (at time of the call) at any time.
		// if the hook is removed (and therefore the trampoline freed) the return address might not contain valid code --> crash
		printf("[Warning] - Decoder - Relocated a call instruction. Unhooking is not safe!\n");
	}

	/**
	 *  \brief Relocates a branch instruction
	 *
	 *	@param instruction branch instruction to be relocated
	 *	@param instructionAddress original address of the branch instruction
	 *	@param rellocatedbytes relocated bytes
	 */
	void RelocateBranchInstruction(ZydisDecodedInstruction& instruction, int8_t* instructionAddress, int8_t* relocatedInstructionAddress, std::vector<int8_t>& rellocatedbytes)
	{
		ZyanU64 originalJumpTarget;
		ZydisCalcAbsoluteAddress(&instruction, instruction.operands, (ZyanU64)instructionAddress, &originalJumpTarget);

		rellocatedbytes.insert(rellocatedbytes.end(), instructionAddress, instructionAddress + instruction.length);

		const int elementSizeInBytes = instruction.operands[0].element_size / 8;
		//suppport jcc rel8, jcc rel16, jcc rel32. JCC always has the offset in its first operand. Fill remmaining bytes with '0'
		for (int i = 1; i < elementSizeInBytes - 1; i++)
		{
			rellocatedbytes[rellocatedbytes.size() - i] = 0x0;
		}
		rellocatedbytes[rellocatedbytes.size() - elementSizeInBytes] = 0x2;

#ifdef _WIN64
		// jmp after jcc instruction because jcc is not taken
		rellocatedbytes.push_back(0xEB);			//jmp    0x10
		rellocatedbytes.push_back(0xE);				//

		// jmp for when jcc is taken
		// we use an absolute JMP for x64 as this allows to relocate jcc instructions to a trampoline that is more than +-2GB away
		rellocatedbytes.push_back(0xFF);			//opcodes = JMP [rip+0]
		rellocatedbytes.push_back(0x25);			//
		rellocatedbytes.push_back(0x0);				//
		rellocatedbytes.push_back(0x0);				//
		rellocatedbytes.push_back(0x0);				//
		rellocatedbytes.push_back(0x0);				//

		rellocatedbytes.insert(rellocatedbytes.end(), (int8_t*)&originalJumpTarget, (int8_t*)&originalJumpTarget + 8); //destination to jump to: 8 Bytes

#elif _WIN32
		// jmp after jcc instruction because jcc is not taken
		rellocatedbytes.push_back(0xEB);			//jmp    0x07
		rellocatedbytes.push_back(0x5);				//

		// use relative jmp
		//write JMP from original code to trampoline_
		//we substract 5 because 
		int32_t newRelativeAddress = (int32_t)((int64_t)originalJumpTarget - (int64_t)relocatedInstructionAddress - 5 - 2 - instruction.length);

		rellocatedbytes.push_back(0xe9);																				//opcodes = JMP rel32
		rellocatedbytes.insert(rellocatedbytes.end(), (int8_t*)&newRelativeAddress, (int8_t*)&newRelativeAddress + 4);	//4 byte relative jump address
#endif
		printf("[Info] - Decoder - Relocated a branch instruction\n");
	}

	/**
	 *  \brief Relocates rip-relative memory instruction.
	 *
	 *  @warning It is important that the target address of the rip-relative instruction can be reached with a 4 byte displacement (+-2gb) from the relocated position, as rip-relative instructions always have a 4 byte displacement.
	 *  If the address accessed by the rip-relative instruciton can't be reached with 4 bytes from the new location we can not relocate it easily. Each instruction would have to be treated individually.
	 *
	 *	@param instruction rip-relative instruction to be relocated
	 *	@param instructionAddress original address of the rip-relative instruction
	 *	@param relocatedInstructionAddress relocated address of the rip-relative instruction
	 *	@param rellocatedbytes relocated bytes
	 */
	void RelocateRipRelativeMemoryInstruction(ZydisDecodedInstruction& instruction, int8_t* instructionAddress, int8_t* relocatedInstructionAddress, std::vector<int8_t>& rellocatedbytes)
	{
		int8_t* tmpBuffer = (int8_t*)malloc(instruction.length);

		// copy original instruction
		memcpy(tmpBuffer, instructionAddress, instruction.length);

		//calculate the absolute address of the rip-relative address
		const int8_t* absoluteAddress = instructionAddress + instruction.length + instruction.raw.disp.value;

		const int32_t relocatedRelativeAddress = absoluteAddress - relocatedInstructionAddress - instruction.length;

		// write relocated relative address to the relocated instrucions displacement
		*(int32_t*)&tmpBuffer[instruction.raw.disp.offset] = relocatedRelativeAddress;

		//add bytes of relocated instructions to relocated instuctions
		rellocatedbytes.insert(rellocatedbytes.end(), tmpBuffer, tmpBuffer + instruction.length);

		free(tmpBuffer);
		printf("[Info] - Decoder - Relocated a rip-relative memory instruction\n");
	}

	/**
	 *  \brief Creates a decoder instance. The first call do this function initialises the wrapped zydis decoder.
	 */
	Decoder::Decoder()
	{
		static ZydisDecoder decoder;
		if (!_zydisDecoder)
		{
			_zydisDecoder = &decoder;
#ifdef _WIN64
			ZyanStatus status = ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
#elif _WIN32
			ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_ADDRESS_WIDTH_32);
#else
			printf("[Error] - Decoder - Unsupported architecture\n");
#endif
		}
	}

	/**
	 * Creates a vector containing relocated instructions. These instructions are not yet written to the targetAddress.
	 * We need need to know the targetAddress to relocate rip-relative instructions.
	 * We do generate a vector<int8_t> of relocated instructions instead of writing them directly to the target address
	 * to first check if the entire relocation succeeds before writing to the target
	 *
	 * @param sourceAddress starting address of instructions to be relocated
	 * @param length minimum amount of bytes to be relocated. As only complete instructions can be relocated we may relocate more than "length" bytes.
	 * @param targetAddress new starting address for relocated instructions
	 *
	 * @return returns bytes of the relocated instructions
	 */
	std::vector<int8_t> Decoder::Relocate(int8_t* sourceAddress, int length, int8_t* targetAddress, bool restrictedRelocation)
	{
		/* Instructions that need to be relocated
		  32bit:
			- call
			- jcc
			- loopcc
			- XBEGIN //not handled

		   64bit:
			-call
			- jcc
			- loopcc
			- XBEGIN //not handled
			- rip-relative memory access (ModR/M addressing)
		*/

		std::vector<int8_t> relocatedbytes;

		int amountOfBytesRellocated = 0;

		// we will atleast rellocate "length" bytes. To avoid splitting an instruction we might rellocate more.
		while (amountOfBytesRellocated < length)
		{
			ZydisDecodedInstruction instruction;
			int8_t* currentAddress = sourceAddress + amountOfBytesRellocated;

			ZyanStatus decodeResult = ZydisDecoderDecodeBuffer((ZydisDecoder*)_zydisDecoder, currentAddress, MAXIMUM_INSTRUCTION_LENGTH, &instruction);
			if (decodeResult != ZYAN_STATUS_SUCCESS)
			{
				printf("[Error] - Decoder - Could not decode instruction\n");
				return std::vector<int8_t>();
			}
			// the order here matters. We start with more specific relocations. There are for example call instructions that use rip-relative memory accesses
			if (IsCallInstruction(instruction))
			{
				//handle relocation of call instructions
				RelocateCallInstruction(instruction, currentAddress, relocatedbytes);
			}
			else if (IsBranchInstruction(instruction))
			{
				// handle relocation of branch instructions (jcc, loopcc)
				RelocateBranchInstruction(instruction, currentAddress, targetAddress + relocatedbytes.size(), relocatedbytes);
			}
			else if (IsRipRelativeMemoryInstruction(instruction))
			{
				// restricted relocation is enabled when the trampoline could not be allocated withing +-2GB range
				// rip-relative memory instructions may not be able to reach their target address (TODO check this on an instruction based level... there are some cases when this works)
				if (restrictedRelocation)
				{
					printf("[Error] - Decoder - Can't relocate a rip-relative memory access with restricted relocation enabled (trampoline is not in rel32 range). This is currently not supported.\n");
					return std::vector<int8_t>();
				}
				//handle relocation of rip-relative memory addresses (x64 only)
				RelocateRipRelativeMemoryInstruction(instruction, currentAddress, targetAddress + relocatedbytes.size(), relocatedbytes);
			}
			else if (instruction.mnemonic == ZYDIS_MNEMONIC_XBEGIN)
			{
				// XBEGIN causes undefined opcode exception on most computers as intel removed it form the underlying microcode architecture due to security concerns (Zombieload 2 Attack)
				// and even physically removed support for it on never processors
				// additionally windows (and linux) allow for disabling tsx support
				// we expect to never encounter this instruction
				printf("[Error] - Decoder - Encountered XBEGIN instruction which is a relative but unhandled instruction!\n");
				return std::vector<int8_t>();
			}
			else
			{
				//instruction does not need to be modified. Just copy the original Bytes.
				relocatedbytes.insert(relocatedbytes.end(), currentAddress, currentAddress + instruction.length);
			}
			amountOfBytesRellocated += instruction.length;
		}
		return relocatedbytes;
	}

	/**
	 *  \brief Retrieves the length of instructions starting at an address.
	 *
	 *  @param sourceAddress address of the instructions to be examined
	 *  @length minimun amount of bytes to examine
	 *
	 *  @return length of complete instructions with a minimun of the passed length
	 */
	int Decoder::GetLengthOfInstructions(int8_t* sourceAddress, int length)
	{
		int byteCount = 0;

		//we will atleast get "length" bytes. To avoid splitting an instruction we might get more.
		while (byteCount < length)
		{
			ZydisDecodedInstruction instruction;
			int8_t* currentAddress = sourceAddress + byteCount;

			ZyanStatus decodeResult = ZydisDecoderDecodeBuffer((ZydisDecoder*)_zydisDecoder, currentAddress, MAXIMUM_INSTRUCTION_LENGTH, &instruction);
			if (decodeResult != ZYAN_STATUS_SUCCESS)
			{
				printf("[Error] - Decoder - Could not decode instruction\n");
				return 0;
			}
			byteCount += instruction.length;
		}
		return byteCount;
	}

	/**
	 *  \brief Scans memory for specific instruction types. This is mainly used for testing.
	 *
	 *  @param startAddress start address of the scan
	 *  @param type of instrction to scan for
	 *  @length minimum amounf of bytes to search (the scan does not stop in the middle of an instruction)
	 *
	 *  @return length of complete instructions with a minimun of the passed length
	 */
	std::vector<int8_t*> Decoder::FindRelativeInstructionsOfType(int8_t* startAddress, RelativeInstruction type, int length)
	{
		std::vector<int8_t*> foundInstructions;
		int offset = 0;
		ZyanStatus decodeResult = ZYAN_STATUS_FAILED;
		// we will atleast relocate "length" bytes. To avoid splitting an instruction we might relocate more.
		do
		{
			ZydisDecodedInstruction instruction;
			int8_t* currentAddress = startAddress + offset;

			decodeResult = ZydisDecoderDecodeBuffer((ZydisDecoder*)_zydisDecoder, currentAddress, MAXIMUM_INSTRUCTION_LENGTH, &instruction);
			if (decodeResult != ZYAN_STATUS_SUCCESS)
			{
				printf("[Error] - Decoder - Could not decode instruction\n");
				offset += instruction.length;
				continue;
			}

			bool typeFound = false;
			switch (type)
			{
			case RelativeInstruction::CALL:
				if (IsCallInstruction(instruction))
				{
					typeFound = true;
				}
				break;
			case RelativeInstruction::BRANCH:
				if (IsBranchInstruction(instruction))
				{
					typeFound = true;
				}
				break;
			case RelativeInstruction::RIP_RELATIV:
				if (IsRipRelativeMemoryInstruction(instruction) && instruction.mnemonic != ZYDIS_MNEMONIC_CALL) //do not show calls here even though there are rip-relative calls
				{
					typeFound = true;
				}
				break;
			}
			if (typeFound)
			{
				foundInstructions.push_back(currentAddress);
			}
			offset += instruction.length;
		} while (decodeResult == ZYAN_STATUS_SUCCESS || offset < length);
		printf("[Warning] - Decoder - Couldn't find relative instruction of desired type in %d bytes\n", offset);
		return foundInstructions;
	}

	/**
	 * Calculates the lowest and highest rip-relative memory access. These have to be taken into consideration when creating the trampoline
	 * as we can only relocate rip-relative intructions if they can access their original target with "relocated rip" + rel32
	 *
	 * @param sourceAddress start address of instructions to be examined
	 * @param length minimum amount of bytes to examine
	 * @param lowestAddress [out] lowest relative access found
	 * @param highestAddress [out] highest relative access found
	 * @return returns true of the bounds could be calculated. False otherwhise.
	 */
	bool Decoder::CalculateRipRelativeMemoryAccessBounds(int8_t* sourceAddress, int length, int64_t* lowestAddress, int64_t* highestAddress)
	{
		int byteCount = 0;
		uint64_t tmpLowestAddress = 0xffffffffffffffff;
		uint64_t tmpHighestAddress = 0;

		// we will atleast rellocate "length" bytes. To avoid splitting an instruction we might rellocate more.
		while (byteCount < length)
		{
			ZydisDecodedInstruction instruction;
			int8_t* currentAddress = sourceAddress + byteCount;

			ZyanStatus decodeResult = ZydisDecoderDecodeBuffer((ZydisDecoder*)_zydisDecoder, currentAddress, MAXIMUM_INSTRUCTION_LENGTH, &instruction);
			if (decodeResult != ZYAN_STATUS_SUCCESS)
			{
				printf("[Error] - Decoder - Could not decode instruction\n");
				return false;
			}

			// skip non rip-relative instructions
			if (!IsRipRelativeMemoryInstruction(instruction))
			{
				byteCount += instruction.length;
				continue;
			}

			// calculate the absolute address of the rip-relative address. Note: ZydisCalcAbsoluteAddress does not calculate addresses for rip-relative instructions
			const int64_t absoluteTargetAddress = (int64_t)currentAddress + instruction.length + instruction.raw.disp.value;

			if (absoluteTargetAddress < tmpLowestAddress)
			{
				tmpLowestAddress = absoluteTargetAddress;
			}

			if (absoluteTargetAddress > tmpHighestAddress)
			{
				tmpHighestAddress = absoluteTargetAddress;
			}

			byteCount += instruction.length;
		}
		*lowestAddress = tmpLowestAddress;
		*highestAddress = tmpHighestAddress;
		return true;
	}


	int8_t* Decoder::HandleTrampolineAllocation(int8_t* sourceAddress, bool* restrictedRelocation)
	{
		int8_t* trampoline = nullptr;
		// if we can allocate our trampoline in +-2gb range we only need a 5 bytes JMP
		// if we can't, we need a 14 bytes JMP
		int fiveBytesWithoutCuttingInstructions = this->GetLengthOfInstructions(sourceAddress, 5);
		int fourteenBytesWithoutCuttingInstructions = this->GetLengthOfInstructions(sourceAddress, 14);

#ifdef _WIN64 
		int64_t lowestRelativeAddress = 0;
		int64_t hightestRelativeAddress = 0;

		// attempt using 5 bytes 
		if (!this->CalculateRipRelativeMemoryAccessBounds(sourceAddress, fiveBytesWithoutCuttingInstructions, &lowestRelativeAddress, &hightestRelativeAddress))
		{
			printf("[Error] - MidfunctionHook - Could not calculate bounds of relative instructions replaced by hook!\n");
			return nullptr;;
		}

		printf("[Info] - MidfunctionHook - Bounds of relative addresses accessed [%llx, %llx]\n", lowestRelativeAddress, hightestRelativeAddress);

		// check if there was rip-relative memory access
		if (lowestRelativeAddress == 0xffffffffffffffff && hightestRelativeAddress == 0)
		{
			// there was no rip-relative memory acccess
			// attempt to allocate trampoline within +-2GB range of source address
			trampoline = this->AllocateTrampoline(sourceAddress, restrictedRelocation);

			if (!trampoline)
			{
				printf("[Error] - MidfunctionHook - Failed to allocate trampoline for hookAddress %p\n", sourceAddress);
				return nullptr;
			}

			// trampoline could not be allocated withing +-2gb range
			if (restrictedRelocation)
			{
				// there were no rip-relative memory accesses within fiveBytesWithoutCuttingInstructions of the hook address.
				// since we failed to allocate withing +-2GB range we now need to check fourteenBytesWithoutCuttingInstructions for rip-relative instructions
				if (!this->CalculateRipRelativeMemoryAccessBounds(sourceAddress, fourteenBytesWithoutCuttingInstructions, &lowestRelativeAddress, &hightestRelativeAddress))
				{
					printf("[Error] - MidfunctionHook - Could not calculate bounds of relative instructions replaced by hook!\n");
					return nullptr;
				}

				// check if there is rip-relative memory access. Since we need to use a fourteenBytesWithoutCuttingInstructions byte jump we don't support relocating rip-relative instructions
				// if we have rip-relativ memory access here, hooking failed
				if (lowestRelativeAddress == 0xffffffffffffffff && hightestRelativeAddress == 0)
				{
					printf("[Error] - MidfunctionHook - The trampoline could not be allocated withing +-2GB range. The instructions at the hook address do contain rip-relative memory access. Relocating those is not supported when the trampoline is not in +-2GB range!\n");
					return nullptr;
				}
			}
		}
		else
		{
			// there was rip-relative memory access (x64 only)
			trampoline = this->AllocateTrampolineWithinBounds(sourceAddress, lowestRelativeAddress, hightestRelativeAddress, restrictedRelocation);

			if (!trampoline)
			{
				printf("[Error] - MidfunctionHook - Failed to allocate trampoline within bounds [%llx, %llx]\n", lowestRelativeAddress, hightestRelativeAddress);
				return nullptr;
			}

			// we know there is rip-relative memory access within fiveBytesWithoutCuttingInstructions bytes of the hooking address which is supported
			// if we failed to allocate the trampoline withing +-2GB range it is not supported
			if (restrictedRelocation)
			{
				printf("[Error] - MidfunctionHook - The trampoline could not be allocated withing +-2GB range. The instructions at the hook address do contain rip-relative memory access. Relocating those is not supported when the trampoline is not in +-2GB range!\n");
				return nullptr;
			}
		}
#elif _WIN32
		trampoline = this->AllocateTrampoline(sourceAddress, restrictedRelocation);
		if (!trampoline)
		{
			printf("[Error] - MidfunctionHook - Failed to allocate trampoline for hookAddress %p\n", sourceAddress);
			return nullptr;
		}

		// only the 5 byte JMP rel32 exists in 32bit
		//this->hookLength_ = fiveBytesWithoutCuttingInstructions;
#endif
		return trampoline;
	}


	int8_t* Decoder::AllocateTrampoline(int8_t* sourceAddress, bool* restrictedRelocation)
	{
		// we attempt to use a rel32 JMP as this allows to relocate RIP-relative memory accesses conveniently
		const int32_t signedIntMaxValue = 0x7fffffff;

		// allocate the trampoline_. We need to allocate this first so we know how many bytes we need to overwrite (5 or 14 Bytes)
		SYSTEM_INFO systemInfo;
		GetSystemInfo(&systemInfo);
		int64_t allocationAttempts = 0;

		// calculate the lowest and highest address than can be reached by a jmp rel32 when placing it at the hookAddress
		int64_t lowestAddressReachableByFiveBytesJump = (int64_t)sourceAddress - signedIntMaxValue + 5;
		if (lowestAddressReachableByFiveBytesJump < 0)
		{
			lowestAddressReachableByFiveBytesJump = 0;
		}

		printf("[Info] - MidfunctionHook - Attempting to allocate trampoline within +-2GB range of %p\n", sourceAddress);
		int8_t* trampoline = nullptr;
		int64_t targetAddress = 0;
		while (!trampoline)
		{
#ifdef _WIN64
			// start with the highest possible address and go down by one pageSize for every attempt. VirtualAlloc rounds down to nearest multiple of allocation granularity.
			// we start by substracting 1 page (++allocationAttempts) to account for VirtualAlloc rounding down the target address to the next page boundary
			targetAddress = (int64_t)sourceAddress + signedIntMaxValue + 5 - (++allocationAttempts * systemInfo.dwPageSize);
#elif _WIN32
			// for 32 bit only addresses up to 0x7fffffff are in user mode and we can only allocate user mode memory
			targetAddress = signedIntMaxValue - ++allocationAttempts * systemInfo.dwPageSize;
#endif

			// check if the target address can still be reached with rel32. If the target address is too low, we failed to allocate it withing JMP rel32 range.
			if ((int64_t)targetAddress >= lowestAddressReachableByFiveBytesJump)
			{
				auto tmp = (int8_t*)targetAddress;
				// attempt to allocate the trampoline. If we fail, we try again on the next loop iteration.
				// we don't need to worry if our targetAddress is high enough because we start at the highest value that we can use and move down 
				trampoline = (int8_t*)VirtualAlloc((int8_t*)targetAddress, systemInfo.dwPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			}
			else
			{
#ifdef _WIN64
				//If we couldn't allocate within +-2GB range let the system allocate the memory page anywhere and use and absolute jump. JMP [RIP+0] 0x1122334455667788 (14 Bytes)
				trampoline = (int8_t*)VirtualAlloc(NULL, systemInfo.dwPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

				//we now require 14 bytes at the hook address to write an absolute JMP and we no longer can relocate rip-relative memory accesses
				*restrictedRelocation = true;

				printf("[Warning] - MidfunctionHook - Could not allocate trampoline within desired range. We currently can't relocate rip-relative instructions in this case!\n");

				return trampoline;

#elif _WIN32
				*restrictedRelocation = false;
				// we currently have no way to deal with situation in 32 Bits. I never observed this to be an issue though. There may be a guarantee that this never happens?
				return nullptr;
#endif
				*restrictedRelocation = false;
				// this should not be reached
				return nullptr;
			}
		}
		printf("[Info] - MidfunctionHook - Allocated trampoline at %p (using %lld attempts)\n", trampoline, allocationAttempts);
		*restrictedRelocation = false;
		return trampoline;
	}

	/**
	 * Attempts to allocate a trampoline_ within +-2gb range with respect to rip-relative memory accesses.
	 */
	int8_t* Decoder::AllocateTrampolineWithinBounds(int8_t* sourceAddress, int64_t lowestRipRelativeMemoryAccess, int64_t highestRipRelativeMemoryAddress, bool* restrictedRelocation)
	{
		const int32_t signedIntMaxValue = 0x7fffffff;

		// allocate the trampoline_. We need to allocate this first so we know how many bytes we need to overwrite (5 or 14 Bytes)
		SYSTEM_INFO systemInfo;
		GetSystemInfo(&systemInfo);
		int64_t allocationAttempts = 0;

		// the size of the static part of the trampoline is 467 Bytes. Additionally relocated Bytes are appended to the trampoline. The length of these instructions depends on the instructions relocated.
		// relocated instructions can be longer than the original ones. At the time of writing this the worst case is jcc from 2 Bytes to 18 Bytes when relocated.
		// the value here is just an upper bound that allows to double the size of the trampoline
		const int trampolineLengthUpperBound = 1000;

		// calculate the lowest and highest address than can be reached by a jmp rel32 when placing it at the hookAddress
		int64_t lowestAddressReachableByFiveBytesJump = (int64_t)sourceAddress - signedIntMaxValue + 5;
		if (lowestAddressReachableByFiveBytesJump < 0)
		{
			lowestAddressReachableByFiveBytesJump = 0;
		}

		int64_t highestAddressReachableByFiveBytesJump = (int64_t)sourceAddress + signedIntMaxValue + 5;

		int64_t lowestAddressThatCanReachHighestRipRelativeAccess = highestRipRelativeMemoryAddress - signedIntMaxValue + 5;

		// calculate the highest address that can still reach the lowest rip-relative access
		int64_t highestAddressThatCanReachLowestRipRelativeAccess = lowestRipRelativeMemoryAccess + signedIntMaxValue - 5;

		// we want to start allocation attempts with the highest address that can reach the lowest rip-relative memory access and is reachable with jmp rel32 from the hook address
		int64_t initialTargetAddress = highestAddressThatCanReachLowestRipRelativeAccess;
		if (initialTargetAddress > highestAddressReachableByFiveBytesJump)
		{
			initialTargetAddress = highestAddressReachableByFiveBytesJump;
		}

		printf("[Info] - MidfunctionHook - Attempting to allocate trampoline within +-2GB range of [%llx, %llx] with a trampoline maximum size of %d\n", lowestRipRelativeMemoryAccess, highestRipRelativeMemoryAddress, trampolineLengthUpperBound);
		int8_t* trampoline = nullptr;
		while (!trampoline)
		{
			// allocation attempts are started from the highest possible address to the lowest. We substract dwPageSize to account for VirtualAlloc rounding down the target address to the next page boundary. 
			// start with highest address that can both: 
			// - reach lowest RIP-relative
			// - can be reached by jmp rel32
			int8_t* targetAddress = (int8_t*)initialTargetAddress - trampolineLengthUpperBound - (++allocationAttempts * systemInfo.dwPageSize);

			// check if we are still high enough
			// we know we failed to allocate with rel32 when one of these statements is true:
			// - address is to low to be reached by rel32
			// - address is to low to reach highestRipRelativeMemoryAccess
			if (!((int64_t)targetAddress < lowestAddressReachableByFiveBytesJump) &&
				!((int64_t)targetAddress < lowestAddressThatCanReachHighestRipRelativeAccess))
			{
				// try to allocate trampoline_ within "JMP rel32" range so we can hook by overwriting 5 Bytes instead of 14 Bytes
				// we don't need to worry if our targetAddress is high enough because we start at the highest value that we can use and move down 
				// if the call with this target address fails we keep trying
				trampoline = (int8_t*)VirtualAlloc(targetAddress, systemInfo.dwPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			}
			else
			{
#ifdef _WIN64
				// if we couldn't allocate within +-2GB range let the system allocate the memory page anywhere and use and absolute jump. JMP [RIP+0] 0x1122334455667788 (14 Bytes)
				trampoline = (int8_t*)VirtualAlloc(NULL, systemInfo.dwPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

				// we now require 14 bytes at the hook address to write an absolute JMP and we no longer can relocate rip-relative memory accesses
				*restrictedRelocation = true;

				printf("[Warning] - MidfunctionHook - Could not allocate trampoline within desired range. We currently can't relocate rip-relative instructions in this case!\n");
				return trampoline;

#elif _WIN32
				*restrictedRelocation = false;
				// we currently have no way to deal with this situation in 32 Bits. I never observed this to be an issue though. There may be a guarantee that this never happens?
				return false;
#endif
				// this should not be reached
				*restrictedRelocation = false;
				return false;
			}
		}
		printf("[Info] - MidfunctionHook - Allocated trampoline at %p (using %lld attempts)\n", trampoline, allocationAttempts);
		*restrictedRelocation = false;
		return trampoline;
	}
}
