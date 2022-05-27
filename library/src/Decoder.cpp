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
	 *	@return true if the passed instruction contains a rip-relative memory access (x64 only). false otherwhise.
	 */
	bool IsRipRelativeMemoryInstruction(ZydisDecodedInstruction& instruction)
	{
#ifdef _WIN64
		// For reference see: https://software.intel.com/content/www/us/en/develop/download/intel-64-and-ia-32-architectures-sdm-combined-volumes-2a-2b-2c-and-2d-instruction-set-reference-a-z.html
		// Table 2-2. 32-Bit Addressing Forms with the ModR/M Byte (x64 only)
		return instruction.attributes & ZYDIS_ATTRIB_HAS_MODRM &&
			instruction.raw.modrm.mod == 0 && instruction.raw.modrm.rm == 5; //disp32 see table	
#elif _WIN32
		// there is no RIP-relative memory address in 32 bit
		return false;
#endif
	}

	/**
	 *  \brief Relocates a call instruction by calculating its absolute target address
	 *
	 *	@param instruction call instruction to be relocated
	 *	@param instructionAddress original address of the call instruction
	 *	@param relocatedbytes relocated bytes
	 */
	bool RelocateCallInstruction(ZydisDecodedInstruction& instruction, const ZydisDecodedOperand* operand, int8_t* instructionAddress, std::vector<int8_t>& relocatedbytes)
	{
		ZyanU64 originalJumpTarget;
		if (instruction.attributes & ZYDIS_ATTRIB_HAS_MODRM)
		{
			if (instruction.raw.modrm.mod == 0 && instruction.raw.modrm.rm == 5)
			{
#ifdef _WIN64
				// disp32 see ModR/M table (intel manual)
				ZydisCalcAbsoluteAddress(&instruction, operand, (ZyanU64)instructionAddress, &originalJumpTarget);

				// we can use rax here as it has not to be preserved in function calls
				const int relocatedCallInstructionsLength = 12;
				int8_t relocatedCallInstructions[relocatedCallInstructionsLength] = {
					0x48, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,			//movabs rax, 0x1122334455667788. 
					0xFF, 0x10															//call   [rax]
				};
				*(uint64_t*)&relocatedCallInstructions[2] = originalJumpTarget;
				relocatedbytes.insert(relocatedbytes.end(), relocatedCallInstructions, relocatedCallInstructions + relocatedCallInstructionsLength);
#elif _WIN32
				// just copy original call instruction. There is no rip-relative addressing in 32 bit. The displacement is relative to 0.
				relocatedbytes.insert(relocatedbytes.end(), instructionAddress, instructionAddress + instruction.length);
#endif 
			}
			else
			{
				// just copy original call instruction
				relocatedbytes.insert(relocatedbytes.end(), instructionAddress, instructionAddress + instruction.length);
			}
		}
		else
		{
			// e8 calls.. CALL rel16, CALL rel32,
			// 9a calls.. CALL ptr16:16, CALL ptr16:32 are not handled (no support for 16 bit architecture)
			ZydisCalcAbsoluteAddress(&instruction, operand, (ZyanU64)instructionAddress, &originalJumpTarget);

#ifdef _WIN64
			const int relocatedCallInstructionsLength = 12;
			// we can use rax here as it has not to be preserved in function calls
			int8_t relocatedCallInstructions[relocatedCallInstructionsLength] = {
				0x48, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,			//movabs rax, 0x1122334455667788. 
				0xFF, 0xD0															//call   rax
			};
			*(uint64_t*)&relocatedCallInstructions[2] = originalJumpTarget;
			relocatedbytes.insert(relocatedbytes.end(), relocatedCallInstructions, relocatedCallInstructions + relocatedCallInstructionsLength);
#elif _WIN32
			const int relocatedCallInstructionsLength = 7;
			// we can use eax here as it has not to be preserved in function calls
			int8_t relocatedCallInstructions[relocatedCallInstructionsLength] = {
				0xB8, 0x44, 0x33, 0x22, 0x11,			//mov  eax,0x11223344
				0xFF, 0xD0								//call eax
			};
			*(uint32_t*)&relocatedCallInstructions[1] = originalJumpTarget;
			relocatedbytes.insert(relocatedbytes.end(), relocatedCallInstructions, relocatedCallInstructions + relocatedCallInstructionsLength);
#endif
		}
		// the program can return to the return address pushed on the stack (at time of the call) at any time.
		// if the hook is removed (and therefore the trampoline freed) the return address might not contain valid code --> crash
		printf("[Warning] - Decoder - Relocated a call instruction. Unhooking is not safe!\n");
		return true;
	}

	/**
	 *  \brief Relocates a branch instruction
	 *
	 *	@param instruction branch instruction to be relocated
	 *	@param instructionAddress original address of the branch instruction
	 *	@param relocatedbytes relocated bytes
	 */
	bool RelocateBranchInstruction(ZydisDecodedInstruction& instruction, const ZydisDecodedOperand* operand, int8_t* instructionAddress, int8_t* relocatedInstructionAddress, std::vector<int8_t>& relocatedbytes)
	{
		ZyanU64 originalJumpTarget;
		ZydisCalcAbsoluteAddress(&instruction, operand, (ZyanU64)instructionAddress, &originalJumpTarget);

		// handle conditional jumps (jcc) by using 2 jmp
		if (instruction.mnemonic != ZYDIS_MNEMONIC_JMP)
		{
			relocatedbytes.insert(relocatedbytes.end(), instructionAddress, instructionAddress + instruction.length);
			const int elementSizeInBytes = operand[0].element_size / 8;
			//suppport jcc rel8, jcc rel16, jcc rel32. JCC always has the offset in its first operand. Fill remmaining bytes with '0'
			for (int i = 1; i < elementSizeInBytes - 1; i++)
			{
				relocatedbytes[relocatedbytes.size() - i] = 0x0;
			}
			relocatedbytes[relocatedbytes.size() - elementSizeInBytes] = 0x2;

#ifdef _WIN64
			// jmp after jcc instruction because jcc is not taken
			relocatedbytes.push_back(0xEB);	//jmp    0x10
			relocatedbytes.push_back(0xE);	//

			// jmp for when jcc is taken
			// we use an absolute JMP for x64 as this allows to relocate jcc instructions to a trampoline that is more than +-2GB away
			relocatedbytes.push_back(0xFF);	//opcodes = JMP [rip+0]
			relocatedbytes.push_back(0x25);	//
			relocatedbytes.push_back(0x0);	//
			relocatedbytes.push_back(0x0);	//
			relocatedbytes.push_back(0x0);	//
			relocatedbytes.push_back(0x0);	//

			relocatedbytes.insert(relocatedbytes.end(), (int8_t*)&originalJumpTarget, (int8_t*)&originalJumpTarget + 8); //destination to jump to: 8 Bytes

#elif _WIN32
			// jmp after jcc instruction because jcc is not taken
			relocatedbytes.push_back(0xEB);	//jmp    0x07
			relocatedbytes.push_back(0x5);	//

			// use relative jmp
			// write JMP from original code to trampoline_
			// we substract 5 because the jmp is relative from the address of the next instruciton and the length of the JMP itself is 5
			int32_t newRelativeAddress = (int32_t)((int64_t)originalJumpTarget - (int64_t)relocatedInstructionAddress - 5 - 2 - instruction.length);

			relocatedbytes.push_back(0xe9);																				//opcodes = JMP rel32
			relocatedbytes.insert(relocatedbytes.end(), (int8_t*)&newRelativeAddress, (int8_t*)&newRelativeAddress + 4);	//4 byte relative jump address
#endif
		}
		else
		{
			// handle JMP instruction
			// relocation of jmp instructions
			if (instruction.attributes & ZYDIS_ATTRIB_IS_RELATIVE)
			{
#ifdef _WIN64
				if (instruction.opcode == 0xff)
				{
					const int lengthOfIndirectJmpInstruction = 6;
					int64_t delta = originalJumpTarget - (int64_t)relocatedInstructionAddress - lengthOfIndirectJmpInstruction;

					if (delta > INT32_MAX || delta < INT32_MIN)
					{
						// use absolute direct jmp
						// if the opcode is 0xff we have to dereference the calculated address since the instructions contains the memory location of the jmp target, not the target itself
						// JMP m16:64, JMP m16:32
						originalJumpTarget = *(int64_t*)originalJumpTarget;

						// use absolute jmp
						relocatedbytes.push_back(0xFF);	//opcodes = JMP [rip+0]
						relocatedbytes.push_back(0x25);	//
						relocatedbytes.push_back(0x0);	//
						relocatedbytes.push_back(0x0);	//
						relocatedbytes.push_back(0x0);	//
						relocatedbytes.push_back(0x0);	//

						relocatedbytes.insert(relocatedbytes.end(), (int8_t*)&originalJumpTarget, (int8_t*)&originalJumpTarget + 8); // destination to jump to: 8 Bytes

						printf("[Warning] - Decoder - Relocated an indirect branch instruction by using a direct JMP because the memory address could not be reached. This may result in undifined behavior\n");
					}
					else
					{
						// use indirect memory jmp
						relocatedbytes.push_back(0xFF);	//opcodes = JMP [rip+displacement]
						relocatedbytes.push_back(0x25);
						relocatedbytes.insert(relocatedbytes.end(), (int8_t*)&delta, (int8_t*)&delta + 4); // 4 byte displacement
					}

				}
				else
				{
					// use absolute jmp
					relocatedbytes.push_back(0xFF);	//opcodes = JMP [rip+0]
					relocatedbytes.push_back(0x25);	//
					relocatedbytes.push_back(0x0);	//
					relocatedbytes.push_back(0x0);	//
					relocatedbytes.push_back(0x0);	//
					relocatedbytes.push_back(0x0);	//

					relocatedbytes.insert(relocatedbytes.end(), (int8_t*)&originalJumpTarget, (int8_t*)&originalJumpTarget + 8); // destination to jump to: 8 Bytes
				}

#elif _WIN32
				// this -5 accounts for using the 5 byte jmp. Even to relocate jmp rel8/rel16/rel32 are all relocated using a 5 byte JMP
				int32_t newRelativeAddress = (int32_t)((int64_t)originalJumpTarget - (int64_t)relocatedInstructionAddress - 5);

				relocatedbytes.push_back(0xe9);																					// opcodes = JMP rel32
				relocatedbytes.insert(relocatedbytes.end(), (int8_t*)&newRelativeAddress, (int8_t*)&newRelativeAddress + 4);	// 4 byte relative jump address
#endif
			}
			else
			{
				// just copy instructions such as "jmp reg"
				relocatedbytes.insert(relocatedbytes.end(), instructionAddress, instructionAddress + instruction.length);
			}
		}

		printf("[Info] - Decoder - Relocated a branch instruction\n");
		return true;
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
	 *	@param relocatedbytes relocated bytes
	 *
	 *  @return true if successful, false otherwise.
	 */
	bool RelocateRipRelativeMemoryInstruction(ZydisDecodedInstruction& instruction, int8_t* instructionAddress, int8_t* relocatedInstructionAddress, std::vector<int8_t>& relocatedbytes)
	{
		int8_t* tmpBuffer = (int8_t*)malloc(instruction.length);

		// copy original instruction
		memcpy(tmpBuffer, instructionAddress, instruction.length);

		// calculate the absolute address of the rip-relative address
		const int8_t* absoluteAddress = instructionAddress + instruction.length + instruction.raw.disp.value;

		const int64_t relocatedRelativeAddress = (int64_t)absoluteAddress - (int64_t)relocatedInstructionAddress - instruction.length;

		// check if new displacement is within int32_t range
		if (relocatedRelativeAddress > INT32_MAX || relocatedRelativeAddress < INT32_MIN)
		{
			printf("[Error] - Decoder - Failed to relocate a rip-relative memory instruction. RelocatedRelativeAddress: %llx\n", relocatedRelativeAddress);
			free(tmpBuffer);
			return false;
		}

		// write relocated relative address to the relocated instrucions displacement
		*(int32_t*)&tmpBuffer[instruction.raw.disp.offset] = relocatedRelativeAddress;

		// add bytes of relocated instructions to relocated instuctions
		relocatedbytes.insert(relocatedbytes.end(), tmpBuffer, tmpBuffer + instruction.length);

		free(tmpBuffer);
		printf("[Info] - Decoder - Relocated a rip-relative memory instruction\n");
		return true;
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
			ZyanStatus status = ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
#elif _WIN32
			ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_ADDRESS_WIDTH_32);
#else
			printf("[Error] - Decoder - Unsupported architecture\n");
#endif
		}
	}

	/**
	 * \brief Relocates assembler instructions and preserves their original semantic.
	 *
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

		int amountOfBytesrelocated = 0;

		// we will atleast relocate "length" bytes. To avoid splitting an instruction we might relocate more
		while (amountOfBytesrelocated < length)
		{
			ZydisDecodedInstruction instruction;
			int8_t* currentAddress = sourceAddress + amountOfBytesrelocated;
			ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE];
			ZyanStatus decodeResult = ZydisDecoderDecodeFull((ZydisDecoder*)_zydisDecoder, currentAddress, MAXIMUM_INSTRUCTION_LENGTH, &instruction, operands, ZYDIS_MAX_OPERAND_COUNT_VISIBLE, ZYDIS_DFLAG_VISIBLE_OPERANDS_ONLY);
			if (decodeResult != ZYAN_STATUS_SUCCESS)
			{
				printf("[Error] - Decoder - Could not decode instruction\n");
				return std::vector<int8_t>();
			}


			// the order here matters. We start with more specific relocations. There are for example call instructions that use rip-relative memory accesses
			if (IsCallInstruction(instruction))
			{
				// handle relocation of call instructions
				if (!RelocateCallInstruction(instruction, operands, currentAddress, relocatedbytes))
				{
					printf("[Error] - Decoder - Failed to relocate call instruction\n");
					return std::vector<int8_t>();
				}
			}
			else if (IsBranchInstruction(instruction))
			{
				// handle relocation of branch instructions (jcc, loopcc)
				if (!RelocateBranchInstruction(instruction, operands, currentAddress, targetAddress + relocatedbytes.size(), relocatedbytes))
				{
					printf("[Error] - Decoder - Failed to relocate branch instruction\n");
					return std::vector<int8_t>();
				}
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
				// handle relocation of rip-relative memory addresses (x64 only)
				if (!RelocateRipRelativeMemoryInstruction(instruction, currentAddress, targetAddress + relocatedbytes.size(), relocatedbytes))
				{
					this->PrintInstructions(currentAddress, 1);
					printf("[Error] - Decoder - Failed to relocate rip-relative instruction\n");
					return std::vector<int8_t>();
				}
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
				// instruction does not need to be modified. Just copy the original Bytes.
				relocatedbytes.insert(relocatedbytes.end(), currentAddress, currentAddress + instruction.length);
			}
			amountOfBytesrelocated += instruction.length;
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

		// we will atleast get "length" bytes. To avoid splitting an instruction we might get more.
		while (byteCount < length)
		{
			ZydisDecodedInstruction instruction;
			int8_t* currentAddress = sourceAddress + byteCount;
			ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE];
			ZyanStatus decodeResult = ZydisDecoderDecodeFull((ZydisDecoder*)_zydisDecoder, currentAddress, MAXIMUM_INSTRUCTION_LENGTH, &instruction, operands, ZYDIS_MAX_OPERAND_COUNT_VISIBLE, ZYDIS_DFLAG_VISIBLE_OPERANDS_ONLY);
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

			ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE];
			ZyanStatus decodeResult = ZydisDecoderDecodeFull((ZydisDecoder*)_zydisDecoder, currentAddress, MAXIMUM_INSTRUCTION_LENGTH, &instruction, operands, ZYDIS_MAX_OPERAND_COUNT_VISIBLE, ZYDIS_DFLAG_VISIBLE_OPERANDS_ONLY);
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
	 * \brief  Calculates the lowest and highest rip-relative memory access.
	 *
	 * These accesses have to be taken into consideration when creating the trampoline as we can only relocate rip-relative intructions if they can access their original target with "relocated rip" + rel32
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

		// we will atleast relocate "length" bytes. To avoid splitting an instruction we might relocate more.
		while (byteCount < length)
		{
			ZydisDecodedInstruction instruction;
			int8_t* currentAddress = sourceAddress + byteCount;
			ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE];
			ZyanStatus decodeResult = ZydisDecoderDecodeFull((ZydisDecoder*)_zydisDecoder, currentAddress, MAXIMUM_INSTRUCTION_LENGTH, &instruction, operands, ZYDIS_MAX_OPERAND_COUNT_VISIBLE, ZYDIS_DFLAG_VISIBLE_OPERANDS_ONLY);
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

	/**
	 * \brief Disassembles intructions and prints them
	 *
	 * @param address Address to start disassembling
	 * @param byteCount amount of bytes to disassemble
	 */
	void Decoder::PrintInstructions(int8_t* address, size_t byteCount)
	{
		ZyanU8* data = (ZyanU8*)address;

		// initialize decoder context
		ZydisDecoder decoder;

#ifdef _WIN64
		ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
#elif _WIN32
		ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_ADDRESS_WIDTH_32);
#else
		printf("[Error] - Disassembler - Unsupported architecture\n");
#endif
		// loop over the instructions in our buffer.
		// the runtime-address (instruction pointer) is chosen arbitrary here in order to better visualize relative addressing
		ZyanU64 runtime_address = (ZyanU64)address;
		ZyanUSize offset = 0;
		ZydisDecodedInstruction instruction;

		while (offset < byteCount)
		{
			ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE];
			ZyanStatus decodeResult = ZydisDecoderDecodeFull((ZydisDecoder*)_zydisDecoder, data + offset, MAXIMUM_INSTRUCTION_LENGTH, &instruction, operands, ZYDIS_MAX_OPERAND_COUNT_VISIBLE, ZYDIS_DFLAG_VISIBLE_OPERANDS_ONLY);
			if (decodeResult != ZYAN_STATUS_SUCCESS)
			{
				printf("[Error] - Decoder - Could not decode instruction\n");
				return;
			}

			ZydisFormatter formatter;
			ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

			char buffer[256];
			printf("[%llx]", runtime_address);
			ZydisFormatterFormatInstruction(&formatter, &instruction, operands, operands->element_count, buffer, sizeof(buffer), runtime_address);
			printf("%s\n", buffer);

			offset += instruction.length;
			runtime_address += instruction.length;
		}
	}

}
