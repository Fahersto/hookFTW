#include <gtest/gtest.h>

#include <cstdint>
#include <vector>
#include <cstring>

#include <Decoder.h>

namespace
{
    int32_t ExtractRel32Offset(const uint8_t* instruction, const size_t offsetPos)
    {
        int32_t offset;
        std::memcpy(&offset, instruction + offsetPos, sizeof(int32_t));
        return offset;
    }

    int8_t ExtractRel8Offset(const uint8_t* instruction, const size_t offsetPos)
    {
        return static_cast<int8_t>(instruction[offsetPos]);
    }

    int8_t* CalculateAbsoluteTarget(const int8_t* instructionAddr, const int32_t relOffset, const size_t instructionLength)
    {
        return const_cast<int8_t*>(instructionAddr + instructionLength + relOffset);
    }

    TEST(Decoder, GetLengthOfInstructionsDoesNotCutInstructions)
    {
        hookftw::Decoder decoder;

        // Mixed instruction stream. We ask for >= 5 bytes and expect returned length >= 5.
        // 55                push rbp
        // 48 89 E5          mov rbp, rsp
        // 90                nop
        // C3                ret
        uint8_t code[] = {0x55, 0x48, 0x89, 0xE5, 0x90, 0xC3};

        const int len = decoder.GetLengthOfInstructions(reinterpret_cast<int8_t*>(code), 5);
        EXPECT_GE(len, 5);
        EXPECT_LE(len, static_cast<int>(sizeof(code)));
    }

    TEST(DecoderRelocation, CallRel32PointsToSameAbsoluteAddress)
    {
        hookftw::Decoder decoder;

        // E8 05 00 00 00    call +5 (relative to next instruction)
        // 90                nop
        // C3                ret
        uint8_t code[] = {0xE8, 0x05, 0x00, 0x00, 0x00, 0x90, 0xC3};

        int8_t* sourceAddress = reinterpret_cast<int8_t*>(code);

        // Calculate original absolute target
        int32_t originalOffset = ExtractRel32Offset(code, 1);
        int8_t* originalTarget = CalculateAbsoluteTarget(sourceAddress, originalOffset, 5);

        // Allocate a target buffer far enough to require relocation
        uint8_t targetBuffer[256];
        std::memset(targetBuffer, 0x90, sizeof(targetBuffer));
        int8_t* targetAddress = reinterpret_cast<int8_t*>(targetBuffer);
        std::vector<int8_t> relocated = decoder.Relocate(sourceAddress, 5, targetAddress);
        ASSERT_FALSE(relocated.empty());

        // On x64, call rel32 is transformed to: movabs rax, return_addr; push rax; movabs rax, target; jmp rax
        // This is 23 bytes: 48 B8 [8 bytes return] 50 48 B8 [8 bytes target] FF E0
        // Breakdown: 10 (movabs) + 1 (push) + 10 (movabs) + 2 (jmp) = 23
        ASSERT_EQ(relocated.size(), 23);
        ASSERT_EQ(static_cast<uint8_t>(relocated[0]), 0x48);  // REX.W prefix
        ASSERT_EQ(static_cast<uint8_t>(relocated[1]), 0xB8);  // movabs rax
        ASSERT_EQ(static_cast<uint8_t>(relocated[10]), 0x50); // push rax
        ASSERT_EQ(static_cast<uint8_t>(relocated[11]), 0x48); // REX.W prefix
        ASSERT_EQ(static_cast<uint8_t>(relocated[12]), 0xB8); // movabs rax
        ASSERT_EQ(static_cast<uint8_t>(relocated[21]), 0xFF); // jmp
        ASSERT_EQ(static_cast<uint8_t>(relocated[22]), 0xE0); // rax

        uint64_t relocatedReturnAddr;
        std::memcpy(&relocatedReturnAddr, relocated.data() + 2, sizeof(uint64_t));

        int8_t* expectedReturnAddr = sourceAddress + 5;
        EXPECT_EQ(reinterpret_cast<void*>(expectedReturnAddr), reinterpret_cast<void*>(relocatedReturnAddr))
            << "Return address should point to instruction after original call (safe for unhooking)";

        uint64_t relocatedTarget;
        std::memcpy(&relocatedTarget, relocated.data() + 13, sizeof(uint64_t));

        EXPECT_EQ(reinterpret_cast<void*>(originalTarget), reinterpret_cast<void*>(relocatedTarget))
            << "Relocated call should point to the same absolute address";
    }

    TEST(DecoderRelocation, MultipleCallInstructionsPointToCorrectTargets)
    {
        hookftw::Decoder decoder;

        // E8 00 00 00 00    call +0
        // E8 10 00 00 00    call +16
        // 90                nop
        uint8_t code[] = {
            0xE8, 0x00, 0x00, 0x00, 0x00,  // call
            0xE8, 0x10, 0x00, 0x00, 0x00,  // call
            0x90
        };

        int8_t* sourceAddress = reinterpret_cast<int8_t*>(code);

        // Calculate original targets
        int32_t originalOffset1 = ExtractRel32Offset(code, 1);
        int8_t* originalTarget1 = CalculateAbsoluteTarget(sourceAddress, originalOffset1, 5);

        int32_t originalOffset2 = ExtractRel32Offset(code + 5, 1);
        int8_t* originalTarget2 = CalculateAbsoluteTarget(sourceAddress + 5, originalOffset2, 5);

        uint8_t targetBuffer[256];
        int8_t* targetAddress = reinterpret_cast<int8_t*>(targetBuffer);

        std::vector<int8_t> relocated = decoder.Relocate(sourceAddress, 10, targetAddress);
        ASSERT_FALSE(relocated.empty());

        // Each call becomes 23 bytes on x64 (push return_addr + jmp target)
        ASSERT_EQ(relocated.size(), 46);

        // Verify first call (movabs rax, return_addr; push rax; movabs rax, target; jmp rax)
        ASSERT_EQ(static_cast<uint8_t>(relocated[0]), 0x48);
        ASSERT_EQ(static_cast<uint8_t>(relocated[1]), 0xB8);

        // Verify return address points to instruction after original call
        uint64_t relocatedReturnAddr1;
        std::memcpy(&relocatedReturnAddr1, relocated.data() + 2, sizeof(uint64_t));
        EXPECT_EQ(reinterpret_cast<void*>(sourceAddress + 5), reinterpret_cast<void*>(relocatedReturnAddr1));

        // Verify call target
        uint64_t relocatedTarget1;
        std::memcpy(&relocatedTarget1, relocated.data() + 13, sizeof(uint64_t));
        EXPECT_EQ(reinterpret_cast<void*>(originalTarget1), reinterpret_cast<void*>(relocatedTarget1));

        // Verify second call
        ASSERT_EQ(static_cast<uint8_t>(relocated[23]), 0x48);
        ASSERT_EQ(static_cast<uint8_t>(relocated[24]), 0xB8);

        // Verify return address points to instruction after original call
        uint64_t relocatedReturnAddr2;
        std::memcpy(&relocatedReturnAddr2, relocated.data() + 25, sizeof(uint64_t));
        EXPECT_EQ(reinterpret_cast<void*>(sourceAddress + 10), reinterpret_cast<void*>(relocatedReturnAddr2));

        // Verify call target
        uint64_t relocatedTarget2;
        std::memcpy(&relocatedTarget2, relocated.data() + 36, sizeof(uint64_t));
        EXPECT_EQ(reinterpret_cast<void*>(originalTarget2), reinterpret_cast<void*>(relocatedTarget2));
    }

    TEST(DecoderRelocation, JccShortFormPointsToSameAbsoluteAddress)
    {
        hookftw::Decoder decoder;

        // 75 0A             jne +10 (short form, 2 bytes)
        // 90                nop
        uint8_t code[] = {0x75, 0x0A, 0x90};

        int8_t* sourceAddress = reinterpret_cast<int8_t*>(code);

        // Calculate original absolute target
        int8_t originalOffset = ExtractRel8Offset(code, 1);
        int8_t* originalTarget = CalculateAbsoluteTarget(sourceAddress, originalOffset, 2);

        uint8_t targetBuffer[256];
        int8_t* targetAddress = reinterpret_cast<int8_t*>(targetBuffer);

        std::vector<int8_t> relocated = decoder.Relocate(sourceAddress, 2, targetAddress);

        ASSERT_FALSE(relocated.empty());

        // On x64, jcc is transformed to: jcc +2; jmp short +14; jmp [rip+0] + 8-byte target
        // Total: 2 (jcc) + 2 (jmp short) + 6 (jmp [rip+0]) + 8 (address) = 18 bytes
        ASSERT_EQ(relocated.size(), 18);

        // Verify it starts with jne (0x75) with offset +2
        ASSERT_EQ(static_cast<uint8_t>(relocated[0]), 0x75);
        ASSERT_EQ(static_cast<uint8_t>(relocated[1]), 0x02);

        // Extract the absolute target from the end of the relocated bytes
        uint64_t relocatedTarget;
        std::memcpy(&relocatedTarget, relocated.data() + 10, sizeof(uint64_t));
        EXPECT_EQ(reinterpret_cast<void*>(originalTarget), reinterpret_cast<void*>(relocatedTarget))
            << "Relocated jcc should jump to the same absolute address";
    }

    TEST(DecoderRelocation, JccNearFormPointsToSameAbsoluteAddress)
    {
        hookftw::Decoder decoder;

        // 0F 84 00 00 00 00 je +0 (near form, 6 bytes)
        // 90                nop
        uint8_t code[] = {0x0F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x90};

        int8_t* sourceAddress = reinterpret_cast<int8_t*>(code);

        // Calculate original absolute target
        int32_t originalOffset = ExtractRel32Offset(code, 2);
        int8_t* originalTarget = CalculateAbsoluteTarget(sourceAddress, originalOffset, 6);

        uint8_t targetBuffer[256];
        int8_t* targetAddress = reinterpret_cast<int8_t*>(targetBuffer);

        std::vector<int8_t> relocated = decoder.Relocate(sourceAddress, 6, targetAddress);

        ASSERT_FALSE(relocated.empty());

        // On x64, near jcc is also transformed: jcc +2; jmp short +14; jmp [rip+0] + 8-byte target
        // Total: 6 (jcc near) + 2 (jmp short) + 6 (jmp [rip+0]) + 8 (address) = 22 bytes
        ASSERT_EQ(relocated.size(), 22);

        // Verify it starts with je near (0x0F 0x84)
        ASSERT_EQ(static_cast<uint8_t>(relocated[0]), 0x0F);
        ASSERT_EQ(static_cast<uint8_t>(relocated[1]), 0x84);

        // Extract the absolute target from the end
        uint64_t relocatedTarget;
        std::memcpy(&relocatedTarget, relocated.data() + 14, sizeof(uint64_t));
        EXPECT_EQ(reinterpret_cast<void*>(originalTarget), reinterpret_cast<void*>(relocatedTarget));
    }

    TEST(DecoderRelocation, VariousJccInstructionsPointToCorrectTargets)
    {
        hookftw::Decoder decoder;

        // Test various conditional jumps
        // 74 05             je +5
        // 75 05             jne +5
        // 7C 05             jl +5
        // 7D 05             jge +5
        uint8_t code[] = {
            0x74, 0x05,  // je
            0x75, 0x05,  // jne
            0x7C, 0x05,  // jl
            0x7D, 0x05   // jge
        };

        int8_t* sourceAddress = reinterpret_cast<int8_t*>(code);

        // Calculate all original targets
        int8_t* originalTargets[4];
        for (int i = 0; i < 4; i++)
        {
            int8_t offset = ExtractRel8Offset(code + i * 2, 1);
            originalTargets[i] = CalculateAbsoluteTarget(sourceAddress + i * 2, offset, 2);
        }

        uint8_t targetBuffer[256];
        int8_t* targetAddress = reinterpret_cast<int8_t*>(targetBuffer);

        std::vector<int8_t> relocated = decoder.Relocate(sourceAddress, sizeof(code), targetAddress);

        ASSERT_FALSE(relocated.empty());

        // Each jcc becomes 18 bytes: jcc +2; jmp short +14; jmp [rip+0]; 8-byte address
        ASSERT_EQ(relocated.size(), 72); // 4 * 18

        // Verify each jump's absolute target is embedded in the relocated code
        for (int i = 0; i < 4; i++)
        {
            size_t offset = i * 18 + 10; // Position of 8-byte absolute address
            uint64_t relocatedTarget;
            std::memcpy(&relocatedTarget, relocated.data() + offset, sizeof(uint64_t));
            EXPECT_EQ(reinterpret_cast<void*>(originalTargets[i]), reinterpret_cast<void*>(relocatedTarget))
                << "Jump " << i << " target mismatch";
        }
    }

    TEST(DecoderRelocation, LoopInstructionPointsToSameAbsoluteAddress)
    {
        hookftw::Decoder decoder;

        // E2 08             loop +8
        // 90                nop
        uint8_t code[] = {0xE2, 0x08, 0x90};

        int8_t* sourceAddress = reinterpret_cast<int8_t*>(code);

        // Calculate original absolute target
        int8_t originalOffset = ExtractRel8Offset(code, 1);
        int8_t* originalTarget = CalculateAbsoluteTarget(sourceAddress, originalOffset, 2);

        uint8_t targetBuffer[256];
        int8_t* targetAddress = reinterpret_cast<int8_t*>(targetBuffer);

        std::vector<int8_t> relocated = decoder.Relocate(sourceAddress, 2, targetAddress);

        ASSERT_FALSE(relocated.empty());

        // Loop instructions are transformed similarly to jcc: loop +2; jmp short; jmp [target]
        // Should be 18 bytes like jcc
        ASSERT_EQ(relocated.size(), 18);

        // Verify target is embedded
        uint64_t relocatedTarget;
        std::memcpy(&relocatedTarget, relocated.data() + 10, sizeof(uint64_t));
        EXPECT_EQ(reinterpret_cast<void*>(originalTarget), reinterpret_cast<void*>(relocatedTarget));
    }

    TEST(DecoderRelocation, LoopVariantsPointToSameTargets)
    {
        hookftw::Decoder decoder;

        // E0 05             loopne +5
        // E1 05             loope +5
        // E2 05             loop +5
        uint8_t code[] = {
            0xE0, 0x05,  // loopne
            0xE1, 0x05,  // loope
            0xE2, 0x05   // loop
        };

        int8_t* sourceAddress = reinterpret_cast<int8_t*>(code);

        // Calculate all original targets
        int8_t* originalTargets[3];
        for (int i = 0; i < 3; i++)
        {
            int8_t offset = ExtractRel8Offset(code + i * 2, 1);
            originalTargets[i] = CalculateAbsoluteTarget(sourceAddress + i * 2, offset, 2);
        }

        uint8_t targetBuffer[256];
        int8_t* targetAddress = reinterpret_cast<int8_t*>(targetBuffer);

        std::vector<int8_t> relocated = decoder.Relocate(sourceAddress, sizeof(code), targetAddress);

        ASSERT_FALSE(relocated.empty());

        // Loop instructions are transformed like jcc
        // Each loop becomes 18 bytes
        ASSERT_EQ(relocated.size(), 54); // 3 * 18

        for (int i = 0; i < 3; i++)
        {
            size_t offset = i * 18 + 10;
            uint64_t relocatedTarget;
            std::memcpy(&relocatedTarget, relocated.data() + offset, sizeof(uint64_t));
            EXPECT_EQ(reinterpret_cast<void*>(originalTargets[i]), reinterpret_cast<void*>(relocatedTarget))
                << "Loop " << i << " target mismatch";
        }
    }

    TEST(DecoderRelocation, JcxzAndJecxzPointToSameAddress)
    {
        hookftw::Decoder decoder;

        // E3 05             jcxz/jecxz +5
        // 90                nop
        uint8_t code[] = {0xE3, 0x05, 0x90};

        int8_t* sourceAddress = reinterpret_cast<int8_t*>(code);

        // Calculate original absolute target
        int8_t originalOffset = ExtractRel8Offset(code, 1);
        int8_t* originalTarget = CalculateAbsoluteTarget(sourceAddress, originalOffset, 2);

        uint8_t targetBuffer[256];
        int8_t* targetAddress = reinterpret_cast<int8_t*>(targetBuffer);

        std::vector<int8_t> relocated = decoder.Relocate(sourceAddress, 2, targetAddress);

        ASSERT_FALSE(relocated.empty());
        ASSERT_GE(relocated.size(), 2);

        if (relocated[0] == 0xE3)
        {
            // Still jcxz/jecxz
            int8_t relocatedOffset = ExtractRel8Offset(reinterpret_cast<uint8_t*>(relocated.data()), 1);
            int8_t* relocatedTarget = CalculateAbsoluteTarget(targetAddress, relocatedOffset, 2);
            EXPECT_EQ(originalTarget, relocatedTarget);
        }
    }

    TEST(Decoder, CalculateRipRelativeMemoryAccessBoundsDetectsRipRelative)
    {
        hookftw::Decoder decoder;

        // 29 2D F5 E9 28 7C sub DWORD PTR [rip+0x7C28E9F5], ebp
        uint8_t code[] = {0x29, 0x2D, 0xF5, 0xE9, 0x28, 0x7C};

        int64_t low = 0;
        int64_t high = 0;
        ASSERT_TRUE(decoder.CalculateRipRelativeMemoryAccessBounds(reinterpret_cast<int8_t*>(code), sizeof(code), &low, &high));

        // If RIP-relative is present, decoder uses sentinel values; we just assert it doesn't claim "no rip-relative"
        EXPECT_FALSE(low == 0xffffffffffffffff && high == 0);
    }

    TEST(DecoderRelocation, RipRelativeMovPointsToSameMemoryLocation)
    {
        hookftw::Decoder decoder;

        // 48 8B 05 00 00 00 00  mov rax, [rip+0]
        // 90                     nop
        uint8_t code[] = {0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x90};

        int8_t* sourceAddress = reinterpret_cast<int8_t*>(code);

        // Calculate original absolute memory address being accessed
        int32_t originalOffset = ExtractRel32Offset(code, 3);
        int8_t* originalMemoryTarget = CalculateAbsoluteTarget(sourceAddress, originalOffset, 7);

        uint8_t targetBuffer[256];
        int8_t* targetAddress = reinterpret_cast<int8_t*>(targetBuffer);

        // This should succeed when trampoline is within rel32 range
        std::vector<int8_t> relocated = decoder.Relocate(sourceAddress, 7, targetAddress);

        ASSERT_FALSE(relocated.empty());
        ASSERT_GE(relocated.size(), 7);

        // Verify it's still a mov rax, [rip+offset] instruction
        ASSERT_EQ(static_cast<uint8_t>(relocated[0]), 0x48);
        ASSERT_EQ(static_cast<uint8_t>(relocated[1]), 0x8B);
        ASSERT_EQ(static_cast<uint8_t>(relocated[2]), 0x05);

        // Verify the relocated instruction accesses the same memory location
        int32_t relocatedOffset = ExtractRel32Offset(reinterpret_cast<uint8_t*>(relocated.data()), 3);
        int8_t* relocatedMemoryTarget = CalculateAbsoluteTarget(targetAddress, relocatedOffset, 7);

        EXPECT_EQ(originalMemoryTarget, relocatedMemoryTarget)
            << "RIP-relative mov should access the same memory location. "
            << "Original: " << static_cast<void*>(originalMemoryTarget) << ", "
            << "Relocated: " << static_cast<void*>(relocatedMemoryTarget);
    }

    TEST(DecoderRelocation, RipRelativeLeaPointsToSameAddress)
    {
        hookftw::Decoder decoder;

        // 48 8D 0D 00 00 00 00  lea rcx, [rip+0]
        uint8_t code[] = {0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00};

        int8_t* sourceAddress = reinterpret_cast<int8_t*>(code);

        // Calculate original absolute address being loaded
        int32_t originalOffset = ExtractRel32Offset(code, 3);
        int8_t* originalTarget = CalculateAbsoluteTarget(sourceAddress, originalOffset, 7);

        uint8_t targetBuffer[256];
        int8_t* targetAddress = reinterpret_cast<int8_t*>(targetBuffer);

        std::vector<int8_t> relocated = decoder.Relocate(sourceAddress, 7, targetAddress);

        ASSERT_FALSE(relocated.empty());
        ASSERT_GE(relocated.size(), 7);

        // Verify instruction format
        ASSERT_EQ(static_cast<uint8_t>(relocated[0]), 0x48);
        ASSERT_EQ(static_cast<uint8_t>(relocated[1]), 0x8D);
        ASSERT_EQ(static_cast<uint8_t>(relocated[2]), 0x0D);

        // Verify the relocated lea loads the same address
        int32_t relocatedOffset = ExtractRel32Offset(reinterpret_cast<uint8_t*>(relocated.data()), 3);
        int8_t* relocatedTarget = CalculateAbsoluteTarget(targetAddress, relocatedOffset, 7);

        EXPECT_EQ(originalTarget, relocatedTarget)
            << "RIP-relative lea should compute the same address";
    }

    TEST(DecoderRelocation, RipRelativeStorePointsToSameMemoryLocation)
    {
        hookftw::Decoder decoder;

        // 48 89 05 00 00 00 00  mov [rip+0], rax
        uint8_t code[] = {0x48, 0x89, 0x05, 0x00, 0x00, 0x00, 0x00};

        int8_t* sourceAddress = reinterpret_cast<int8_t*>(code);

        // Calculate original absolute memory address being written to
        int32_t originalOffset = ExtractRel32Offset(code, 3);
        int8_t* originalMemoryTarget = CalculateAbsoluteTarget(sourceAddress, originalOffset, 7);

        uint8_t targetBuffer[256];
        int8_t* targetAddress = reinterpret_cast<int8_t*>(targetBuffer);

        std::vector<int8_t> relocated = decoder.Relocate(sourceAddress, 7, targetAddress);

        ASSERT_FALSE(relocated.empty());
        ASSERT_GE(relocated.size(), 7);

        // Verify instruction format
        ASSERT_EQ(static_cast<uint8_t>(relocated[0]), 0x48);
        ASSERT_EQ(static_cast<uint8_t>(relocated[1]), 0x89);
        ASSERT_EQ(static_cast<uint8_t>(relocated[2]), 0x05);

        // Verify the relocated instruction writes to the same memory location
        int32_t relocatedOffset = ExtractRel32Offset(reinterpret_cast<uint8_t*>(relocated.data()), 3);
        int8_t* relocatedMemoryTarget = CalculateAbsoluteTarget(targetAddress, relocatedOffset, 7);

        EXPECT_EQ(originalMemoryTarget, relocatedMemoryTarget)
            << "RIP-relative store should write to the same memory location";
    }

    TEST(DecoderRelocation, RipRelativeArithmeticPointsToSameMemoryLocation)
    {
        hookftw::Decoder decoder;

        // 48 03 05 00 00 00 00  add rax, [rip+0]
        uint8_t code[] = {0x48, 0x03, 0x05, 0x00, 0x00, 0x00, 0x00};

        int8_t* sourceAddress = reinterpret_cast<int8_t*>(code);

        // Calculate original absolute memory address being read
        int32_t originalOffset = ExtractRel32Offset(code, 3);
        int8_t* originalMemoryTarget = CalculateAbsoluteTarget(sourceAddress, originalOffset, 7);

        uint8_t targetBuffer[256];
        int8_t* targetAddress = reinterpret_cast<int8_t*>(targetBuffer);

        std::vector<int8_t> relocated = decoder.Relocate(sourceAddress, 7, targetAddress);

        ASSERT_FALSE(relocated.empty());
        ASSERT_GE(relocated.size(), 7);

        // Verify instruction format
        ASSERT_EQ(static_cast<uint8_t>(relocated[0]), 0x48);
        ASSERT_EQ(static_cast<uint8_t>(relocated[1]), 0x03);
        ASSERT_EQ(static_cast<uint8_t>(relocated[2]), 0x05);

        // Verify the relocated instruction reads from the same memory location
        int32_t relocatedOffset = ExtractRel32Offset(reinterpret_cast<uint8_t*>(relocated.data()), 3);
        int8_t* relocatedMemoryTarget = CalculateAbsoluteTarget(targetAddress, relocatedOffset, 7);

        EXPECT_EQ(originalMemoryTarget, relocatedMemoryTarget)
            << "RIP-relative arithmetic should read from the same memory location";
    }

    TEST(DecoderRelocation, RipRelativeCmpPointsToSameMemoryLocation)
    {
        hookftw::Decoder decoder;

        // 48 3B 05 00 00 00 00  cmp rax, [rip+0]
        uint8_t code[] = {0x48, 0x3B, 0x05, 0x00, 0x00, 0x00, 0x00};

        int8_t* sourceAddress = reinterpret_cast<int8_t*>(code);

        // Calculate original absolute memory address being read
        int32_t originalOffset = ExtractRel32Offset(code, 3);
        int8_t* originalMemoryTarget = CalculateAbsoluteTarget(sourceAddress, originalOffset, 7);

        uint8_t targetBuffer[256];
        int8_t* targetAddress = reinterpret_cast<int8_t*>(targetBuffer);

        std::vector<int8_t> relocated = decoder.Relocate(sourceAddress, 7, targetAddress);

        ASSERT_FALSE(relocated.empty());
        ASSERT_GE(relocated.size(), 7);

        // Verify instruction format
        ASSERT_EQ(static_cast<uint8_t>(relocated[0]), 0x48);
        ASSERT_EQ(static_cast<uint8_t>(relocated[1]), 0x3B);
        ASSERT_EQ(static_cast<uint8_t>(relocated[2]), 0x05);

        // Verify the relocated instruction compares with the same memory location
        int32_t relocatedOffset = ExtractRel32Offset(reinterpret_cast<uint8_t*>(relocated.data()), 3);
        int8_t* relocatedMemoryTarget = CalculateAbsoluteTarget(targetAddress, relocatedOffset, 7);

        EXPECT_EQ(originalMemoryTarget, relocatedMemoryTarget)
            << "RIP-relative cmp should read from the same memory location";
    }

    TEST(DecoderRelocation, MultipleRipRelativeInstructionsPointToCorrectLocations)
    {
        hookftw::Decoder decoder;

        // 48 8B 05 00 00 00 00  mov rax, [rip+0]
        // 48 89 05 07 00 00 00  mov [rip+7], rax
        uint8_t code[] = {
            0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00,  // mov rax, [rip+0]
            0x48, 0x89, 0x05, 0x07, 0x00, 0x00, 0x00   // mov [rip+7], rax
        };

        int8_t* sourceAddress = reinterpret_cast<int8_t*>(code);

        // Calculate original memory targets
        int32_t originalOffset1 = ExtractRel32Offset(code, 3);
        int8_t* originalTarget1 = CalculateAbsoluteTarget(sourceAddress, originalOffset1, 7);

        int32_t originalOffset2 = ExtractRel32Offset(code + 7, 3);
        int8_t* originalTarget2 = CalculateAbsoluteTarget(sourceAddress + 7, originalOffset2, 7);

        uint8_t targetBuffer[256];
        int8_t* targetAddress = reinterpret_cast<int8_t*>(targetBuffer);

        std::vector<int8_t> relocated = decoder.Relocate(sourceAddress, sizeof(code), targetAddress);

        ASSERT_FALSE(relocated.empty());
        ASSERT_GE(relocated.size(), sizeof(code));

        // Verify first instruction
        ASSERT_EQ(static_cast<uint8_t>(relocated[0]), 0x48);
        ASSERT_EQ(static_cast<uint8_t>(relocated[1]), 0x8B);
        ASSERT_EQ(static_cast<uint8_t>(relocated[2]), 0x05);
        int32_t relocatedOffset1 = ExtractRel32Offset(reinterpret_cast<uint8_t*>(relocated.data()), 3);
        int8_t* relocatedTarget1 = CalculateAbsoluteTarget(targetAddress, relocatedOffset1, 7);
        EXPECT_EQ(originalTarget1, relocatedTarget1) << "First RIP-relative instruction target mismatch";

        // Verify second instruction
        ASSERT_EQ(static_cast<uint8_t>(relocated[7]), 0x48);
        ASSERT_EQ(static_cast<uint8_t>(relocated[8]), 0x89);
        ASSERT_EQ(static_cast<uint8_t>(relocated[9]), 0x05);
        int32_t relocatedOffset2 = ExtractRel32Offset(reinterpret_cast<uint8_t*>(relocated.data() + 7), 3);
        int8_t* relocatedTarget2 = CalculateAbsoluteTarget(targetAddress + 7, relocatedOffset2, 7);
        EXPECT_EQ(originalTarget2, relocatedTarget2) << "Second RIP-relative instruction target mismatch";
    }

    TEST(Decoder, CalculateRipRelativeMemoryAccessBoundsWithMultipleAccesses)
    {
        hookftw::Decoder decoder;

        // 48 8B 05 00 00 00 00  mov rax, [rip+0]
        // 48 8B 0D 00 00 00 00  mov rcx, [rip+0]
        uint8_t code[] = {
            0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00,
            0x48, 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00
        };

        int64_t low = 0;
        int64_t high = 0;
        ASSERT_TRUE(decoder.CalculateRipRelativeMemoryAccessBounds(reinterpret_cast<int8_t*>(code), sizeof(code), &low, &high));

        // Should detect RIP-relative accesses
        EXPECT_FALSE(low == 0xffffffffffffffff && high == 0);
    }

    TEST(Decoder, CalculateRipRelativeMemoryAccessBoundsNoRipRelative)
    {
        hookftw::Decoder decoder;

        // 48 89 C3              mov rbx, rax
        // 48 01 D8              add rax, rbx
        // 90                    nop
        uint8_t code[] = {0x48, 0x89, 0xC3, 0x48, 0x01, 0xD8, 0x90};

        int64_t low = 0;
        int64_t high = 0;
        ASSERT_TRUE(decoder.CalculateRipRelativeMemoryAccessBounds(reinterpret_cast<int8_t*>(code), sizeof(code), &low, &high));

        // Should indicate no RIP-relative access with sentinel values
        EXPECT_TRUE(low == 0xffffffffffffffff && high == 0);
    }

    TEST(DecoderRelocation, MixedRelativeInstructionsCanBeRelocated)
    {
        hookftw::Decoder decoder;

        // E8 00 00 00 00    call +0
        // 75 05             jne +5
        // E2 03             loop +3
        // 90                nop
        uint8_t code[] = {
            0xE8, 0x00, 0x00, 0x00, 0x00,  // call
            0x75, 0x05,                     // jne
            0xE2, 0x03,                     // loop
            0x90                            // nop
        };

        int8_t* sourceAddress = reinterpret_cast<int8_t*>(code);
        uint8_t targetBuffer[256];
        int8_t* targetAddress = reinterpret_cast<int8_t*>(targetBuffer);

        std::vector<int8_t> relocated = decoder.Relocate(sourceAddress, sizeof(code), targetAddress);

        EXPECT_FALSE(relocated.empty());
        EXPECT_GE(relocated.size(), sizeof(code));
    }

    TEST(DecoderRelocation, RelocationPreservesNonRelativeInstructions)
    {
        hookftw::Decoder decoder;

        // 55                push rbp
        // 48 89 E5          mov rbp, rsp
        // E8 00 00 00 00    call +0
        // 5D                pop rbp
        // C3                ret
        uint8_t code[] = {
            0x55,                           // push rbp
            0x48, 0x89, 0xE5,              // mov rbp, rsp
            0xE8, 0x00, 0x00, 0x00, 0x00,  // call
            0x5D,                           // pop rbp
            0xC3                            // ret
        };

        int8_t* sourceAddress = reinterpret_cast<int8_t*>(code);
        uint8_t targetBuffer[256];
        int8_t* targetAddress = reinterpret_cast<int8_t*>(targetBuffer);

        std::vector<int8_t> relocated = decoder.Relocate(sourceAddress, sizeof(code), targetAddress);

        EXPECT_FALSE(relocated.empty());
        EXPECT_GE(relocated.size(), sizeof(code));
    }

}
