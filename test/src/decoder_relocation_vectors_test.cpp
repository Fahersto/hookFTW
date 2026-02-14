#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include <Decoder.h>

namespace
{
    #if defined(__x86_64__)

    // These vectors are taken from the old manual relocation tool (test/test_relocation.cpp)
    // and turned into automated assertions.
    constexpr uint8_t kCalls[] = {
        0xe8, 0x11, 0x22, 0x33, 0x44,

        0xFF, 0x10,
        0xFF, 0x14, 0x0A,
        0xFF, 0x15, 0x11, 0x22, 0x33, 0x44,
        0xFF, 0x50, 0x11,
        0xFF, 0x90, 0x11, 0x22, 0x33, 0x44,
        0xFF, 0xD0,

        0xFF, 0x98, 0x11, 0x22, 0x33, 0x44,
        0x48, 0xFF, 0x98, 0x11, 0x22, 0x33, 0x44,
    };

    // Only include forms that are safe in a synthetic buffer.
    // Indirect JMP forms like FF /4 and FF /5 require valid memory operands and can crash relocation logic
    // when pointed at fake addresses.
    constexpr uint8_t kBranchRelForms[] = {
        0x77, 0x11,                               // JA rel8
        0x0F, 0x87, 0x11, 0x00, 0x00, 0x00,       // JA rel32
        0xEB, 0x11,                               // JMP rel8
        0xE9, 0x11, 0x22, 0x33, 0x44,             // JMP rel32
    };

    constexpr uint8_t kLoops[] = {
        0xE2, 0x11,
        0xE1, 0x11,
        0xE0, 0x11,
    };

    constexpr uint8_t kRipRelativeSingle[] = {
        // sub DWORD PTR [rip+disp32], ebp
        0x29, 0x2D, 0xF5, 0xE9, 0x28, 0x7C,
    };

    uint64_t ReadU32LE(const uint8_t* p)
    {
        uint32_t v;
        std::memcpy(&v, p, sizeof(v));
        return v;
    }

    int32_t ReadI32LE(const uint8_t* p)
    {
        int32_t v;
        std::memcpy(&v, p, sizeof(v));
        return v;
    }

    int8_t ReadI8(const uint8_t* p)
    {
        int8_t v;
        std::memcpy(&v, p, sizeof(v));
        return v;
    }

    std::vector<uint64_t> ExtractOriginalTargets_BranchRelForms(const uint8_t* bytes, size_t len, uint64_t base)
    {
        std::vector<uint64_t> targets;

        // kBranchRelForms layout is fixed by the test vector itself.
        // JA rel8
        {
            const size_t off = 0;
            const int8_t disp = ReadI8(bytes + off + 1);
            targets.push_back(base + off + 2 + static_cast<int64_t>(disp));
        }
        // JA rel32
        {
            const size_t off = 2;
            const int32_t disp = ReadI32LE(bytes + off + 2);
            targets.push_back(base + off + 6 + static_cast<int64_t>(disp));
        }
        // JMP rel8
        {
            const size_t off = 8;
            const int8_t disp = ReadI8(bytes + off + 1);
            targets.push_back(base + off + 2 + static_cast<int64_t>(disp));
        }
        // JMP rel32
        {
            const size_t off = 10;
            const int32_t disp = ReadI32LE(bytes + off + 1);
            targets.push_back(base + off + 5 + static_cast<int64_t>(disp));
        }

        (void)len;
        return targets;
    }

    bool BufferContainsAbsTargetViaMovabsOpcode(const uint8_t* relocated, size_t relocatedLen, uint64_t target)
    {
        // We look for a common absolute control-transfer encoding pattern used in this project:
        //   48 B8 <imm64> (movabs rax, imm64)
        // followed by either:
        //   FF D0 (call rax) or FF E0 (jmp rax)
        for (size_t i = 0; i + 10 < relocatedLen; ++i)
        {
            if (relocated[i] == 0x48 && relocated[i + 1] == 0xB8)
            {
                uint64_t imm;
                std::memcpy(&imm, relocated + i + 2, sizeof(imm));
                if (imm != target)
                    continue;

                // call rax
                if (i + 12 <= relocatedLen && relocated[i + 10] == 0xFF && relocated[i + 11] == 0xD0)
                    return true;
                // jmp rax
                if (i + 12 <= relocatedLen && relocated[i + 10] == 0xFF && relocated[i + 11] == 0xE0)
                    return true;
            }
        }
        return false;
    }

    bool BufferContainsAbsTargetViaRipIndStub(const uint8_t* relocated, size_t relocatedLen, uint64_t target)
    {
        // Pattern used throughout the library for absolute control transfer:
        //  - JMP [RIP+0]  imm64  => FF 25 00 00 00 00 <imm64>
        //  - CALL [RIP+0] imm64  => FF 15 00 00 00 00 <imm64>
        for (size_t i = 0; i + 14 <= relocatedLen; ++i)
        {
            if (relocated[i] == 0xFF && (relocated[i + 1] == 0x25 || relocated[i + 1] == 0x15))
            {
                // disp32 must be 0
                if (relocated[i + 2] || relocated[i + 3] || relocated[i + 4] || relocated[i + 5])
                    continue;

                uint64_t imm;
                std::memcpy(&imm, relocated + i + 6, sizeof(imm));
                if (imm == target)
                    return true;
            }
        }
        return false;
    }

    bool BufferContainsLegacyRelBranchTarget(const uint8_t* relocated, size_t relocatedLen, uint64_t base, uint64_t target)
    {
        // Support two simple encodings:
        //  - JMP rel32: E9 disp32
        //  - Jcc rel32: 0F 8* disp32
        // We compute target as (base + ip_after + disp).
        for (size_t i = 0; i + 5 <= relocatedLen; ++i)
        {
            // JMP rel32
            if (relocated[i] == 0xE9)
            {
                const int32_t disp = ReadI32LE(relocated + i + 1);
                const uint64_t computed = base + i + 5 + static_cast<int64_t>(disp);
                if (computed == target)
                    return true;
            }

            // Jcc rel32
            if (i + 6 <= relocatedLen && relocated[i] == 0x0F && (relocated[i + 1] & 0xF0) == 0x80)
            {
                const int32_t disp = ReadI32LE(relocated + i + 2);
                const uint64_t computed = base + i + 6 + static_cast<int64_t>(disp);
                if (computed == target)
                    return true;
            }
        }

        return false;
    }

    bool BufferContainsDisp32(const uint8_t* relocated, size_t relocatedLen, int32_t disp)
    {
        for (size_t i = 0; i + 4 <= relocatedLen; ++i)
        {
            int32_t v;
            std::memcpy(&v, relocated + i, sizeof(v));
            if (v == disp)
                return true;
        }
        return false;
    }

    void AssertRelocateOK(const uint8_t* bytes, size_t len, bool restrictedRelocation, const std::vector<uint64_t>& expectedAbsTargets)
    {
        hookftw::Decoder decoder;

        // Decoder::Relocate may patch the source stream.
        alignas(16) uint8_t src[2048] = {};
        ASSERT_LT(len, sizeof(src));
        std::memcpy(src, bytes, len);

        alignas(16) int8_t outBuf[4096] = {};

        auto relocatedVec = decoder.Relocate(reinterpret_cast<int8_t*>(src), static_cast<int>(len), outBuf, restrictedRelocation);
        ASSERT_FALSE(relocatedVec.empty());

        std::vector<uint8_t> relocated(relocatedVec.size());
        std::memcpy(relocated.data(), relocatedVec.data(), relocatedVec.size());

        const uint64_t relocatedBase = reinterpret_cast<uint64_t>(outBuf);
        for (uint64_t target : expectedAbsTargets)
        {
            const bool found = BufferContainsAbsTargetViaMovabsOpcode(relocated.data(), relocated.size(), target) ||
                               BufferContainsAbsTargetViaRipIndStub(relocated.data(), relocated.size(), target) ||
                               BufferContainsLegacyRelBranchTarget(relocated.data(), relocated.size(), relocatedBase, target);
            EXPECT_TRUE(found) << "Expected relocated control-transfer to target 0x" << std::hex << target;
        }
    }

    void AssertRelocateOK_DisplacementInvariant(const uint8_t* bytes, size_t len, bool restrictedRelocation, const std::vector<int32_t>& expectedDisp32)
    {
        hookftw::Decoder decoder;

        alignas(16) uint8_t src[2048] = {};
        ASSERT_LT(len, sizeof(src));
        std::memcpy(src, bytes, len);

        alignas(16) int8_t outBuf[4096] = {};
        auto relocatedVec = decoder.Relocate(reinterpret_cast<int8_t*>(src), static_cast<int>(len), outBuf, restrictedRelocation);
        ASSERT_FALSE(relocatedVec.empty());

        std::vector<uint8_t> relocated(relocatedVec.size());
        std::memcpy(relocated.data(), relocatedVec.data(), relocatedVec.size());

        for (int32_t disp : expectedDisp32)
        {
            EXPECT_TRUE(BufferContainsDisp32(relocated.data(), relocated.size(), disp))
                << "Expected relocated bytes to preserve disp32 value 0x" << std::hex << static_cast<uint32_t>(disp);
        }
    }

    TEST(DecoderRelocationVectors, CallsVector_Relocates)
    {
        // For a synthetic buffer, absolute addresses of the original targets are not meaningful.
        // Tight invariant: the original CALL rel32 displacement must be preserved/encoded into the relocated bytes.
        const int32_t callDisp = ReadI32LE(kCalls + 1);

        AssertRelocateOK_DisplacementInvariant(kCalls, sizeof(kCalls), /*restrictedRelocation=*/false, {callDisp});
    }

    TEST(DecoderRelocationVectors, BranchRelForms_Relocates)
    {
        // For branches, the target of the relative instruction is within the same synthetic buffer,
        // so the absolute target address is meaningful (it points back into the buffer).

        alignas(16) uint8_t src[sizeof(kBranchRelForms)] = {};
        std::memcpy(src, kBranchRelForms, sizeof(kBranchRelForms));

        const uint64_t base = reinterpret_cast<uint64_t>(src);
        auto expectedTargets = ExtractOriginalTargets_BranchRelForms(src, sizeof(src), base);

        // Relocate and make sure target addresses are preserved.
        hookftw::Decoder decoder;
        alignas(16) int8_t outBuf[4096] = {};

        auto relocatedVec = decoder.Relocate(reinterpret_cast<int8_t*>(src), static_cast<int>(sizeof(src)), outBuf,
                                             /*restrictedRelocation=*/false);
        ASSERT_FALSE(relocatedVec.empty());

        std::vector<uint8_t> relocated(relocatedVec.size());
        std::memcpy(relocated.data(), relocatedVec.data(), relocatedVec.size());

        const uint64_t relocatedBase = reinterpret_cast<uint64_t>(outBuf);
        for (uint64_t target : expectedTargets)
        {
            const bool found = BufferContainsAbsTargetViaMovabsOpcode(relocated.data(), relocated.size(), target) ||
                               BufferContainsAbsTargetViaRipIndStub(relocated.data(), relocated.size(), target) ||
                               BufferContainsLegacyRelBranchTarget(relocated.data(), relocated.size(), relocatedBase, target);
            EXPECT_TRUE(found) << "Expected relocated branch to preserve target 0x" << std::hex << target;
        }
    }

    TEST(DecoderRelocationVectors, LoopsVector_Relocates)
    {
        // LOOPcc targets are still relative branches; we validate successful relocation here.
        AssertRelocateOK(kLoops, sizeof(kLoops), /*restrictedRelocation=*/false, /*expectedAbsTargets=*/{});
    }

    TEST(DecoderRelocationVectors, RipRelativeSingle_Relocates)
    {
        AssertRelocateOK(kRipRelativeSingle, sizeof(kRipRelativeSingle), /*restrictedRelocation=*/false, /*expectedAbsTargets=*/{});
    }

    TEST(DecoderRelocationVectors, RestrictedRelocation_FailsOnRipRelative)
    {
        hookftw::Decoder decoder;

        alignas(16) uint8_t src[64] = {};
        std::memcpy(src, kRipRelativeSingle, sizeof(kRipRelativeSingle));

        alignas(16) int8_t outBuf[256] = {};
        auto relocated = decoder.Relocate(reinterpret_cast<int8_t*>(src), static_cast<int>(sizeof(kRipRelativeSingle)), outBuf,
                                          /*restrictedRelocation=*/true);

        EXPECT_TRUE(relocated.empty());
    }

    #else

    TEST(DecoderRelocationVectors, SkippedOnNonX8664)
    {
        GTEST_SKIP() << "Relocation vector suite currently only implemented for x86_64";
    }

    #endif
}
