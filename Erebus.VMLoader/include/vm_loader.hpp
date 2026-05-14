/*
BSD 2-Clause License

Copyright (c) 2026, MochaByte

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#pragma once

/*
 vmkit: a header-only, freestanding VM template for IR-bytecode loaders.
 Source: https://github.com/mochabyte0x/vmkit
*/

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace vmkit {

template <typename Opcode, std::size_t U32Slots = 8, std::size_t U64Slots = 4>
struct alignas(8) Op {
    Opcode        opcode;
    std::uint32_t u32[U32Slots];
    std::uint64_t u64[U64Slots];
};

template <auto Opcode>
struct Handler;

template <auto... Ops>
struct OpcodeList {};

template <auto Op_, typename Ctx, typename OpT>
concept HasHandler = requires(Ctx& ctx, const OpT& op) {
    Handler<Op_>::execute(ctx, op);
};

namespace xor_codec {

constexpr void apply(std::span<std::uint8_t>       data,
                     std::span<const std::uint8_t> key) noexcept {
    for (std::size_t i = 0; i < data.size(); ++i)
        data[i] ^= key[i % key.size()];
}

} // namespace xor_codec

namespace api_hash {

constexpr std::uint32_t oaat(const char* s, std::uint32_t seed = 1) noexcept {
    std::uint32_t h = 0;
    for (std::size_t i = 0; s[i] != '\0'; ++i) {
        h += static_cast<std::uint8_t>(s[i]);
        h += h << seed;
        h ^= h >> 6;
    }
    h += h << 3;
    h ^= h >> 11;
    h += h << 15;
    return h;
}

} // namespace api_hash

using OpcodeReverseMap = std::array<std::uint8_t, 256>;

constexpr OpcodeReverseMap identity_reverse_map() noexcept {
    OpcodeReverseMap m{};
    for (std::size_t i = 0; i < 256; ++i)
        m[i] = static_cast<std::uint8_t>(i);
    return m;
}

struct DefaultConfig {
    static constexpr bool opcode_randomization      = false;
    static constexpr bool bytecode_xor_encrypted    = false;
    static constexpr bool per_op_context_encryption = false;

    static constexpr OpcodeReverseMap opcode_reverse_map = identity_reverse_map();

    static void decrypt_bytecode(std::span<std::uint8_t> /*blob*/,
                                 std::uint32_t /*seed*/) noexcept {}

    template <typename Ctx>
    static void encrypt_context(Ctx& /*ctx*/, std::uint32_t /*op_index*/) noexcept {}

    template <typename Ctx>
    static void decrypt_context(Ctx& /*ctx*/, std::uint32_t /*op_index*/) noexcept {}
};

template <typename Opcode,
          typename Ctx,
          typename Cfg = DefaultConfig,
          typename Ops = OpcodeList<>>
class Vm;

template <typename Opcode, typename Ctx, typename Cfg, auto... Ops>
class Vm<Opcode, Ctx, Cfg, OpcodeList<Ops...>> {
public:
    using OpType     = Op<Opcode>;
    using Dispatcher = void (*)(Ctx&, const OpType&) noexcept;

    void execute(std::span<std::uint8_t> blob,
                 Ctx&                    ctx,
                 std::uint32_t           seed = 0) const noexcept {
        if constexpr (Cfg::bytecode_xor_encrypted)
            Cfg::decrypt_bytecode(blob, seed);

        const std::size_t count = blob.size() / sizeof(OpType);
        const auto*       ops   = reinterpret_cast<const OpType*>(blob.data());

        for (std::size_t i = 0; i < count; ++i) {
            if constexpr (Cfg::per_op_context_encryption)
                if (i > 0) Cfg::decrypt_context(ctx, static_cast<std::uint32_t>(i));

            const OpType& op  = ops[i];
            std::uint8_t  raw = static_cast<std::uint8_t>(op.opcode);
            if constexpr (Cfg::opcode_randomization)
                raw = Cfg::opcode_reverse_map[raw];

            dispatch_table[raw](ctx, op);

            if constexpr (Cfg::per_op_context_encryption)
                Cfg::encrypt_context(ctx, static_cast<std::uint32_t>(i + 1));
        }

        if constexpr (Cfg::per_op_context_encryption)
            if (count > 0)
                Cfg::decrypt_context(ctx, static_cast<std::uint32_t>(count));
    }

private:
    template <auto Op_>
    static void dispatch_to(Ctx& ctx, const OpType& op) noexcept {
        static_assert(HasHandler<Op_, Ctx, OpType>,
                      "vmkit: missing Handler<Op> specialization for a listed opcode");
        Handler<Op_>::execute(ctx, op);
    }

    static void unknown_op(Ctx& /*ctx*/, const OpType& /*op*/) noexcept {}

    static constexpr std::array<Dispatcher, 256> build_table() noexcept {
        std::array<Dispatcher, 256> t{};
        for (auto& f : t) f = &unknown_op;
        ((t[static_cast<std::size_t>(Ops)] = &dispatch_to<Ops>), ...);
        return t;
    }

    static constexpr std::array<Dispatcher, 256> dispatch_table = build_table();
};

} // namespace vmkit
