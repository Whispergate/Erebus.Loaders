#ifndef EREBUS_SHELLCODE_OPTIONAL_HPP
#define EREBUS_SHELLCODE_OPTIONAL_HPP
#pragma once

#if defined(__GNUC__)
extern unsigned char nonce[] __attribute__((weak));

static inline bool ShellcodeHasNonce()
{
    return reinterpret_cast<const void*>(nonce) != nullptr;
}
#else
// Fallback when weak symbols are unavailable.
extern unsigned char nonce[];

static inline bool ShellcodeHasNonce()
{
    return true;
}
#endif

#endif
