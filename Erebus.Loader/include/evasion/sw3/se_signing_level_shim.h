#ifndef EREBUS_SW3_SE_SIGNING_LEVEL_SHIM_H
#define EREBUS_SW3_SE_SIGNING_LEVEL_SHIM_H

/*
 * SE_SIGNING_LEVEL is a Win10+ BYTE enum (winnt.h) used by
 * NtSetCachedSigningLevel / NtGetCachedSigningLevel. MinGW-w64 on Debian
 * bullseye (the wrapper Docker base) ships a winnt.h that omits it.
 * SysWhispers3-generated Syscalls.h / Syscalls.c reference the typedef
 * without providing one, so translation units that include those files
 * fail to parse. Force-include this shim via -include to satisfy the
 * references; the ABI matches the real typedef (BYTE).
 */
#include <windows.h>
#ifndef SE_SIGNING_LEVEL_DEFINED
#define SE_SIGNING_LEVEL_DEFINED 1
typedef BYTE SE_SIGNING_LEVEL, *PSE_SIGNING_LEVEL;
#endif

#endif
