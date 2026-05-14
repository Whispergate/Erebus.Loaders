/* Shadow header - suppresses MinGW's winternl.h in VMLoader builds.
 * loader.hpp already defines all NT types that winternl.h provides.
 * $(CURDIR)/include is first in the VMLoader Makefile include path,
 * so this file is found before /usr/share/mingw-w64/include/winternl.h.
 */
#pragma once
