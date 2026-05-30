# Detect operating system/environment
ifeq ($(OS),Windows_NT)
	# Running on Windows (native or MSYS2/MinGW)
	DETECTED_OS := Windows
	ifneq ($(MSYSTEM),)
		# Determine compiler based on architecture
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
	# Running on Linux (use cross-compiler)
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

BUILD	?= release
TARGET	?= exe
INJECTION_TYPE  ?= 3
ENCRYPTION_TYPE ?= 0
ARCH    ?= x64

# Common Flags for Loader/Shellcode stability
# -ffreestanding: No standard library startup
# -mno-red-zone: Essential for x64 interrupt safety (x86 doesn't need this)
# -fno-stack-protector: Prevent stack cookies requiring CRT
# -fno-exceptions -fno-rtti: Remove C++ runtime dependencies
COMMON_FLAGS := -Wall -I"$(CURDIR)/include" $(MINGW_INCLUDE) $(ARCH_FLAGS) \
                -masm=intel \
                -fno-stack-protector \
                -fno-exceptions \
                -fno-rtti \
                -Wno-unknown-pragmas \
                -Wno-unused-function \
                -Wno-narrowing \
                -DCONFIG_INJECTION_TYPE=$(INJECTION_TYPE) \
                $(if $(EREBUS_HASH_SEED),-DEREBUS_HASH_SEED=$(EREBUS_HASH_SEED),)

# Add architecture-specific flags
ifeq ($(ARCH),x64)
	COMMON_FLAGS += -mno-red-zone
endif

# Libraries needed for guardrails (iphlpapi for IP address check, ws2_32 for network functions)
LIBS := -liphlpapi -lws2_32 -lnetapi32

ifeq ($(BUILD),debug)
	# O0 is critical for debugging loaders to prevent optimization reordering
	CFLAGS  := -g -O0 -D_DEBUG $(COMMON_FLAGS)
	LDFLAGS := -static -static-libgcc -static-libstdc++ -Wl,--gc-sections
else
	# Aggressive size optimization for release builds
	CFLAGS  := -DNDEBUG -Os $(COMMON_FLAGS) \
	           -ffunction-sections -fdata-sections \
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

# Check if proxy.def exists in defs folder
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
	OUT  := erebus.dll
else ifeq ($(TARGET),xll)
	CFLAGS  += -DBUILD_XLL
	LDFLAGS += -shared -Wl,--subsystem,windows
	OUT  := erebus.xll
else
	ifeq ($(BUILD),release)
		LDFLAGS += -mwindows
	endif
	OUT  := erebus.exe
endif

SRCS := $(wildcard src/*.c src/*.cpp src/injection/*.cpp src/helpers/*.cpp src/guardrails/*.cpp src/evasion/*.cpp)
OBJS := $(patsubst %.cpp,%.o,$(patsubst %.c,%.o,$(SRCS)))

# ---------------------------------------------------------------------------
# SysWhispers3 / callstack spoof wiring
# ---------------------------------------------------------------------------
# Gated on the same CONFIG_* macros that gate the C++ call sites in
# config.hpp; builder.py passes both on the `make` command line so the
# Makefile + header agree without parsing config.hpp.
#
# The bundled Syscalls-asm.x{64,86}.asm + callstack_spoof.asm files are
# MASM-syntax, targetting MSVC's ml64. The MinGW toolchain used here has
# no MASM assembler, so:
#   - SysWhispers3: use Syscalls.c exclusively. It ships the same 482
#     Sw3Nt* stubs via __declspec(naked) + inline asm and also owns
#     SW3_PopulateSyscallList / SW3_GetSyscall{Number,Address}. Single
#     source of truth on MinGW builds.
#   - Callstack spoof: SpoofCall() lives only in callstack_spoof.asm and
#     has no MinGW-compatible counterpart. Toggling CONFIG_CALLSTACK_
#     SPOOF_ENABLED=1 on MinGW adds the -D flag so the .cpp call sites
#     try to link SpoofCall and fail. Effectively MSVC-only; kept here
#     as a no-op flag until a GAS translation lands.
CONFIG_SYSCALL_BACKEND        ?= 0
CONFIG_CALLSTACK_SPOOF_ENABLED ?= 0

ifeq ($(CONFIG_SYSCALL_BACKEND),0)
    CFLAGS   += -DCONFIG_SYSCALL_BACKEND=0
endif
ifeq ($(CONFIG_SYSCALL_BACKEND),1)
    CFLAGS   += -DCONFIG_SYSCALL_BACKEND=1
    SW3_C_SRC := src/evasion/Syscalls.c
    SW3_C_OBJ := $(SW3_C_SRC:.c=.o)
    OBJS      += $(SW3_C_OBJ)
    # Syscalls.c inline asm uses bare intel syntax (`mov [rsp+8], rcx`).
    # -masm=intel alone does not forward the matching flags to `as`, which
    # then errors with "operand size mismatch". Force intel syntax and
    # naked-reg through -Wa, add the Syscalls.h include path (file lives
    # under include/evasion/sw3/ but its #include uses no subdir), and
    # force-include the SE_SIGNING_LEVEL shim since MinGW's winnt.h omits
    # that typedef while SysWhispers3 references it.
    $(SW3_C_OBJ): CFLAGS += -Wa,-msyntax=intel,-mnaked-reg -Iinclude/evasion/sw3 -include include/evasion/sw3/se_signing_level_shim.h
endif
ifeq ($(CONFIG_SYSCALL_BACKEND),2)
    # Heaven's Gate - 32-bit WoW64 syscall via CS:0x33 far jump.
    # Requires ARCH=x86. heavens_gate.S is AT&T-syntax with .intel_syntax
    # preamble; assemble with plain $(CC) -m32.
    ifneq ($(ARCH),x86)
        $(error Heaven's Gate (CONFIG_SYSCALL_BACKEND=2) requires ARCH=x86)
    endif
    CFLAGS       += -DCONFIG_SYSCALL_BACKEND=2
    HG_CPP_SRC   := src/evasion/heavens_gate.cpp
    HG_S_SRC     := src/evasion/heavens_gate.S
    HG_CPP_OBJ   := $(HG_CPP_SRC:.cpp=.o)
    HG_S_OBJ     := $(HG_S_SRC:.S=.o)
    OBJS         += $(HG_CPP_OBJ) $(HG_S_OBJ)
    # heavens_gate.S contains both .code32 and .code64 directives and
    # must be assembled as a 32-bit object that happens to contain 64-bit
    # code islands. -m32 keeps the object ABI correct; the .code64 section
    # is inert to the linker - it is jumped to at runtime via far ret.
    $(HG_S_OBJ): CFLAGS += -Wa,-msyntax=intel,-mnaked-reg
endif
ifeq ($(CONFIG_CALLSTACK_SPOOF_ENABLED),1)
    CFLAGS   += -DCONFIG_CALLSTACK_SPOOF_ENABLED=1
    # SpoofCall() lives in callstack_spoof_gas.S - a GAS port of the
    # MASM-only callstack_spoof.asm so MinGW's as can consume it. x64
    # only; the trampoline uses the Win64 ABI (shadow space + r10/r11
    # scratch) and has no x86 counterpart, so silently drop it there.
    ifeq ($(ARCH),x64)
        CS_S_SRC  := src/evasion/callstack_spoof_gas.S
        CS_S_OBJ  := $(CS_S_SRC:.S=.o)
        OBJS      += $(CS_S_OBJ)
    endif
endif

# Test sources (exclude main.cpp, use test_erebus.cpp instead)
TEST_SRCS := $(wildcard tests/*.cpp src/helpers/*.cpp)
TEST_OBJS := $(patsubst %.cpp,%.o,$(TEST_SRCS))
TEST_OUT := erebus_test.exe
TEST_DLL_OUT := erebus_test.dll
GUARDRAILS_TEST_OUT := erebus_guardrails_test.exe

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.S
	$(CC) $(ARCH_FLAGS) -c $< -o $@

STRIP_SCRIPT := $(CURDIR)/scripts/strip_metadata.py

$(OUT): $(OBJS)
	$(CC) $(LDFLAGS) $^ -o $@ $(LIBS)
ifeq ($(BUILD),release)
	@python3 $(STRIP_SCRIPT) $@ 2>/dev/null || true
endif

all: $(OUT)

dll:
	$(MAKE) TARGET=dll

exe:
	$(MAKE) TARGET=exe

# Architecture targets
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

xll:
	$(MAKE) TARGET=xll

x64-xll:
	$(MAKE) ARCH=x64 TARGET=xll

x86-xll:
	$(MAKE) ARCH=x86 TARGET=xll

# Debug LDFLAGS for test targets - console subsystem, no stripping, debug symbols
TEST_LDFLAGS := -g -static -static-libgcc -static-libstdc++ -Wl,--gc-sections -mconsole

# Test target - builds and optionally runs the test suite
TEST_CFLAGS := -g -O0 -D_DEBUG -Wall -I"$(CURDIR)/include" $(MINGW_INCLUDE) $(ARCH_FLAGS) -masm=intel -ffunction-sections -fdata-sections -DCONFIG_INJECTION_TYPE=0 -DCONFIG_SYSCALL_BACKEND=0 -DCONFIG_CALLSTACK_SPOOF_ENABLED=0
TEST_DLL_CFLAGS := $(TEST_CFLAGS) -DBUILD_DLL
TEST_DLL_LDFLAGS := $(TEST_LDFLAGS) -shared -Wl,--subsystem,windows
ifneq ($(DEF_LINK),)
	TEST_DLL_LDFLAGS += $(DEF_LINK)
endif
test:
	$(CC) $(TEST_CFLAGS) -c tests/test_erebus.cpp -o tests/test_erebus.o
	$(CC) $(TEST_CFLAGS) -c src/helpers/compression_helpers.cpp -o src/helpers/compression_helpers.o
	$(CC) $(TEST_CFLAGS) -c src/helpers/crypto_helpers.cpp -o src/helpers/crypto_helpers.o
	$(CC) $(TEST_CFLAGS) -c src/helpers/peb_helpers.cpp -o src/helpers/peb_helpers.o
	$(CC) $(TEST_CFLAGS) -c src/helpers/process_helpers.cpp -o src/helpers/process_helpers.o
	$(CC) $(TEST_CFLAGS) -c src/helpers/api_hashing.cpp -o src/helpers/api_hashing.o
	$(CC) $(TEST_CFLAGS) -c src/guardrails/guardrails.cpp -o src/guardrails/guardrails.o
	$(CC) $(TEST_CFLAGS) -c src/evasion/evasion.cpp -o src/evasion/evasion.o
	$(CC) $(TEST_CFLAGS) -c src/evasion/ntdll_unhook.cpp -o src/evasion/ntdll_unhook.o
	$(CC) $(TEST_CFLAGS) -c src/evasion/syscalls.cpp -o src/evasion/syscalls.o
	$(CC) $(TEST_LDFLAGS) tests/test_erebus.o src/helpers/*.o src/guardrails/*.o src/evasion/*.o -o $(TEST_OUT) $(LIBS)
	@echo "Test binary built: $(TEST_OUT)"

test-dll:
	$(CC) $(TEST_DLL_CFLAGS) -c tests/test_erebus.cpp -o tests/test_erebus.o
	$(CC) $(TEST_DLL_CFLAGS) -c src/helpers/compression_helpers.cpp -o src/helpers/compression_helpers.o
	$(CC) $(TEST_DLL_CFLAGS) -c src/helpers/crypto_helpers.cpp -o src/helpers/crypto_helpers.o
	$(CC) $(TEST_DLL_CFLAGS) -c src/helpers/peb_helpers.cpp -o src/helpers/peb_helpers.o
	$(CC) $(TEST_DLL_CFLAGS) -c src/helpers/process_helpers.cpp -o src/helpers/process_helpers.o
	$(CC) $(TEST_DLL_CFLAGS) -c src/helpers/api_hashing.cpp -o src/helpers/api_hashing.o
	$(CC) $(TEST_DLL_CFLAGS) -c src/guardrails/guardrails.cpp -o src/guardrails/guardrails.o
	$(CC) $(TEST_DLL_CFLAGS) -c src/evasion/evasion.cpp -o src/evasion/evasion.o
	$(CC) $(TEST_DLL_CFLAGS) -c src/evasion/ntdll_unhook.cpp -o src/evasion/ntdll_unhook.o
	$(CC) $(TEST_DLL_CFLAGS) -c src/evasion/syscalls.cpp -o src/evasion/syscalls.o
	$(CC) $(TEST_DLL_LDFLAGS) tests/test_erebus.o src/helpers/*.o src/guardrails/*.o src/evasion/*.o -o $(TEST_DLL_OUT) $(LIBS)
	@echo "Test DLL built: $(TEST_DLL_OUT)"

# Test guardrails - exercises every guardrail check individually
test-guardrails:
	$(CC) $(TEST_CFLAGS) -c tests/test_guardrails.cpp -o tests/test_guardrails.o
	$(CC) $(TEST_CFLAGS) -c src/helpers/compression_helpers.cpp -o src/helpers/compression_helpers.o
	$(CC) $(TEST_CFLAGS) -c src/helpers/crypto_helpers.cpp -o src/helpers/crypto_helpers.o
	$(CC) $(TEST_CFLAGS) -c src/helpers/peb_helpers.cpp -o src/helpers/peb_helpers.o
	$(CC) $(TEST_CFLAGS) -c src/helpers/process_helpers.cpp -o src/helpers/process_helpers.o
	$(CC) $(TEST_CFLAGS) -c src/helpers/api_hashing.cpp -o src/helpers/api_hashing.o
	$(CC) $(TEST_CFLAGS) -c src/guardrails/guardrails.cpp -o src/guardrails/guardrails.o
	$(CC) $(TEST_CFLAGS) -c src/evasion/evasion.cpp -o src/evasion/evasion.o
	$(CC) $(TEST_CFLAGS) -c src/evasion/ntdll_unhook.cpp -o src/evasion/ntdll_unhook.o
	$(CC) $(TEST_CFLAGS) -c src/evasion/syscalls.cpp -o src/evasion/syscalls.o
	$(CC) $(TEST_LDFLAGS) tests/test_guardrails.o src/helpers/*.o src/guardrails/*.o src/evasion/*.o -o $(GUARDRAILS_TEST_OUT) $(LIBS)
	@echo "Guardrails test binary built: $(GUARDRAILS_TEST_OUT)"

# Test specific injection method
# Usage: make test-injection INJECTION_TYPE=2
INJECTION_TEST_CFLAGS := -g -O0 -D_DEBUG -Wall -I"$(CURDIR)/include" $(MINGW_INCLUDE) $(ARCH_FLAGS) -masm=intel -ffunction-sections -fdata-sections -DCONFIG_INJECTION_TYPE=$(INJECTION_TYPE) -DCONFIG_ENCRYPTION_TYPE=$(ENCRYPTION_TYPE) -DCONFIG_SYSCALL_BACKEND=0 -DCONFIG_CALLSTACK_SPOOF_ENABLED=0
INJECTION_TEST_OUT := erebus_injection_test.exe
INJECTION_TEST_DLL_OUT := erebus_injection_test.dll
INJECTION_TEST_DLL_CFLAGS := $(INJECTION_TEST_CFLAGS) -DBUILD_DLL
INJECTION_TEST_XLL_CFLAGS := $(INJECTION_TEST_CFLAGS) -DBUILD_XLL
INJECTION_TEST_XLL_OUT := erebus_injection_test.xll
INJECTION_TEST_DLL_LDFLAGS := $(TEST_LDFLAGS) -shared -Wl,--subsystem,windows
ifneq ($(DEF_LINK),)
	INJECTION_TEST_DLL_LDFLAGS += $(DEF_LINK)
endif
# Common compile recipe shared by all test-injection* flavours.
# $(1) = CFLAGS variable name, $(2) = LDFLAGS variable name, $(3) = output name
define INJECTION_TEST_COMPILE
	$(CC) $($(1)) -c tests/test_injection.cpp -o tests/test_injection.o
	$(CC) $($(1)) -c src/helpers/compression_helpers.cpp -o src/helpers/compression_helpers.o
	$(CC) $($(1)) -c src/helpers/crypto_helpers.cpp -o src/helpers/crypto_helpers.o
	$(CC) $($(1)) -c src/helpers/peb_helpers.cpp -o src/helpers/peb_helpers.o
	$(CC) $($(1)) -c src/helpers/process_helpers.cpp -o src/helpers/process_helpers.o
	$(CC) $($(1)) -c src/helpers/api_hashing.cpp -o src/helpers/api_hashing.o
	$(CC) $($(1)) -c src/guardrails/guardrails.cpp -o src/guardrails/guardrails.o
	$(CC) $($(1)) -c src/evasion/evasion.cpp -o src/evasion/evasion.o
	$(CC) $($(1)) -c src/evasion/ntdll_unhook.cpp -o src/evasion/ntdll_unhook.o
	$(CC) $($(1)) -c src/evasion/syscalls.cpp -o src/evasion/syscalls.o
	$(CC) $($(1)) -c src/injection/injection_ntmapviewofsection.cpp -o src/injection/injection_ntmapviewofsection.o
	$(CC) $($(1)) -c src/injection/injection_createfiber.cpp -o src/injection/injection_createfiber.o
	$(CC) $($(1)) -c src/injection/injection_earlycascade.cpp -o src/injection/injection_earlycascade.o
	$(CC) $($(1)) -c src/injection/injection_poolparty.cpp -o src/injection/injection_poolparty.o
	$(CC) $($(1)) -c src/injection/injection_ntqueueapcthread.cpp -o src/injection/injection_ntqueueapcthread.o
	$(CC) $($(1)) -c src/injection/injection_module_stomp.cpp -o src/injection/injection_module_stomp.o
	$(CC) $($(1)) -c src/injection/injection_kernelcallback.cpp -o src/injection/injection_kernelcallback.o
	$(CC) $($(1)) -c src/injection/injection_txf_hollow.cpp -o src/injection/injection_txf_hollow.o
	$(CC) $($(1)) -c src/loader.cpp -o src/loader.o
	$(CC) $($(2)) tests/test_injection.o src/helpers/*.o src/guardrails/*.o src/evasion/*.o src/injection/*.o src/loader.o -o $(3) $(LIBS)
endef

test-injection:
	$(call INJECTION_TEST_COMPILE,INJECTION_TEST_CFLAGS,TEST_LDFLAGS,$(INJECTION_TEST_OUT))
	@echo "Injection test binary built: $(INJECTION_TEST_OUT)"
	@echo "Injection type: $(INJECTION_TYPE)"

test-injection-dll:
	$(call INJECTION_TEST_COMPILE,INJECTION_TEST_DLL_CFLAGS,INJECTION_TEST_DLL_LDFLAGS,$(INJECTION_TEST_DLL_OUT))
	@echo "Injection test DLL built: $(INJECTION_TEST_DLL_OUT)"
	@echo "Injection type: $(INJECTION_TYPE)"

test-injection-xll:
	$(call INJECTION_TEST_COMPILE,INJECTION_TEST_XLL_CFLAGS,INJECTION_TEST_DLL_LDFLAGS,$(INJECTION_TEST_XLL_OUT))
	@echo "Injection test XLL built: $(INJECTION_TEST_XLL_OUT)"
	@echo "Injection type: $(INJECTION_TYPE)"

# Run tests after building
run-tests: test
	@echo "Running Erebus test suite..."
	$(TEST_OUT)

# Test all injection methods by building with different configurations
test-all-injections:
	@echo "Testing NtMapViewOfSection injection (type 1)..."
	$(MAKE) clean
	$(MAKE) BUILD=debug INJECTION_TYPE=1
	@echo "Testing CreateFiber injection (type 2)..."
	$(MAKE) clean
	$(MAKE) BUILD=debug INJECTION_TYPE=2
	@echo "Testing EarlyCascade injection (type 3)..."
	$(MAKE) clean
	$(MAKE) BUILD=debug INJECTION_TYPE=3
	@echo "Testing PoolParty injection (type 4)..."
	$(MAKE) clean
	$(MAKE) BUILD=debug INJECTION_TYPE=4
	@echo "Testing NtQueueApcThread injection (type 5)..."
	$(MAKE) clean
	$(MAKE) BUILD=debug INJECTION_TYPE=5
	@echo "Testing ModuleStomp injection (type 6)..."
	$(MAKE) clean
	$(MAKE) BUILD=debug INJECTION_TYPE=6
	@echo "Testing KernelCallbackTable injection (type 7)..."
	$(MAKE) clean
	$(MAKE) BUILD=debug INJECTION_TYPE=7
	@echo "Testing TxfHollow injection (type 8)..."
	$(MAKE) clean
	$(MAKE) BUILD=debug INJECTION_TYPE=8
	@echo "All injection types built successfully!"

# Build all test payloads (EXE and DLL for each test type) and copy to payloads directory
# XLL format is only meaningful for self-injection techniques (no suspended
# target process in those host contexts), so XLL coverage is limited to
# self-injection types: 2 (CreateFiber), 3 (EarlyCascade), 6 (ModuleStomp), 7 (KernelCallbackTable).
PAYLOADS_DIR := $(CURDIR)/payloads
test-all: test-all-payloads
test-all-payloads:
	@echo "=== Building all test payloads ==="
	@mkdir -p $(PAYLOADS_DIR)
	@echo ""
	@echo "[1/23] Building general test EXE..."
	$(MAKE) clean
	$(MAKE) test
	@mv $(TEST_OUT) $(PAYLOADS_DIR)/
	@echo "[2/23] Building general test DLL..."
	$(MAKE) clean
	$(MAKE) test-dll
	@mv $(TEST_DLL_OUT) $(PAYLOADS_DIR)/
	@echo "[3/23] Building guardrails test EXE..."
	$(MAKE) clean
	$(MAKE) test-guardrails
	@mv $(GUARDRAILS_TEST_OUT) $(PAYLOADS_DIR)/
	@echo "[4/23] Building injection test EXE (TYPE=1 - NtMapViewOfSection, remote)..."
	$(MAKE) clean
	$(MAKE) test-injection INJECTION_TYPE=1
	@mv $(INJECTION_TEST_OUT) $(PAYLOADS_DIR)/erebus_injection_test_type1.exe
	@echo "[5/23] Building injection test DLL (TYPE=1 - NtMapViewOfSection, remote)..."
	$(MAKE) clean
	$(MAKE) test-injection-dll INJECTION_TYPE=1
	@mv $(INJECTION_TEST_DLL_OUT) $(PAYLOADS_DIR)/erebus_injection_test_type1.dll
	@echo "[6/23] Building injection test EXE (TYPE=2 - CreateFiber, self)..."
	$(MAKE) clean
	$(MAKE) test-injection INJECTION_TYPE=2
	@mv $(INJECTION_TEST_OUT) $(PAYLOADS_DIR)/erebus_injection_test_type2.exe
	@echo "[7/23] Building injection test DLL (TYPE=2 - CreateFiber, self)..."
	$(MAKE) clean
	$(MAKE) test-injection-dll INJECTION_TYPE=2
	@mv $(INJECTION_TEST_DLL_OUT) $(PAYLOADS_DIR)/erebus_injection_test_type2.dll
	@echo "[8/23] Building injection test EXE (TYPE=3 - EarlyCascade, remote)..."
	$(MAKE) clean
	$(MAKE) test-injection INJECTION_TYPE=3
	@mv $(INJECTION_TEST_OUT) $(PAYLOADS_DIR)/erebus_injection_test_type3.exe
	@echo "[9/23] Building injection test DLL (TYPE=3 - EarlyCascade, remote)..."
	$(MAKE) clean
	$(MAKE) test-injection-dll INJECTION_TYPE=3
	@mv $(INJECTION_TEST_DLL_OUT) $(PAYLOADS_DIR)/erebus_injection_test_type3.dll
	@echo "[10/23] Building injection test EXE (TYPE=4 - PoolParty, remote)..."
	$(MAKE) clean
	$(MAKE) test-injection INJECTION_TYPE=4
	@mv $(INJECTION_TEST_OUT) $(PAYLOADS_DIR)/erebus_injection_test_type4.exe
	@echo "[11/23] Building injection test DLL (TYPE=4 - PoolParty, remote)..."
	$(MAKE) clean
	$(MAKE) test-injection-dll INJECTION_TYPE=4
	@mv $(INJECTION_TEST_DLL_OUT) $(PAYLOADS_DIR)/erebus_injection_test_type4.dll
	@echo "[12/23] Building injection test EXE (TYPE=5 - NtQueueApcThread, remote)..."
	$(MAKE) clean
	$(MAKE) test-injection INJECTION_TYPE=5
	@mv $(INJECTION_TEST_OUT) $(PAYLOADS_DIR)/erebus_injection_test_type5.exe
	@echo "[13/23] Building injection test DLL (TYPE=5 - NtQueueApcThread, remote)..."
	$(MAKE) clean
	$(MAKE) test-injection-dll INJECTION_TYPE=5
	@mv $(INJECTION_TEST_DLL_OUT) $(PAYLOADS_DIR)/erebus_injection_test_type5.dll
	@echo "[14/23] Building injection test EXE (TYPE=6 - ModuleStomp, self)..."
	$(MAKE) clean
	$(MAKE) test-injection INJECTION_TYPE=6
	@mv $(INJECTION_TEST_OUT) $(PAYLOADS_DIR)/erebus_injection_test_type6.exe
	@echo "[15/23] Building injection test DLL (TYPE=6 - ModuleStomp, self)..."
	$(MAKE) clean
	$(MAKE) test-injection-dll INJECTION_TYPE=6
	@mv $(INJECTION_TEST_DLL_OUT) $(PAYLOADS_DIR)/erebus_injection_test_type6.dll
	@echo "[16/23] Building injection test EXE (TYPE=7 - KernelCallbackTable, self)..."
	$(MAKE) clean
	$(MAKE) test-injection INJECTION_TYPE=7
	@mv $(INJECTION_TEST_OUT) $(PAYLOADS_DIR)/erebus_injection_test_type7.exe
	@echo "[17/23] Building injection test DLL (TYPE=7 - KernelCallbackTable, self)..."
	$(MAKE) clean
	$(MAKE) test-injection-dll INJECTION_TYPE=7
	@mv $(INJECTION_TEST_DLL_OUT) $(PAYLOADS_DIR)/erebus_injection_test_type7.dll
	@echo "[18/23] Building injection test EXE (TYPE=8 - TxfHollow, remote)..."
	$(MAKE) clean
	$(MAKE) test-injection INJECTION_TYPE=8
	@mv $(INJECTION_TEST_OUT) $(PAYLOADS_DIR)/erebus_injection_test_type8.exe
	@echo "[19/23] Building injection test DLL (TYPE=8 - TxfHollow, remote)..."
	$(MAKE) clean
	$(MAKE) test-injection-dll INJECTION_TYPE=8
	@mv $(INJECTION_TEST_DLL_OUT) $(PAYLOADS_DIR)/erebus_injection_test_type8.dll
	@echo "[20/23] Building injection test XLL (TYPE=2 - CreateFiber, self)..."
	$(MAKE) clean
	$(MAKE) test-injection-xll INJECTION_TYPE=2
	@mv $(INJECTION_TEST_XLL_OUT) $(PAYLOADS_DIR)/erebus_injection_test_type2.xll
	@echo "[21/23] Building injection test XLL (TYPE=3 - EarlyCascade, remote)..."
	$(MAKE) clean
	$(MAKE) test-injection-xll INJECTION_TYPE=3
	@mv $(INJECTION_TEST_XLL_OUT) $(PAYLOADS_DIR)/erebus_injection_test_type3.xll
	@echo "[22/23] Building injection test XLL (TYPE=6 - ModuleStomp, self)..."
	$(MAKE) clean
	$(MAKE) test-injection-xll INJECTION_TYPE=6
	@mv $(INJECTION_TEST_XLL_OUT) $(PAYLOADS_DIR)/erebus_injection_test_type6.xll
	@echo "[23/23] Building injection test XLL (TYPE=7 - KernelCallbackTable, self)..."
	$(MAKE) clean
	$(MAKE) test-injection-xll INJECTION_TYPE=7
	@mv $(INJECTION_TEST_XLL_OUT) $(PAYLOADS_DIR)/erebus_injection_test_type7.xll
	@echo ""
	@echo "=== All test payloads built successfully! ==="
	@echo "Location: $(PAYLOADS_DIR)"
	@ls -lh $(PAYLOADS_DIR)/

clean:
	rm -f src/*.o src/helpers/*.o src/injection/*.o src/guardrails/*.o src/evasion/*.o src/evasion/*.obj tests/*.o $(RES) $(CURDIR)/erebus.exe $(CURDIR)/erebus.dll $(CURDIR)/erebus.xll $(TEST_OUT) $(TEST_DLL_OUT) $(GUARDRAILS_TEST_OUT) $(INJECTION_TEST_OUT) $(INJECTION_TEST_DLL_OUT) $(INJECTION_TEST_XLL_OUT)

clean-payloads:
	rm -rf $(PAYLOADS_DIR)

clean-all: clean clean-payloads

.PHONY: all dll exe xll x64 x86 x64-dll x86-dll x64-exe x86-exe x64-xll x86-xll test test-dll test-guardrails run-tests test-injection test-injection-dll test-injection-xll test-all-injections test-all test-all-payloads clean clean-payloads clean-all
