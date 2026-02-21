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
                -DCONFIG_INJECTION_TYPE=$(INJECTION_TYPE)

# Add architecture-specific flags
ifeq ($(ARCH),x64)
	COMMON_FLAGS += -mno-red-zone
endif

# Libraries needed for guardrails (iphlpapi for IP address check, ws2_32 for network functions)
LIBS := -liphlpapi -lws2_32

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
	DEF_LINK := $(DEF_FILE)
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
else
	OUT  := erebus.exe
endif

SRCS := $(wildcard src/*.c src/*.cpp src/injection/*.cpp src/helpers/*.cpp src/guardrails/*.cpp)
OBJS := $(patsubst %.cpp,%.o,$(patsubst %.c,%.o,$(SRCS)))

# Test sources (exclude main.cpp, use test_erebus.cpp instead)
TEST_SRCS := $(wildcard tests/*.cpp src/helpers/*.cpp)
TEST_OBJS := $(patsubst %.cpp,%.o,$(TEST_SRCS))
TEST_OUT := erebus_test.exe
TEST_DLL_OUT := erebus_test.dll

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT): $(OBJS)
	$(CC) $(LDFLAGS) $^ -o $@ $(LIBS)

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

# Test target - builds and optionally runs the test suite
TEST_CFLAGS := -g -O0 -D_DEBUG -Wall -I"$(CURDIR)/include" $(MINGW_INCLUDE) -masm=intel -ffunction-sections -fdata-sections -DCONFIG_INJECTION_TYPE=0
TEST_DLL_CFLAGS := $(TEST_CFLAGS) -DBUILD_DLL
TEST_DLL_LDFLAGS := $(LDFLAGS) -shared -Wl,--subsystem,windows
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
	$(CC) $(LDFLAGS) tests/test_erebus.o src/helpers/*.o src/guardrails/*.o -o $(TEST_OUT) $(LIBS)
	@echo "Test binary built: $(TEST_OUT)"

test-dll:
	$(CC) $(TEST_DLL_CFLAGS) -c tests/test_erebus.cpp -o tests/test_erebus.o
	$(CC) $(TEST_DLL_CFLAGS) -c src/helpers/compression_helpers.cpp -o src/helpers/compression_helpers.o
	$(CC) $(TEST_DLL_CFLAGS) -c src/helpers/crypto_helpers.cpp -o src/helpers/crypto_helpers.o
	$(CC) $(TEST_DLL_CFLAGS) -c src/helpers/peb_helpers.cpp -o src/helpers/peb_helpers.o
	$(CC) $(TEST_DLL_CFLAGS) -c src/helpers/process_helpers.cpp -o src/helpers/process_helpers.o
	$(CC) $(TEST_DLL_CFLAGS) -c src/helpers/api_hashing.cpp -o src/helpers/api_hashing.o
	$(CC) $(TEST_DLL_CFLAGS) -c src/guardrails/guardrails.cpp -o src/guardrails/guardrails.o
	$(CC) $(TEST_DLL_LDFLAGS) tests/test_erebus.o src/helpers/*.o src/guardrails/*.o -o $(TEST_DLL_OUT) $(LIBS)
	@echo "Test DLL built: $(TEST_DLL_OUT)"

# Test specific injection method
# Usage: make test-injection INJECTION_TYPE=1
INJECTION_TEST_CFLAGS := -g -O0 -D_DEBUG -Wall -I"$(CURDIR)/include" $(MINGW_INCLUDE) -masm=intel -ffunction-sections -fdata-sections -DCONFIG_INJECTION_TYPE=$(INJECTION_TYPE)
INJECTION_TEST_OUT := erebus_injection_test.exe
INJECTION_TEST_DLL_OUT := erebus_injection_test.dll
INJECTION_TEST_DLL_CFLAGS := $(INJECTION_TEST_CFLAGS) -DBUILD_DLL
INJECTION_TEST_DLL_LDFLAGS := $(LDFLAGS) -shared -Wl,--subsystem,windows
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
	$(CC) $(INJECTION_TEST_CFLAGS) -c src/injection/injection_ntqueueapcthread.cpp -o src/injection/injection_ntqueueapcthread.o
	$(CC) $(INJECTION_TEST_CFLAGS) -c src/injection/injection_ntmapviewofsection.cpp -o src/injection/injection_ntmapviewofsection.o
	$(CC) $(INJECTION_TEST_CFLAGS) -c src/injection/injection_createfiber.cpp -o src/injection/injection_createfiber.o
	$(CC) $(INJECTION_TEST_CFLAGS) -c src/injection/injection_earlycascade.cpp -o src/injection/injection_earlycascade.o
	$(CC) $(INJECTION_TEST_CFLAGS) -c src/injection/injection_poolparty.cpp -o src/injection/injection_poolparty.o
	$(CC) $(INJECTION_TEST_CFLAGS) -c src/loader.cpp -o src/loader.o
	$(CC) $(LDFLAGS) tests/test_injection.o src/helpers/*.o src/guardrails/*.o src/injection/*.o src/loader.o -o $(INJECTION_TEST_OUT) $(LIBS)
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
	$(CC) $(INJECTION_TEST_DLL_CFLAGS) -c src/injection/injection_ntqueueapcthread.cpp -o src/injection/injection_ntqueueapcthread.o
	$(CC) $(INJECTION_TEST_DLL_CFLAGS) -c src/injection/injection_ntmapviewofsection.cpp -o src/injection/injection_ntmapviewofsection.o
	$(CC) $(INJECTION_TEST_DLL_CFLAGS) -c src/injection/injection_createfiber.cpp -o src/injection/injection_createfiber.o
	$(CC) $(INJECTION_TEST_DLL_CFLAGS) -c src/injection/injection_earlycascade.cpp -o src/injection/injection_earlycascade.o
	$(CC) $(INJECTION_TEST_DLL_CFLAGS) -c src/injection/injection_poolparty.cpp -o src/injection/injection_poolparty.o
	$(CC) $(INJECTION_TEST_DLL_CFLAGS) -c src/loader.cpp -o src/loader.o
	$(CC) $(INJECTION_TEST_DLL_LDFLAGS) tests/test_injection.o src/helpers/*.o src/guardrails/*.o src/injection/*.o src/loader.o -o $(INJECTION_TEST_DLL_OUT) $(LIBS)
	@echo "Injection test DLL built: $(INJECTION_TEST_DLL_OUT)"
	@echo "Injection type: $(INJECTION_TYPE)"

# Run tests after building
run-tests: test
	@echo "Running Erebus test suite..."
	$(TEST_OUT)

# Test all injection methods by building with different configurations
test-all-injections:
	@echo "Testing NtQueueApcThread injection..."
	$(MAKE) clean
	$(MAKE) BUILD=debug INJECTION_TYPE=1
	@echo "Testing NtMapViewOfSection injection..."
	$(MAKE) clean
	$(MAKE) BUILD=debug INJECTION_TYPE=2
	@echo "Testing CreateFiber injection..."
	$(MAKE) clean
	$(MAKE) BUILD=debug INJECTION_TYPE=3
	@echo "Testing EarlyCascade injection..."
	$(MAKE) clean
	$(MAKE) BUILD=debug INJECTION_TYPE=4
	@echo "Testing PoolParty injection..."
	$(MAKE) clean
	$(MAKE) BUILD=debug INJECTION_TYPE=5
	@echo "All injection types built successfully!"

# Build all test payloads (EXE and DLL for each test type) and copy to payloads directory
PAYLOADS_DIR := $(CURDIR)/payloads
test-all: test-all-payloads
test-all-payloads:
	@echo "=== Building all test payloads ==="
	@mkdir -p $(PAYLOADS_DIR)
	@echo ""
	@echo "[1/12] Building general test EXE..."
	$(MAKE) clean
	$(MAKE) test
	@mv $(TEST_OUT) $(PAYLOADS_DIR)/
	@echo "[2/12] Building general test DLL..."
	$(MAKE) clean
	$(MAKE) test-dll
	@mv $(TEST_DLL_OUT) $(PAYLOADS_DIR)/
	@echo "[3/12] Building injection test EXE (INJECTION_TYPE=1)..."
	$(MAKE) clean
	$(MAKE) test-injection INJECTION_TYPE=1
	@mv $(INJECTION_TEST_OUT) $(PAYLOADS_DIR)/erebus_injection_test_type1.exe
	@echo "[4/12] Building injection test DLL (INJECTION_TYPE=1)..."
	$(MAKE) clean
	$(MAKE) test-injection-dll INJECTION_TYPE=1
	@mv $(INJECTION_TEST_DLL_OUT) $(PAYLOADS_DIR)/erebus_injection_test_type1.dll
	@echo "[5/12] Building injection test EXE (INJECTION_TYPE=2)..."
	$(MAKE) clean
	$(MAKE) test-injection INJECTION_TYPE=2
	@mv $(INJECTION_TEST_OUT) $(PAYLOADS_DIR)/erebus_injection_test_type2.exe
	@echo "[6/12] Building injection test DLL (INJECTION_TYPE=2)..."
	$(MAKE) clean
	$(MAKE) test-injection-dll INJECTION_TYPE=2
	@mv $(INJECTION_TEST_DLL_OUT) $(PAYLOADS_DIR)/erebus_injection_test_type2.dll
	@echo "[7/12] Building injection test EXE (INJECTION_TYPE=3)..."
	$(MAKE) clean
	$(MAKE) test-injection INJECTION_TYPE=3
	@mv $(INJECTION_TEST_OUT) $(PAYLOADS_DIR)/erebus_injection_test_type3.exe
	@echo "[8/12] Building injection test DLL (INJECTION_TYPE=3)..."
	$(MAKE) clean
	$(MAKE) test-injection-dll INJECTION_TYPE=3
	@mv $(INJECTION_TEST_DLL_OUT) $(PAYLOADS_DIR)/erebus_injection_test_type3.dll
	@echo "[9/12] Building injection test EXE (INJECTION_TYPE=4)..."
	$(MAKE) clean
	$(MAKE) test-injection INJECTION_TYPE=4
	@mv $(INJECTION_TEST_OUT) $(PAYLOADS_DIR)/erebus_injection_test_type4.exe
	@echo "[10/12] Building injection test DLL (INJECTION_TYPE=4)..."
	$(MAKE) clean
	$(MAKE) test-injection-dll INJECTION_TYPE=4
	@mv $(INJECTION_TEST_DLL_OUT) $(PAYLOADS_DIR)/erebus_injection_test_type4.dll
	@echo "[11/12] Building injection test EXE (INJECTION_TYPE=5)..."
	$(MAKE) clean
	$(MAKE) test-injection INJECTION_TYPE=5
	@mv $(INJECTION_TEST_OUT) $(PAYLOADS_DIR)/erebus_injection_test_type5.exe
	@echo "[12/12] Building injection test DLL (INJECTION_TYPE=5)..."
	$(MAKE) clean
	$(MAKE) test-injection-dll INJECTION_TYPE=5
	@mv $(INJECTION_TEST_DLL_OUT) $(PAYLOADS_DIR)/erebus_injection_test_type5.dll
	@echo ""
	@echo "=== All test payloads built successfully! ==="
	@echo "Location: $(PAYLOADS_DIR)"
	@ls -lh $(PAYLOADS_DIR)/

clean:
	rm -f src/*.o src/helpers/*.o src/injection/*.o src/guardrails/*.o tests/*.o $(RES) $(CURDIR)/erebus.exe $(CURDIR)/erebus.dll $(TEST_OUT) $(TEST_DLL_OUT) $(INJECTION_TEST_OUT) $(INJECTION_TEST_DLL_OUT)

clean-payloads:
	rm -rf $(PAYLOADS_DIR)

clean-all: clean clean-payloads

.PHONY: all dll exe x64 x86 x64-dll x86-dll x64-exe x86-exe test test-dll run-tests test-injection test-injection-dll test-all-injections test-all test-all-payloads clean clean-payloads clean-all
