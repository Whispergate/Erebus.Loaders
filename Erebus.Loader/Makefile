# Detect operating system/environment
ifeq ($(OS),Windows_NT)
	# Running on Windows (native or MSYS2/MinGW)
	DETECTED_OS := Windows
	ifneq ($(MSYSTEM),)
		CC      := g++
		WINDRES := windres
		MINGW_INCLUDE := -I/mingw64/include
	else
		CC      := g++
		WINDRES := windres
		MINGW_INCLUDE :=
	endif
else
	# Running on Linux (use cross-compiler)
	DETECTED_OS := Linux
	CC      := x86_64-w64-mingw32-g++
	WINDRES := x86_64-w64-mingw32-windres
	MINGW_INCLUDE := -I/usr/x86_64-w64-mingw32/include
endif

BUILD	?= release
TARGET	?= exe
INJECTION_TYPE ?= 5

# Common Flags for Loader/Shellcode stability
# -ffreestanding: No standard library startup
# -mno-red-zone: Essential for x64 interrupt safety
# -fno-stack-protector: Prevent stack cookies requiring CRT
# -fno-exceptions -fno-rtti: Remove C++ runtime dependencies
COMMON_FLAGS := -Wall -I$(PWD)/include $(MINGW_INCLUDE) \
                -masm=intel \
                -fno-stack-protector \
                -mno-red-zone \
                -fno-exceptions \
                -fno-rtti \
                -Wno-unknown-pragmas \
                -Wno-unused-function \
                -Wno-narrowing \
                -DCONFIG_INJECTION_TYPE=$(INJECTION_TYPE)

ifeq ($(BUILD),debug)
	# O0 is critical for debugging loaders to prevent optimization reordering
	CFLAGS  := -g -O0 -D_DEBUG $(COMMON_FLAGS)
	LDFLAGS := -static -static-libgcc -static-libstdc++ -Wl,--gc-sections
else
	# Os (size) is safer than O2/O3 for loaders
	CFLAGS  := -DNDEBUG -Os $(COMMON_FLAGS)
	LDFLAGS := -s -static -static-libgcc -static-libstdc++ -Wl,--gc-sections
endif

ifeq ($(TARGET),dll)
	CFLAGS  += -DBUILD_DLL
	LDFLAGS += -shared -Wl,--subsystem,windows
	OUT  := $(PWD)/erebus.dll
else
	OUT  := $(PWD)/erebus.exe
endif

SRCS := $(wildcard src/*.c src/*.cpp src/injection/*.cpp src/helpers/*.cpp)
OBJS := $(patsubst %.cpp,%.o,$(patsubst %.c,%.o,$(SRCS)))

# Test sources (exclude main.cpp, use test_erebus.cpp instead)
TEST_SRCS := $(wildcard tests/*.cpp src/helpers/*.cpp)
TEST_OBJS := $(patsubst %.cpp,%.o,$(TEST_SRCS))
TEST_OUT := $(PWD)/erebus_test.exe

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT): $(OBJS)
	$(CC) $(LDFLAGS) $^ -o $@

all: $(OUT)

dll:
	$(MAKE) TARGET=dll

exe:
	$(MAKE) TARGET=exe

# Test target - builds and optionally runs the test suite
TEST_CFLAGS := -g -O0 -D_DEBUG -Wall -I$(PWD)/include $(MINGW_INCLUDE) -masm=intel -ffunction-sections -fdata-sections -DCONFIG_INJECTION_TYPE=0
test:
	$(CC) $(TEST_CFLAGS) -c tests/test_erebus.cpp -o tests/test_erebus.o
	$(CC) $(TEST_CFLAGS) -c src/helpers/compression_helpers.cpp -o src/helpers/compression_helpers.o
	$(CC) $(TEST_CFLAGS) -c src/helpers/crypto_helpers.cpp -o src/helpers/crypto_helpers.o
	$(CC) $(TEST_CFLAGS) -c src/helpers/peb_helpers.cpp -o src/helpers/peb_helpers.o
	$(CC) $(TEST_CFLAGS) -c src/helpers/process_helpers.cpp -o src/helpers/process_helpers.o
	$(CC) $(TEST_CFLAGS) -c src/helpers/api_hashing.cpp -o src/helpers/api_hashing.o
	$(CC) $(LDFLAGS) tests/test_erebus.o src/helpers/*.o -o $(TEST_OUT)
	@echo "Test binary built: $(TEST_OUT)"

# Test specific injection method
# Usage: make test-injection INJECTION_TYPE=1
INJECTION_TEST_CFLAGS := -g -O0 -D_DEBUG -Wall -I$(PWD)/include $(MINGW_INCLUDE) -masm=intel -ffunction-sections -fdata-sections -DCONFIG_INJECTION_TYPE=$(INJECTION_TYPE)
INJECTION_TEST_OUT := $(PWD)/erebus_injection_test.exe
test-injection:
	$(CC) $(INJECTION_TEST_CFLAGS) -c tests/test_injection.cpp -o tests/test_injection.o
	$(CC) $(INJECTION_TEST_CFLAGS) -c src/helpers/compression_helpers.cpp -o src/helpers/compression_helpers.o
	$(CC) $(INJECTION_TEST_CFLAGS) -c src/helpers/crypto_helpers.cpp -o src/helpers/crypto_helpers.o
	$(CC) $(INJECTION_TEST_CFLAGS) -c src/helpers/peb_helpers.cpp -o src/helpers/peb_helpers.o
	$(CC) $(INJECTION_TEST_CFLAGS) -c src/helpers/process_helpers.cpp -o src/helpers/process_helpers.o
	$(CC) $(INJECTION_TEST_CFLAGS) -c src/helpers/api_hashing.cpp -o src/helpers/api_hashing.o
	$(CC) $(INJECTION_TEST_CFLAGS) -c src/injection/injection_ntqueueapcthread.cpp -o src/injection/injection_ntqueueapcthread.o
	$(CC) $(INJECTION_TEST_CFLAGS) -c src/injection/injection_ntmapviewofsection.cpp -o src/injection/injection_ntmapviewofsection.o
	$(CC) $(INJECTION_TEST_CFLAGS) -c src/injection/injection_createfiber.cpp -o src/injection/injection_createfiber.o
	$(CC) $(INJECTION_TEST_CFLAGS) -c src/injection/injection_earlycascade.cpp -o src/injection/injection_earlycascade.o
	$(CC) $(INJECTION_TEST_CFLAGS) -c src/injection/injection_poolparty.cpp -o src/injection/injection_poolparty.o
	$(CC) $(INJECTION_TEST_CFLAGS) -c src/loader.cpp -o src/loader.o
	$(CC) $(LDFLAGS) tests/test_injection.o src/helpers/*.o src/injection/*.o src/loader.o -o $(INJECTION_TEST_OUT)
	@echo "Injection test binary built: $(INJECTION_TEST_OUT)"
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

clean:
	rm -f src/*.o src/helpers/*.o src/injection/*.o tests/*.o $(RES) $(PWD)/erebus.exe $(PWD)/erebus.dll $(TEST_OUT) $(INJECTION_TEST_OUT)

.PHONY: all dll exe test run-tests test-injection test-all-injections clean
