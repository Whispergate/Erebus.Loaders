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

# Common Flags for Loader/Shellcode stability
# -ffreestanding: No standard library startup
# -mno-red-zone: Essential for x64 interrupt safety
# -fno-stack-protector: Prevent stack cookies requiring CRT
# -fno-exceptions -fno-rtti: Remove C++ runtime dependencies
COMMON_FLAGS := -Wall -I$(PWD)/include $(MINGW_INCLUDE) \
                -masm=intel \
                -ffreestanding \
                -fno-builtin \
                -fno-stack-protector \
                -mno-red-zone \
                -fno-exceptions \
                -fno-rtti \
                -Wno-unknown-pragmas \
                -Wno-unused-function \
                -Wno-narrowing

ifeq ($(BUILD),debug)
	# O0 is critical for debugging loaders to prevent optimization reordering
	CFLAGS  := -g -O0 -DDEBUG $(COMMON_FLAGS)
	LDFLAGS := -static -static-libgcc -static-libstdc++
else
	# Even in release, Os (size) or O1 is safer than O2 for loaders
	CFLAGS  := -DNDEBUG -Os $(COMMON_FLAGS)
	LDFLAGS := -s -static -static-libgcc -static-libstdc++
endif

ifeq ($(TARGET),dll)
	CFLAGS  += -DBUILD_DLL
	LDFLAGS += -shared -Wl,--subsystem,windows
	OUT  := $(PWD)erebus.dll
else
	OUT  := $(PWD)erebus.exe
endif

SRCS := $(wildcard src/*.c src/*.cpp)
OBJS := $(patsubst %.cpp,%.o,$(patsubst %.c,%.o,$(SRCS)))

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

clean:
	rm -f src/*.o $(PWD)erebus.exe $(PWD)erebus.dll

.PHONY: all dll exe clean
