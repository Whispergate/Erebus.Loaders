CC      := x86_64-w64-mingw32-gcc
CFLAGS  := -Wall -O2 -I$(PWD)/include
LDFLAGS := -s

SRCS   := $(wildcard src/*)
INCL   := $(wildcard include/*)
OBJS   := $(SRCS:.c=.o)
OUT    := $(PWD)/../../agent_code/payload/erebus.exe

$(OBJS): src/%.o: src/%.c : src/%.cpp
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT): $(OBJS)
	$(CC) $(LDFLAGS) $^ -o $@
	@echo "[+] PE written to $(OUT)"

all: $(OUT)
clean:
	rm -f src/*.o $(OUT)

.PHONY: all clean