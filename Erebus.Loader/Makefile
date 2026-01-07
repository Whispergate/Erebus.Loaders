BUILD	?= release

ifeq ($(BUILD),debug)
	CFLAGS  := -g -O0 -DDEBUG -Wall -I$(PWD)/include -I/usr/x86_64-w64-mingw32/include
	LDFLAGS := -s -static -static-libgcc -static-libstdc++
else
	CFLAGS  := -DNDEBUG -O2 -Wall -I$(PWD)/include -I/usr/x86_64-w64-mingw32/include -masm=intel
	LDFLAGS := -s -static -static-libgcc -static-libstdc++
endif

CC      := x86_64-w64-mingw32-g++
SRCS := $(wildcard src/*.c src/*.cpp)
OBJS := $(patsubst %.cpp,%.o,$(patsubst %.c,%.o,$(SRCS)))
OUT  := $(PWD)erebus.exe

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT): $(OBJS)
	$(CC) $(LDFLAGS) $^ -o $@

all: $(OUT)
clean:
	rm -f src/*.o $(OUT)

.PHONY: all clean
