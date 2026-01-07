CC      := x86_64-w64-mingw32-g++
CFLAGS  := -Wall -O2 -I$(PWD)/include -I/usr/x86_64-w64-mingw32/include -masm=intel -m64
LDFLAGS := -s -m64 -static -static-libgcc -static-libstdc++

SRCS := $(wildcard src/*.c src/*.cpp)
OBJS := $(patsubst %.cpp,%.o,$(patsubst %.c,%.o,$(SRCS)))
OUT  := $(PWD)erebus.exe

# compile C sources
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# compile C++ sources
%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

# link
$(OUT): $(OBJS)
	$(CC) $(LDFLAGS) $^ -o $@

all: $(OUT)
clean:
	rm -f src/*.o $(OUT)

.PHONY: all clean
