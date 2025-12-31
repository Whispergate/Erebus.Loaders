# ================================
# Makefile for C++ project
# Cross-platform compatibility
# ================================

# Executable name
TARGET := erebus

# Compiler
CXX := x86_64-w64-mingw32-gcc

# Directories
BIN := build
SRC := src
OBJ := obj
LIB := lib
INC := include
COMPILE_FLAG := $(BIN)/.compiled

# Detect OS
ifeq ($(OS),Windows_NT)
  TARGET := $(TARGET).exe
  DETECTED_OS := Windows
else
  DETECTED_OS := Unix
endif

# System commands depending on the environment
ifeq ($(DETECTED_OS),Windows)
  SHELL = cmd.exe
  MKDIR = if not exist "$(subst /,,$1)" mkdir "$(subst /,,$1)"
  RMDIR = if exist "$(subst /,,$1)" rmdir /s /q "$(subst /,,$1)"
  RM = if exist "$(subst /,,$1)" del /f /q
  NULL_DEVICE = NUL
	FILE_FLAG = type nul > $(COMPILE_FLAG)
	PS = powershell -Command "Write-Host -NoNewline '$(1)' -ForegroundColor $(2); Write-Host '$(3)' -ForegroundColor $(4)"
else
  SHELL = /bin/sh
  MKDIR = mkdir -p $1
  RMDIR = rm -rf $1
  RM = rm -f $1
  NULL_DEVICE = /dev/null
	FILE_FLAG = touch $(COMPILE_FLAG)
define ANSI_COLOR
$(if $(filter $(1),Red),\033[31m,$(if $(filter $(1),Green),\033[32m,$(if $(filter $(1),Cyan),\033[36m,$(if $(filter $(1),White),\033[37m,\033[0m))))
endef
  PS = printf "$(call ANSI_COLOR,$(2))$(1)$(call ANSI_COLOR,$(4))$(3)\033[0m\n"
endif

# Find source and header files (include both root and subdirectories)
SRCS := $(wildcard $(SRC)/*.cpp) $(wildcard $(SRC)/**/*.cpp)
HDRS := $(wildcard $(INC)/*.h) $(wildcard $(INC)/**/*.h)
HDRS2 := $(wildcard $(INC)/*.hpp) $(wildcard $(INC)/**/*.hpp)
OBJS := $(patsubst $(SRC)/%.cpp, $(OBJ)/%.o, $(SRCS))

# Configure PKG_CONFIG
PKG_CONFIG := $(shell command -v pkg-config 2>$(NULL_DEVICE))

ifneq ($(PKG_CONFIG),)
  PKG_FLAGS := $(shell pkg-config --cflags gtkmm-4.0 2>$(NULL_DEVICE))
  PKG_LIBS  := $(shell pkg-config --libs gtkmm-4.0 2>$(NULL_DEVICE))
else
  PKG_FLAGS :=
  PKG_LIBS :=
endif

# Find static libraries in lib/
LIBS_STATIC := $(wildcard $(LIB)/*.a)

# Additional libraries
LIBS_EXTRA ?=

# Compiler flags (includes headers and compiler flags)
CXXFLAGS := -Wall -std=c++17 -I$(INC) $(PKG_FLAGS) -I/usr/x86_64-w64-mingw32/include -L/usr/x86_64-w64-mingw32/lib

# Linker flags (libraries from lib/ and system libraries)
LFLAGS := $(PKG_LIBS) $(LIBS_STATIC) $(LIBS_EXTRA)

# Rule to compile the project (checks .compiled)
.PHONY: all
all: $(BIN)/$(TARGET)
$(BIN)/$(TARGET): $(OBJS)
	@$(call MKDIR,$(BIN))
	@$(CXX) $(OBJS) $(LFLAGS) -o $@
	@$(FILE_FLAG)
	
# Rule to create object files
$(OBJ)/%.o: $(SRC)/%.cpp $(HDRS) $(HDRS2)
	@$(call MKDIR,$(dir $@))
	@$(CXX) $(CXXFLAGS) -c $< -o $@

# Rule to run the program
.PHONY: run
run: all
	@$(call PS,Running:, Cyan, $(TARGET), Green)
	@$(BIN)/$(TARGET)

# Rule to clean compiled files
.PHONY: clean
clean:
	@$(call PS,Cleaning build files:, Red, $(BIN)/$(TARGET), Green)
	@$(call RMDIR,$(BIN))
	@$(call RMDIR,$(OBJ))
	@$(call PS,Clean completed!:, Red, $(BIN)/$(TARGET), Green)