LIB := tkh

TEST_CMD := test
CLI_CMD := totpcli

SRC_DIR := ./src
CLI_SRC_DIR := $(SRC_DIR)/cli
DEV_SRC_DIR := $(SRC_DIR)/dev
LIB_SRC_DIR := $(SRC_DIR)/lib
TEST_SRC_DIR := $(SRC_DIR)/tests

BUILD_DIR := ./build
TEST_DIR := $(BUILD_DIR)/test
BIN_DIR := $(BUILD_DIR)/bin
OBJ_DIR := $(BUILD_DIR)/obj

AR := ar

AS := nasm
AS_FLAGS := -felf64
AS_EXT := nasm

CC := gcc
CC_FLAGS := -Wall -fPIC -O2 -std=c99 -march=native

LD := ld
LD_FLAGS := -z noexecstack

MKDIR_P = mkdir -p

CLI_SRC := cli.c

LIB_OBJS := 	$(OBJ_DIR)/hmac_sha1.o \
				$(OBJ_DIR)/sha1.o \
				$(OBJ_DIR)/sys.o \
				$(OBJ_DIR)/totp.o

TEST_OBJS := 	$(OBJ_DIR)/bytes.o \
				$(OBJ_DIR)/test.o

all: $(BIN_DIR)/lib$(LIB).a $(TEST_DIR)/$(TEST_CMD) $(BIN_DIR)/$(CLI_CMD)

cli: $(BIN_DIR)/$(CLI_CMD)

lib: $(BIN_DIR)/lib$(LIB).a

test: $(TEST_DIR)/$(TEST_CMD)


# Binary: tests
$(TEST_DIR)/$(TEST_CMD): $(TEST_OBJS) $(BIN_DIR)/lib$(LIB).a
	@[ -d $(TEST_DIR) ] || $(MKDIR_P) $(TEST_DIR)
	$(CC) $(CC_FLAGS) -o $@ $^ -L$(BIN_DIR) -lcunit -l$(LIB)
	./$(TEST_DIR)/$(TEST_CMD)

# CLI command
$(BIN_DIR)/$(CLI_CMD): $(BIN_DIR)/lib$(LIB).a
	@[ -d $(BIN_DIR) ] || $(MKDIR_P) $(BIN_DIR)
	$(CC) $(CC_FLAGS) -nostdlib -o $@ $(CLI_SRC_DIR)/$(CLI_SRC) -I$(LIB_SRC_DIR) -L$(BIN_DIR) -l$(LIB)

# AR object: library
$(BIN_DIR)/lib$(LIB).a: $(OBJ_DIR)/lib$(LIB).o
	@[ -d $(BIN_DIR) ] || $(MKDIR_P) $(BIN_DIR)
	$(AR) -rcs $@ $^

# C object: library
$(OBJ_DIR)/lib$(LIB).o: $(LIB_OBJS)
	$(LD) $(LD_FLAGS) -r -o $@ $^

# C objects: library components
$(OBJ_DIR)/%.o: $(LIB_SRC_DIR)/%.c
	@[ -d $(OBJ_DIR) ] || $(MKDIR_P) $(OBJ_DIR)
	$(CC) $(CC_FLAGS) -c -o $@ $<

# AS objects: library components
$(OBJ_DIR)/%.o: $(LIB_SRC_DIR)/%.$(AS_EXT)
	@[ -d $(OBJ_DIR) ] || $(MKDIR_P) $(OBJ_DIR)
	$(AS) $(AS_FLAGS) -o $@ $<

# C objects: development
$(OBJ_DIR)/%.o: $(DEV_SRC_DIR)/%.c
	@[ -d $(OBJ_DIR) ] || $(MKDIR_P) $(OBJ_DIR)
	$(CC) $(CC_FLAGS) -c -o $@ $<

# C objects: tests
$(OBJ_DIR)/%.o: $(TEST_SRC_DIR)/%.c
	@[ -d $(OBJ_DIR) ] || $(MKDIR_P) $(OBJ_DIR)
	$(CC) $(CC_FLAGS) -c -o $@ $< -I$(LIB_SRC_DIR) -I$(DEV_SRC_DIR)

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
