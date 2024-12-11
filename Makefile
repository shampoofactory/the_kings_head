LIB := tkh

TEST_CMD := test
TOTP_CMD := totpfoo
TOTP_GEN_CMD := totpgen

TOTP_GEN_SRC := totp_gen.c
TOTP_SRC := totp_foo.c

RES_DIR := ./res
TOTP_RES_DIR := $(RES_DIR)/totp

SRC_DIR := ./src
TOTP_SRC_DIR := $(SRC_DIR)/cli
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
CC_FLAGS := -Wall -fPIC -O2 -std=gnu99 -march=native -z noexecstack

LD := ld
LD_FLAGS := -z noexecstack

OBJCOPY := objcopy
OBJCOPY_FLAGS := -I binary -O elf64-x86-64 --rename-section .data=.rodata,alloc,contents,load,readonly

XXD := xxd
XXD_FLAGS := -r -p

MKDIR_P = mkdir -p

LIB_OBJS := 		$(OBJ_DIR)/aes_ks.o \
					$(OBJ_DIR)/aes_ofb.o \
					$(OBJ_DIR)/hmac_sha1.o \
					$(OBJ_DIR)/pbkdf2_hmac_sha1.o \
					$(OBJ_DIR)/sha1.o \
					$(OBJ_DIR)/sys.o \
					$(OBJ_DIR)/totp.o

TOTP_GEN_OBJS :=	$(OBJ_DIR)/totp_core.o


TOTP_OBJS :=		$(OBJ_DIR)/totp_core.o \
					$(OBJ_DIR)/totp_blk.o


TEST_OBJS := 		$(OBJ_DIR)/aes_core.o \
					$(OBJ_DIR)/aes_ofb_test.o \
					$(OBJ_DIR)/bytes.o \
					$(OBJ_DIR)/hmac_sha1_test.o \
					$(OBJ_DIR)/pbkdf2_hmac_sha1_test.o \
					$(OBJ_DIR)/rdr.o \
					$(OBJ_DIR)/rsp.o \
					$(OBJ_DIR)/sha1_core.o \
					$(OBJ_DIR)/sha1_test.o \
					$(OBJ_DIR)/totp_test.o \
					$(OBJ_DIR)/test.o

all:    $(BIN_DIR)/lib$(LIB).a \
        $(TEST_DIR)/$(TEST_CMD) \
        $(BIN_DIR)/$(TOTP_GEN_CMD) \
        $(BIN_DIR)/$(TOTP_CMD)

totp_gen: $(BIN_DIR)/$(TOTP_GEN_CMD) \
		  $(TEST_DIR)/$(TEST_CMD)

totp: $(BIN_DIR)/$(TOTP_CMD) \
	  $(TEST_DIR)/$(TEST_CMD)

lib: $(BIN_DIR)/lib$(LIB).a \
	 $(TEST_DIR)/$(TEST_CMD)
	 
test: $(TEST_DIR)/$(TEST_CMD)


# Binary: tests
$(TEST_DIR)/$(TEST_CMD): $(TEST_OBJS) $(BIN_DIR)/lib$(LIB).a
	@[ -d $(TEST_DIR) ] || $(MKDIR_P) $(TEST_DIR)
	$(CC) $(CC_FLAGS) -o $@ $^ -L$(BIN_DIR) -lcunit -l$(LIB)
	./$(TEST_DIR)/$(TEST_CMD)

# TOTP_GEN command
$(BIN_DIR)/$(TOTP_GEN_CMD): $(TOTP_GEN_OBJS) $(BIN_DIR)/lib$(LIB).a
	@[ -d $(BIN_DIR) ] || $(MKDIR_P) $(BIN_DIR)
	$(CC) $(CC_FLAGS) -o $@ $^ $(TOTP_SRC_DIR)/$(TOTP_GEN_SRC) -I$(LIB_SRC_DIR) -L$(BIN_DIR) -l$(LIB)

# TOTP command
$(BIN_DIR)/$(TOTP_CMD): $(TOTP_OBJS) $(BIN_DIR)/lib$(LIB).a
	@[ -d $(BIN_DIR) ] || $(MKDIR_P) $(BIN_DIR)
	$(CC) $(CC_FLAGS) -o $@ $^ $(TOTP_SRC_DIR)/$(TOTP_SRC) -I$(LIB_SRC_DIR) -L$(BIN_DIR) -l$(LIB)

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
	$(AS) $(AS_FLAGS) -i$(LIB_SRC_DIR) -o $@ $<

# C objects: development
$(OBJ_DIR)/%.o: $(DEV_SRC_DIR)/%.c
	@[ -d $(OBJ_DIR) ] || $(MKDIR_P) $(OBJ_DIR)
	$(CC) $(CC_FLAGS) -c -o $@ $<

# C objects: totp
$(OBJ_DIR)/%.o: $(TOTP_SRC_DIR)/%.c
	@[ -d $(OBJ_DIR) ] || $(MKDIR_P) $(OBJ_DIR)
	$(CC) $(CC_FLAGS) -c -o $@ $< -I$(LIB_SRC_DIR)

# C objects: tests
$(OBJ_DIR)/%.o: $(TEST_SRC_DIR)/%.c
	@[ -d $(OBJ_DIR) ] || $(MKDIR_P) $(OBJ_DIR)
	$(CC) $(CC_FLAGS) -c -o $@ $< -I$(LIB_SRC_DIR) -I$(DEV_SRC_DIR)

# Binary objects
$(OBJ_DIR)/%.o: $(OBJ_DIR)/%.bin
	@[ -d $(OBJ_DIR) ] || $(MKDIR_P) $(OBJ_DIR)
	$(OBJCOPY) $(OBJCOPY_FLAGS) $^ $@

# Binary data: topt resources
$(OBJ_DIR)/%.bin: $(TOTP_RES_DIR)/%.hex
	@[ -d $(OBJ_DIR) ] || $(MKDIR_P) $(OBJ_DIR)
	$(XXD) $(XXD_FLAGS) $^ $@

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
