CC = gcc
C_FLAGS = -Wall -Wextra
C_LIBS = -lgpgme

TEST_FILES = $(shell find test/ -name '*_test.c')
SRC_FILES = $(shell find ../src/ -name '*.c')
OUT_FILES = $(patsubst %.c,%.o, $(TEST_FILES:test/%=out/%))
UNITY_FILE = unity/unity.c
testing: clean $(OUT_FILES)
	echo "Test"
%.o: $(patsubst out/%_test.o, test/%_test.c, $@)
	mkdir -p $(dir $@)
	$(eval TEST_FILE := $(patsubst out/%_test.o, test/%_test.c, $@))
	$(CC) $(C_FLAGS) $(C_LIBS) $(UNITY_FILE) $(SRC_FILES) $(TEST_FILE) -o $@	
clean: 
	rm -rf out/
