CC = gcc
C_FLAGS = -Wall -Wextra

TEST_FILES = $(shell find ../testing/test/ -name '*_test.c')
SRC_FILES = $(TEST_FILES:../testing/test/%_test.c=test/%.c)
UNITY_FILE = unity/unity.c
testing:
	$(CC) $(C_FLAGS) $(TEST_FILES) $(SRC_FILES) $(UNITY_FILE) -o
	# Change to pattern rule but idea stays the same
clean: 
