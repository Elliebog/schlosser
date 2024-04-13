CC = clang
C_FLAGS = -I ./
C_LIBS = -lgpgme
TEST_FILES = $(shell find testing/test -name '*_test.c')
SRC_FILES = $(filter-out src/server/schlosser.c, $(shell find src/ -name '*.c'))
OUT_FILES = $(patsubst %.c,%.o, $(TEST_FILES:testing/test/%=testing/out/%))
UNITY_FILES = testing/unity/unity.c

testing: $(OUT_FILES)
	echo "Compiled $(OUT_FILES)"

%.o: $(patsubst testing/out%_test.o, testing/test/%_test.c, $@)
	mkdir -p $(dir $@)
	$(eval TEST_FILE := $(patsubst testing/out/%_test.o, testing/test/%_test.c, $@))
	$(CC) $(C_FLAGS) $(C_LIBS) $(UNITY_FILES) $(SRC_FILES) $(TEST_FILE)

clean:
	rm -rf testing/out/
	rm -rf out/
