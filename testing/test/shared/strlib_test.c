#include "testing/unity/unity.h"
#include "src/shared/strlib.h"
#include <string.h>

void setUp() {

}

void tearDown() {
    
}

void test_str_in_alphabet() {
    char* alphabet = "abc123456";
    char* str = "aaa45623";
    size_t alphabet_len = strlen(alphabet);
    size_t str_len = strlen(str);
    // test null handling
    TEST_ASSERT_EQUAL_INT(-1, str_in_alphabet(NULL, str_len, alphabet, alphabet_len));
    TEST_ASSERT_EQUAL_INT(-1, str_in_alphabet(str, str_len, NULL, alphabet_len));
    TEST_ASSERT_TRUE(str_in_alphabet(str, str_len, alphabet, alphabet_len));

    str = "912345aaa";
    str_len = strlen(str);
    TEST_ASSERT_FALSE(str_in_alphabet(str, str_len, alphabet, alphabet_len));
    TEST_ASSERT_FALSE(str_in_alphabet(str, str_len-5, alphabet, alphabet_len));

    str = "12345aaa9";
    str_len = strlen(str);
    TEST_ASSERT_FALSE(str_in_alphabet(str, str_len, alphabet, alphabet_len));
    TEST_ASSERT_TRUE(str_in_alphabet(str, str_len-1, alphabet, alphabet_len));
    
    str = "12345";
    str_len = strlen(str);
    TEST_ASSERT_TRUE(str_in_alphabet(str, str_len, alphabet, alphabet_len));
    TEST_ASSERT_FALSE(str_in_alphabet(str, str_len, alphabet, alphabet_len-3));
}

void test_parse_vflag() {
    vflag_t flag = 0b00011010;
    char* flag_str = "00011010";
    TEST_ASSERT_EQUAL_UINT8(flag, parse_vflag(flag_str));
    char* err_flag_str = "abc00110";
    TEST_ASSERT_EQUAL_UINT8(0, parse_vflag(err_flag_str));

    char* wrong_flag_str = "00011000";
    TEST_ASSERT_NOT_EQUAL_UINT8(flag, parse_vflag(wrong_flag_str));
} 

void test_vflag_tostring() {
    vflag_t flag = 0b00010101;
    char* flag_str = "00010101";
    char gen_flag_str[9];
    vflag_tostring(flag, gen_flag_str);
    TEST_ASSERT_EQUAL_STRING_LEN(flag_str, gen_flag_str, 8);
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_str_in_alphabet);
    RUN_TEST(test_parse_vflag);
    return UNITY_END();
}
