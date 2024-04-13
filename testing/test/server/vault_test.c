#include "testing/test/test_globals.h"
#include "testing/unity/unity.h"
#include "src/server/vault.h"
#include "src/shared/strlib.h"
#include <stdlib.h>
#include <string.h>

vaultkey_t* vkey = NULL;

void setUp() {
    vkey = malloc(sizeof(vaultkey_t));
}

void tearDown() {
    free(vkey);
}

void test_create_key() {
    vflag_t perms = RPWD | CPWD | WPWD; 
    char alphabet[256] = VKEY_ALPH_STRING; 
    TEST_ASSERT_EQUAL_INT(0, create_vkey(vkey, perms));
    TEST_ASSERT_EQUAL_INT(256, strlen(vkey->key));
    TEST_ASSERT_EQUAL_INT(0, str_in_alphabet(vkey->key, 256, alphabet, 256));
    TEST_ASSERT_EQUAL_UINT8(perms, vkey->perms);
} 

//TODO: Test Write vault function and check whether or not to use raw binary format or txt style for better debugging ability

int main() {
    UNITY_BEGIN();
    return UNITY_END();
}
