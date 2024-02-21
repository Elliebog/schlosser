#include "../../unity/unity.h"
#include "../../../src/shared/vault-types.h"

void setUp() {

}

void tearDown() {

}

void test_vflag_getattr() {
    //test without defines
    vflag_t flag = 0b11110101;
    //check that defines are equivalent
    TEST_ASSERT_TRUE(vflag_getattr(flag, 0b00000001));
    TEST_ASSERT_TRUE(vflag_getattr(flag, RPWD));
    TEST_ASSERT_FALSE(vflag_getattr(flag, 0b00000010));
    TEST_ASSERT_FALSE(vflag_getattr(flag, CPWD));
    TEST_ASSERT_TRUE(vflag_getattr(flag, 0b00000100));
    TEST_ASSERT_TRUE(vflag_getattr(flag, WPWD));
    TEST_ASSERT_FALSE(vflag_getattr(flag, 0b00001000));
    TEST_ASSERT_FALSE(vflag_getattr(flag, WDIR));
    TEST_ASSERT_TRUE(vflag_getattr(flag, 0b00010000));
    TEST_ASSERT_TRUE(vflag_getattr(flag, CVKEY));
    
    //Check if correct flag is retrieved
    flag = 0b00000001;
    TEST_ASSERT_TRUE(vflag_getattr(flag, RPWD));
    flag = 0b00000000;
    TEST_ASSERT_FALSE(vflag_getattr(flag, RPWD));
}

void test_vflag_setattr() {
    vflag_t flag = 0b00000000;
    
    TEST_ASSERT_EQUAL_INT(-1, vflag_setattr(NULL, RPWD, 1));
    TEST_ASSERT_TRUE(vflag_getattr(flag, RPWD));
    TEST_ASSERT_EQUAL_INT(0, vflag_setattr(&flag, RPWD, 0));
    TEST_ASSERT_FALSE(vflag_getattr(flag, RPWD));

    TEST_ASSERT_EQUAL_INT(0, vflag_setattr(&flag, CPWD, 1));
    TEST_ASSERT_TRUE(vflag_getattr(flag, CPWD));
    TEST_ASSERT_EQUAL_INT(0, vflag_setattr(&flag, CPWD, 0));
    TEST_ASSERT_FALSE(vflag_getattr(flag, CPWD));

    TEST_ASSERT_EQUAL_INT(0, vflag_setattr(&flag, WPWD, 1));
    TEST_ASSERT_TRUE(vflag_getattr(flag, WPWD));
    TEST_ASSERT_EQUAL_INT(0, vflag_setattr(&flag, WPWD, 0));
    TEST_ASSERT_FALSE(vflag_getattr(flag, WPWD));
    
    TEST_ASSERT_EQUAL_INT(0, vflag_setattr(&flag, WDIR, 1));
    TEST_ASSERT_TRUE(vflag_getattr(flag, WDIR));
    TEST_ASSERT_EQUAL_INT(0, vflag_setattr(&flag, WDIR, 0));
    TEST_ASSERT_FALSE(vflag_getattr(flag, WDIR));

     TEST_ASSERT_EQUAL_INT(0, vflag_setattr(&flag, CVKEY, 1));
    TEST_ASSERT_TRUE(vflag_getattr(flag, CVKEY));
    TEST_ASSERT_EQUAL_INT(0, vflag_setattr(&flag, CVKEY, 0));
    TEST_ASSERT_FALSE(vflag_getattr(flag, CVKEY));
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_vflag_getattr);
    RUN_TEST(test_vflag_getattr);
    return UNITY_END();
}
