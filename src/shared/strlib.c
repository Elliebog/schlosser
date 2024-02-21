#include <stdlib.h>
#include <string.h>
#include "strlib.h"
#include "vault-types.h"

/**
 * @brief Checks if the elements of the string are contained in an alphabet (=string)
 *
 * @param char* str string to check
 * @param size_t len length of the str
 * @param char* alphabet the alphabet string
 * @param size_t alphabetsize length of the alphabet string
 * @return -1 on error. (Pointer is null) 0 if the string elements is not in alphabet. else 1
 */
int str_in_alphabet(char* str, size_t len, const char* alphabet, size_t alphabetsize) {
    if(str == NULL || alphabet == NULL) {
        return -1;
    }
    //Build a map with size 255 -> set element at index = char-value to 1 if it is in the alphabet 
    //and afterwards iterate through string and check that element is always 1
    unsigned char map[256];
    for(size_t i = 0; i < alphabetsize; i++) {
        map[alphabet[i]] = 1;
    }

    for(size_t i = 0; i < len; i++) {
        if(!map[str[i]]) {
            //map doesn't have 1 here -> str is not in alphabet
            return 0;
        }
    }
    return 1;
}

/**
 * @brief convert the vflag string into the vflag_t structure
 *
 * @param char* str the string to convert (must be at least 8 chars long)
 * @return 0 if the string doesn't only contain 1 and 0s. Else the converted flag 
 */
vflag_t parse_vflag(char *str) {
    vflag_t flag = 0;
    for(size_t i = 0; i < sizeof(vflag_t)*8; i++) {
        switch (str[i]) {
            case '1':
                flag |= 1 << i;
                break;
            case '0':
                break;
            default: 
                return 0;
        }
    }
    return flag;
}

/**
 * @brief Convert vflag_t structure to string
 *
 * @param vflag_t flag 
 * @param char* vflag_str The string to put the contents in. Must be at least of size=8
 */
void vflag_tostring(vflag_t flag, char* vflag_str) {
    size_t vflag_len = sizeof(vflag_t)*8;
    for(size_t i = 0; i < vflag_len; i++) {
        if(flag & (1 << (vflag_len - i))) {
            vflag_str[i] = '1';
        } else {
            vflag_str[i] = '0';
        }
    }
}
