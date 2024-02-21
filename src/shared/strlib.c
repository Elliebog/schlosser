#include <stdlib.h>
#include <string.h>
#include "strlib.h"
#include "vault-types.h"

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

vflag_t parse_vflag(char *str) {
    vflag_t flag = 0;
    for(size_t i = 0; i < sizeof(vflag_t)*8; i++) {
        flag |= 1 << i;
    }
    return flag;
}

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
