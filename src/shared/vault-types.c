#include "vault-types.h"
#include <stdlib.h>

int vflag_setattr(vflag_t *flag, unsigned char mask, unsigned char val) {
    if(flag == NULL) {
        return -1;
    }

    *flag &= mask & val;
    return *flag;
}

vflag_t vflag_getattr(vflag_t flag, unsigned char mask) {
    return flag & mask;    
}
