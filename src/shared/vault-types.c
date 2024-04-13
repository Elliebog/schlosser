#include "src/shared/vault-types.h"
#include <stdlib.h>


/**
 * @brief Set an attribute in the vflag_t structure
 *
 * @param vflag_t* flag
 * @param unsigned char mask What flag to set
 * @param unsigned char val the value to set the flag to (0 or 1)
 * @return 0 if the change was successful or -1 if the pointer is NULL
 */
int vflag_setattr(vflag_t *flag, unsigned char mask, unsigned char val) {
    if(flag == NULL) {
        return -1;
    }

    *flag &= mask & val;
    return 0;
}

/**
 * @brief Get an attribute of the vflag_t structure
 *
 * @param vflag_t flag 
 * @param mask what flag to retrieve
 * @return 1 if the flag is set. anything else if the flag is set
 */
unsigned char vflag_getattr(vflag_t flag, unsigned char mask) {
    return flag & mask;    
}
