#pragma once
#include "src/shared/vault-types.h"
#include <string.h>

int str_in_alphabet(char* str, size_t len, const char* alphabet, size_t alphabetsize); 
vflag_t parse_vflag(char* str);
void vflag_tostring(vflag_t flag, char* vflag_str);
