#pragma once
#include <gpgme.h>

#include "../shared/vault-types.h"
#include "userconfig.h"

int create_vkey(vaultkey_t *key, vflag_t perms);
vaultkey_t* read_vault(userconfig_t* uconfig, char* passphrase, size_t* vaultsize); 
