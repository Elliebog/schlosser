#pragma once
#include <gpgme.h>

#include "../shared/vault-types.h"
#include "userconfig.h"

enum vaultkey_action {
    NOTHING = 0, FINISH_ITER = 1, DELETE_KEY = 2, DELETE_AND_FIN = 3
};
typedef enum vaultkey_action (*handle_key_cb_t)(vaultkey_t* key);

gpgme_error_t get_vault_passphrase(void* hook, const char* uid_hint, const char* passphrase_info, int prev_was_bad, int fd);
int create_vkey(vaultkey_t *key, vflag_t perms);
int access_vault(userconfig_t* uconfig, char* passphrase, handle_key_cb_t handle_key_cb); 
