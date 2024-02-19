#pragma once
#include "../shared/vault-types.h"

enum vaultkey_action {
    NOTHING = 0, FINISH_ITER = 1, DELETE_KEY = 2, DELETE_AND_FIN = 3
};
typedef enum vaultkey_action (*handle_key_cb_t)(vaultkey_t* key);
