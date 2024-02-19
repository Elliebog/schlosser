#pragma once
struct userconfig {
    unsigned int max_vkeys; // maximum number of vault keys
    char* vaultpath;
};

typedef struct userconfig userconfig_t;
