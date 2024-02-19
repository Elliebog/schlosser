#include <stdio.h>
#include <sys/random.h>
#include <stdio.h>
#include <gpgme.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "../shared/vault-types.h"
#include "userconfig.h"
#include "vault.h"
#include "../shared/strlib.h"

// Each userspace has one vault (vaults and userspace should be different directories. Adjustable in config)
// Vault file syntax
// the vault files are not meant to be read by users and the parsing functions does not expect comments so don't edit them
// Each line in the file corresponds to one vault key
//
// Line syntax:
// Key,permissions
// Key = 256 long string
// permissions = 8 long string consisting of 0 and 1s each corresponding to flags described below
// The symbols used in the keys are: "abcdefghijklmnopqrstuvwxyzABCDEFGHIKLMNOPQRSTUVWXYZ0123456789!#$%&'()*+-./:;<=>?@[\]^_{|}~"
//
// Permissions:
// From LSB to MSB
// 0th: RPWD Read Passwords (Client is allowed to read passwords)
// 1st: CPWD Can create new passwords
// 2nd: WPWD Can edit and generally write passwords also implies 
// 3rd: WDIR Can edit directories and create subdirectories
// 4th: CVKEY Can create new Vault key with the same permissions

gpgme_error_t get_vault_passphrase(void* hook, const char* uid_hint, const char* passphrase_info, int prev_was_bad, int fd);

static const char VKEY_ALPHABET[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIKLMNOPQRSTUVWXYZ0123456789!#$%&'()*+-./:;<=>?@[\\]^_{|}~"; 

#define iferr_throw(err) if(err) { printf("GPGme failed with error code %s from source: %s", gpgme_strerror(err), gpgme_strsource(err)); return -1;}


//TODO add documentation and fix your doxygen plugin
int create_vkey(vaultkey_t *key, vflag_t perms) {
    // use random bytes from /dev/urandom and convert them to random floats from 0 to 1
    unsigned char buffer[VKEY_LEN];
    ssize_t read = getrandom(&buffer, VKEY_LEN, 0);
    // check if an error has occured (err = -1) or not enough bytes have been read
    if(read < 0 || read != 255) {
        return -1;
    }

    for(size_t i = 0; i < VKEY_LEN; i++) {
        //this index has range 0..255 because integer cast rounds down and 255/256 < 1
        int index = ((float)buffer[i]/256) * sizeof(VKEY_ALPHABET);
        key->key[i] = VKEY_ALPHABET[index];
    }
    key->perms = perms;

    return 0;
}

int iterate_vault(userconfig_t* uconfig, char* passphrase, handle_key_cb_t handle_key_cb) {  
    //First check if vaultpath and passphrase are valid strings, then check if vaultpath is a valid path to a file
    if(uconfig->vaultpath == NULL || passphrase == NULL) {
        return -1;
    }

    // try to open vault in readonly
    FILE *fp = fopen(uconfig->vaultpath, "r");
    if(fp == NULL) {
        return -1;
    }
    
    //Now use GPGme to decrypt the file and load its decrypted content into memory 
    // By using GPG me we avoid having to create a temporary unencrypted file, which could be observed in an attack 
    gpgme_ctx_t context;
    gpgme_error_t err;
    gpgme_data_t input;
    gpgme_data_t output;
    
    //Create context 
    err = gpgme_new(&context);
    iferr_throw(err)
    
    //setup the correct passphrase callback
    //Expand passphrase to 32 characters
    char passwd[32];
    snprintf(passwd, VDECRYPTKEY_LEN, "%32s", passphrase);
    gpgme_set_passphrase_cb(context, &get_vault_passphrase, passwd);
    
    // Create input cipher and store decrypted output in plain output data
    gpgme_data_new_from_stream(&input, fp);
    gpgme_op_decrypt(context, input, output);
    
    //Now we can read the contents of the file
    for (int i = 0; i < uconfig->max_vkeys; i++) {
        // prepare key and permissions for handling operations 
        vaultkey_t* vkey = malloc(sizeof(vaultkey_t));
        gpgme_data_read(output, vkey->key, 256);
        //check if key is valid (is contained in alphabet) -> to prevent possible attacks from modifying the vaultkeyfile
        if(!str_in_alphabet(vkey->key, VKEY_LEN, VKEY_ALPHABET, sizeof(VKEY_ALPHABET))) {
            printf("Line %d in vault file is faulty", i);
            continue;
        }
        
        char permsbuffer[10];
        gpgme_data_read(output, permsbuffer, 10);
        //,00000000\n is the normal format (or \n replaced with EOF)
        if(permsbuffer[0] != ',' || permsbuffer[9] != '\n') {
            printf("Line %d in vault file is faulty", i);
        }
        
        //check if perms is valid and parse
        if(!str_in_alphabet(permsbuffer+1, sizeof(vflag_t)*8, "01", 2)) {
            printf("Line %d in vault file is faulty", i);
        }

        vkey->perms = parse_vflag(permsbuffer+1);
        // dependent on return value from callback do different things
        enum vaultkey_action action = handle_key_cb(vkey);
        switch (action) {
            case FINISH_ITER:
                return -1;
            case DELETE_KEY:
                break;
            case DELETE_AND_FIN:
                break;
            case NOTHING:
                break;
            
        }
    }
    
}

int write_vault(gpgme_data_t *output, char* passphrase, vaultkey_t* key, size_t size) {
    for(size_t i = 0; i < size; i++) {
        //convert perms to string
        char perm_str[8];
        vflag_tostring(key[i].perms, perm_str);

        //256 + 8 + 1 + 1 (1 for , 1 for newline)
        char line[266];
        int written = 0;
        if(i != 0) { 
            written = 266;
            snprintf(line, written,  "\n%256s,%8s", key->key, perm_str);
        } else {
            written = 265;
            snprintf(line, 265, "%256s,%8s", key->key, perm_str);
        }
        // write the line to output data
        gpgme_data_write(*output, line, written);
    }
    return size;
}

gpgme_error_t get_vault_passphrase(void* hook, const char* uid_hint, const char* passphrase_info, int prev_was_bad, int fd) {
    // GPGme will call this function which then provides the password to unlock the vault. 
    // (This replaces the normal callback function which asks for user input. -> reset after operation is done)
    // In case of a symmetric cipher -> uid_hint = NULL
    if(uid_hint == NULL) {
        write(fd, hook, VDECRYPTKEY_LEN);
        write(fd, "\n", 1);
    }
    return 0;
}
