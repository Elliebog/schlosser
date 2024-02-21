#pragma once
// Each userspace has one vault (vaults and userspace should be different directories. Adjustable in config)
// Vault file syntax
// the vault files are not meant to be read by users and the parsing functions does not expect comments so don't edit them
// Each line in the file corresponds to one vault key
// Line syntax:
// 
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

typedef unsigned char vflag_t;
//              0b01234567
#define RPWD    0b00000001
#define CPWD    0b00000010
#define WPWD    0b00000100
#define WDIR    0b00001000
#define CVKEY   0b00010000

int vflag_setattr(vflag_t *flag, unsigned char mask, unsigned char val);
vflag_t vflag_getattr(vflag_t flag, unsigned char mask);

#define VKEY_LEN 256
#define VDECRYPTKEY_LEN 32
struct vaultkey {
    char key[VKEY_LEN];
    vflag_t perms;
};

typedef struct vaultkey vaultkey_t;
