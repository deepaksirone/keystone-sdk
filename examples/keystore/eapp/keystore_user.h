#ifndef _KEYSTONE_USER_H_
#define _KEYSTONE_USER_H_
#include <stdint.h>

struct keystone_user {
    uintptr_t uid;
    char username[21];
    char password[21];
};

struct enc_keystone_user {
    unsigned char ciphertext[sizeof(keystone_user)];
    // using AES_BLOCK_SIZE from wolfssl
    char auth_tag[16];
};

#endif
