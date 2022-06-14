#ifndef _KEYSTORE_USER_H_
#define _KEYSTORE_USER_H_
#include <stdint.h>

struct keystore_user {
    uintptr_t uid;
    char username[21];
    char password[21];
};

struct enc_keystore_user {
    unsigned char ciphertext[sizeof(struct keystore_user)];
    // using AES_BLOCK_SIZE from wolfssl
    char auth_tag[16];
};

#endif
