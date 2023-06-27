#ifndef _H_KEYSTORE_DEFS_H_
#define _H_KEYSTORE_DEFS_H_

#define USERNAME_SIZE 21
#define PASSWORD_SIZE 21

#define MAX_TRIGGERS 20
#define MAX_ACTIONS 20
#define TRIGGER_KEY_SIZE 32
#define ACTION_KEY_SIZE 32
#define RULE_KEY_SIZE 32

#define RUNTIME_BIN_HASH_SIZE 64
#define EAPP_BIN_HASH_SIZE 64

#define IV_SIZE 16

#define KEYSTORE_PORT 7777

#if defined(DEBUG_RULE)
#define DEBUG_PRINT(fmt, args...)    fprintf(stderr, fmt, ## args)
#else
#define DEBUG_PRINT(fmt, args...)    
#endif

#define SECURE_CODE __attribute__ ((section(".secure_code"), noinline))
#define SECURE_DATA __attribute__((section(".secure_data")))

#endif