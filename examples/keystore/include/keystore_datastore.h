#ifndef _H_KEYSTORE_DATASTORE_H_
#define _H_KEYSTORE_DATASTORE_H_
#include <sys/types.h>
#include <stdint.h>

extern "C" int32_t init_keystore(char *pathname);

extern "C" int32_t get_user_record(char *username, struct enc_keystore_user *enc_user);
extern "C" int32_t set_user_record(char *username, struct enc_keystore_user *enc_user);
extern "C" int32_t get_rule_record(uintptr_t uid, uintptr_t rule_id, struct enc_keystore_rule *enc_rule, int exist_query);
extern "C" int32_t set_rule_record(uintptr_t uid, uintptr_t rule_id, struct enc_keystore_rule *enc_rule);

#endif