#ifndef _H_RULE_KEYSTORE_H_
#define _H_RULE_KEYSTORE_H_

#include <stdint.h>

#define TRIGGER_KEY_LEN 32
#define ACTION_KEY_LEN 32
#define RULE_KEY_LEN 32
#define RULE_BIN_HASH_LEN 64
#define RUNTIME_BIN_HASH_LEN 64
#define MAX_TRIGGER_SERVICES 20
#define MAX_ACTION_SERVICES 20

struct keystore_rule {
    uintptr_t rid;
    int num_triggers;
    int num_actions;

    // Support atmost 20 trigger and action services for now
    char key_trigger[MAX_TRIGGER_SERVICES][TRIGGER_KEY_LEN];
    char key_action[MAX_ACTION_SERVICES][ACTION_KEY_LEN];
    char key_rule[RULE_KEY_LEN];

    // Hash sizes according to the Keystone SDK
    char rule_bin_hash[RULE_BIN_HASH_LEN];
    char runtime_bin_hash[RUNTIME_BIN_HASH_LEN];
};


#endif