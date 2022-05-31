#ifndef _KEYSTONE_RULE_H_
#define _KEYSTONE_RULE_H

struct keystore_rule {
    uintptr_t rid;
    int num_triggers;
    int num_actions;

    // Support atmost 20 trigger and action services for now
    char key_trigger[20][32];
    char key_action[20][32];
    char key_rule[32];

    // Hash sizes according to the Keystone SDK
    char rule_bin_hash[64];
    char runtime_bin_hash[64];
};

struct enc_keystore_rule {
    char iv[16];
    char auth_tag[16];
    struct keystore_rule rule;
};

struct keystore_rule_reply {
    char key_trigger[20][32];
    char key_action[20][32];
    char key_rule[32];
};

#endif