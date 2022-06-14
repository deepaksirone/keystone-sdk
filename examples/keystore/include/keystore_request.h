#ifndef _H_KEYSTORE_REQUEST_H
#define _H_KEYSTORE_REQUEST_H

typedef struct reguser_request {
    int user_len;
    int password_len;
    char username[20];
    char password[20];
} reguser_request_t;

typedef struct regrule_request {
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
} regrule_request_t;


typedef struct runtime_request {
    uintptr_t user_id;
    uintptr_t rule_id;
    struct report_t report;
} runtime_request_t;

#endif