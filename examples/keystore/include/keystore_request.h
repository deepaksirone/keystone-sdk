#ifndef _H_KEYSTORE_REQUEST_H
#define _H_KEYSTORE_REQUEST_H

#include <stdint.h>
#include "keystore_defs.h"
#include "keystore_report.h"

#define REGUSER_REQUEST 0x1
#define REGRULE_REQUEST 0x2
#define RUNTIME_REQUEST 0x3

// Chain Replication Defines
#define CHAIN_R_ASGN_SVR_ID 0x4
#define CHAIN_R_SET_STORAGE_KEY 0x5
#define CHAIN_R_FORWARD_REQUEST 0x6
#define CHAIN_R_ACK_REQUEST 0x7

typedef struct reguser_request {
    int user_len;
    int password_len;
    char username[USERNAME_SIZE];
    char password[PASSWORD_SIZE];
} reguser_request_t;

typedef struct regrule_request {
    uint64_t rid;
    int32_t num_triggers;
    int32_t num_actions;

    char username[USERNAME_SIZE];
    char password[PASSWORD_SIZE];

    // Support atmost 20 trigger and action services for now
    char key_trigger[MAX_TRIGGERS][TRIGGER_KEY_SIZE];
    char key_action[MAX_ACTIONS][ACTION_KEY_SIZE];
    char key_rule[RULE_KEY_SIZE];

    // Hash sizes according to the Keystone SDK
    char rule_bin_hash[EAPP_BIN_HASH_SIZE];
    char sm_bin_hash[SM_BIN_HASH_SIZE];
} regrule_request_t;


typedef struct runtime_request {
    uintptr_t user_id;
    uintptr_t rule_id;
    struct report_t report;
} runtime_request_t;

typedef struct assign_server_id_request {
    uintptr_t server_id;
} server_id_request_t;

typedef struct storage_key_request {
    char storage_key[STORAGE_KEY_SIZE];
} storage_key_request_t;

typedef struct ack_key_request {
    uint64_t ack_id;
} ack_key_request_t;

typedef struct request {
    char type;
    union {
        runtime_request_t runtime_req;
        regrule_request_t regrule_req;
        reguser_request_t reguser_req;
        server_id_request_t serverid_req;
        storage_key_request_t storage_key_req;
        ack_key_request_t ack_key_req;
    } data;
} request_t;

#endif