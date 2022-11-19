#include <stdio.h>
#include <fcntl.h>           
#include <sys/stat.h>
#include <string.h>
#include <assert.h>

#include "keystore_datastore.h"
#include "keystore_user.h"
#include "keystore_rule.h"
#include "keystore_defs.h"

char _pathname[4096];
char _filepath[4096];
char filebuffer[5000];

extern "C" int32_t init_keystore(char *pathname) {
    strncpy(_pathname, pathname, 4095);
    return 0;
}

// Returns 1 and copies the struct to the pointer if the user file exists
extern "C" int32_t get_user_record(char *username, struct enc_keystore_user *enc_user) {
    DEBUG_PRINT("[get_user_record] Entering\n");
    snprintf(_filepath, 4096, "%s/%s.dat", _pathname, username);
    FILE *fp = fopen(_filepath, "r");
    if (fp == NULL) {
        DEBUG_PRINT("[get_user_record] Record not found\n");
        return 0;
    }

    int i = 0;
    while (!feof(fp) && (i < sizeof(struct enc_keystore_user))) {
        i += fread(filebuffer + i, 1, sizeof(struct enc_keystore_user) - i, fp);
    }

    assert(i == sizeof(struct enc_keystore_user));
    memcpy(enc_user, filebuffer, i);

    fclose(fp);
    DEBUG_PRINT("[get_user_record] Record found\n");
    return 1;
}

// Warning: Overwrites previous record, use get_user_record to test for presence
extern "C" int32_t set_user_record(char *username, struct enc_keystore_user *enc_user) {
    DEBUG_PRINT("[set_user_record] Entering\n");
    snprintf(_filepath, 4096, "%s/%s.dat", _pathname, username);
    FILE *fp = fopen(_filepath, "w+");

    if (fp == NULL) {
        DEBUG_PRINT("[set_user_record] Unable to create file record\n");
        return 1;
    }

    int i = 0;
    while (i < sizeof(struct enc_keystore_user)) {
        i += fwrite(((char *)enc_user) + i, 1, sizeof(struct enc_keystore_user) - i, fp);
    }

    fflush(fp);
    fclose(fp);

    DEBUG_PRINT("[set_user_record] Created user record\n");
    return 0;
}


extern "C" int32_t get_rule_record(uintptr_t uid, uintptr_t rule_id, struct enc_keystore_rule *enc_rule, int exist_query) {
    DEBUG_PRINT("[get_rule_record] Entering, exists_query: %d\n", exist_query);
    DEBUG_PRINT("[get_rule_record] uid: %ld, rule_id: %ld\n", uid, rule_id);
    snprintf(_filepath, 4096, "%s/%lu_%lu.dat", _pathname, uid, rule_id);
    
    if (exist_query) {
        struct stat s;
        DEBUG_PRINT("[get_rule_record] Returning exists query\n");
        return (stat(_filepath, &s) == 0) ? 1 : 0;
    }

    FILE *fp = fopen(_filepath, "r");
    if (fp == NULL) {
        DEBUG_PRINT("[get_rule_record] Rule not found\n");
        return 0;
    }

    int i = 0;
    while (!feof(fp) && (i < sizeof(struct enc_keystore_rule))) {
        i += fread(filebuffer + i, 1, sizeof(struct enc_keystore_rule) - i, fp);
    }

    assert(i == sizeof(struct enc_keystore_rule));
    memcpy(enc_rule, filebuffer, i);

    fclose(fp);

    DEBUG_PRINT("[get_rule_record] Record found\n");
    return 1;
}

extern "C" int32_t set_rule_record(uintptr_t uid, uintptr_t rule_id, struct enc_keystore_rule *enc_rule) {
    DEBUG_PRINT("[set_rule_record] Entering\n");
    snprintf(_filepath, 4096, "%s/%lu_%lu.dat", _pathname, uid, rule_id);
    FILE *fp = fopen(_filepath, "w+");

    if (fp == NULL) {
        DEBUG_PRINT("[set_rule_record] Unable to create record\n");
        return 1;
    }

    int i = 0;
    while (i < sizeof(struct enc_keystore_rule)) {
        i += fwrite(((char *)enc_rule) + i, 1, sizeof(struct enc_keystore_rule) - i, fp);
    }

    fflush(fp);
    fclose(fp);

    DEBUG_PRINT("[set_rule_record] Record created\n");
    return 0;
}