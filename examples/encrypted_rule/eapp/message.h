#ifndef _H_MESSAGE_H_
#define _H_MESSAGE_H_
#include "keystore_report.h"
#include <stdint.h>

#define SYSCALL_GENRAND_WORD 1006

int send_key_retrieval_message(uintptr_t uid, uintptr_t rule_id, struct report_t *report, struct keystore_rule *rule);
void *decrypt_trigger_data(void *encrypted_blob, int encrypted_blob_sz, unsigned char *key, int key_sz);

#endif
