#ifndef _H_EVENT_LOOP_H_
#define _H_EVENT_LOOP_H_
#include <stdint.h>
#include "rule_keystore.h"

#define SYSCALL_GENRAND_WORD 1006
// Setting trigger response timeout to be 20 seconds
#define TRIGGER_TIMEOUT 20

void event_loop(struct keystore_rule *rule,int loop_times);
void *fetch_trigger_data(int trig_id, char *trigger_url, int trigger_url_sz, char *rule_params, uint64_t *blob_size, uintptr_t *nonce);
void *decrypt_trigger_data(void *encrypted_blob, int encrypted_blob_sz, unsigned char *key, int key_sz);
extern int validate_and_init_trigger_data(int trig_id, char *trigger_data, uintptr_t nonce, char *trigger_url, int trigger_url_sz, char *rule_params, uint64_t timeout);
extern void clear_data();
#endif