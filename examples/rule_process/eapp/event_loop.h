#ifndef _H_EVENT_LOOP_H_
#define _H_EVENT_LOOP_H_
#include <stdint.h>
#include "rule_keystore.h"
#include "encl_message.h"

#define SYSCALL_GENRAND_WORD 1006
#define SYSCALL_VERIFY_NONCE 1010
// Setting trigger response timeout to be 20 seconds
#define TRIGGER_TIMEOUT 20

void event_loop(struct keystore_rule *rule,int loop_times);
void *fetch_trigger_data(int trig_id, char *trigger_url, int trigger_url_sz, char *rule_params, uint64_t *blob_size, uintptr_t *nonce);
void *decrypt_trigger_data(void *encrypted_blob, int encrypted_blob_sz, unsigned char *key, int key_sz);
action_data_t *encrypt_action_data(void *action_data, int action_data_sz, unsigned char *key, int key_sz, int32_t *struct_sz);
extern int validate_and_init_trigger_data(int trig_id, char *trigger_data, uintptr_t nonce, 
            char *trigger_url, int trigger_url_sz, char *rule_params, uint64_t timeout);
// Same as above but does not check the nonce and the 
extern "C" int init_trigger_data(int trig_id, char *trigger_data, uintptr_t nonce, 
    char *trigger_url, int trigger_url_sz, char *rule_params, uint64_t timeout);
//Returns the skip vector after the rule has finished execution
extern "C" int format_action_data(char **action_data_json, int num_actions, char **ingredients, int num_ingredients);
extern "C" int *get_action_skip_vector();
//Includes the action params and the nonce in the returned data
extern "C" char *get_action_data(int i, int32_t *size, char *action_params, int32_t action_param_sz);
extern "C" void clear_data();
#endif