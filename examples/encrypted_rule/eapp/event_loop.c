#include "event_loop.h"
#include "edge_wrapper.h"
#include "rule_params.h"
#include "rule_keystore.h"
#include "app/syscall.h"
#include <stdio.h>
#include "app/string.h"
#include "app/malloc.h"

static char *rule_params[NUM_RULE_TRIGGERS] = RULE_PARAMS;
static char *rule_params_unescaped[NUM_RULE_TRIGGERS] = RULE_PARAMS_UNESCAPED;
//static char *rule_action_params[NUM_RULE_ACTIONS] = RULE_ACTION_PARAMS;
static char *rule_action_params_unescaped[NUM_RULE_ACTIONS] = RULE_ACTION_PARAMS_UNESCAPED;
extern void __rule_function();

void *fetch_trigger_data(int trig_id, char *trigger_name, int trigger_name_sz, char *rule_params, uint64_t *blob_size, uintptr_t *nonce)
{
	uintptr_t n = SYSCALL_0(SYSCALL_GENRAND_WORD);
    int rule_param_size = strlen(rule_params);

    trigger_data_t *data = (trigger_data_t *)malloc(sizeof(trigger_data_t) + (rule_param_size + 1) * sizeof(char));
    memset(data, 0, sizeof(trigger_data_t) + (rule_param_size + 1) * sizeof(char));
    memcpy(&data->trigger_name, trigger_name, trigger_name_sz);
    data->trigger_name_size = trigger_name_sz;
    data->nonce = n;
    memcpy(&data->rule_params, rule_params, rule_param_size);

    struct edge_data msg;
	size_t data_size = ocall_get_trigger_data(data, sizeof(trigger_data_t) + (rule_param_size + 1) * sizeof(char), &msg);
    void *ret = (void *)malloc(data_size);

	copy_from_shared(ret, msg.offset, msg.size);


    // Freeing data
    free(data);

	*nonce = n;
    *blob_size = data_size;
	return ret;
}

int fetch_and_validate_data(char **trig_data, struct keystore_rule *rule)
{
    char trigger_url[200];
    char printbuf[200];
    
    for(int i = 0; i < 1; i++) {
        int url_length = snprintf(trigger_url, 200, "%d", i);
        uint64_t trigger_data_sz;
        uintptr_t nonce;
        char *t_data = fetch_trigger_data(i, trigger_url, url_length, rule_params[i], &trigger_data_sz, &nonce);
        ocall_print_buffer("[fetch_and_validate_data] Fetched trigger data\n");

        trig_data[i] = decrypt_trigger_data(t_data, trigger_data_sz, (unsigned char *)&rule->key_trigger[i], 32);
        if (trig_data[i] == NULL) {
            ocall_print_buffer("[fetch_and_validate_data] Failed to decrypt trigger data\n");
            return 0;
        }

        free(t_data);

        ocall_print_buffer("[fetch_and_validate_data] Decrypted trigger data\n");
        ocall_print_buffer(trig_data[i]);
        ocall_print_buffer("\n");

        int isvalid = validate_and_init_trigger_data(i, trig_data[i], nonce, trigger_url, url_length, rule_params_unescaped[i], TRIGGER_TIMEOUT);

        free(trig_data[i]);
        if (isvalid < 0) {

            ocall_print_buffer("[fetch_and_validate_data] Validation failed!\n");
            snprintf(printbuf, 200, "[fetch_and_validate_data] validate_and_init_trigger_data return code: %d\n", isvalid);
            ocall_print_buffer(printbuf);
            //printf("[fetch_and_validate_data] Invalid Trigger data for trigger %d\n", i);
            return 0;
        }

        ocall_print_buffer("[fetch_and_validate_data] After validate_and_init_trigger_data data\n");
    }

    return 1;
}

void format_output_data()
{
    //TODO: Do default string replacement in JSON
    char *action_default_data[NUM_RULE_ACTIONS] = { "{\"GoogleCalendar\": { \"EndTime\": \"\" }}", }; 
    int ret = format_action_data(action_default_data, 1, NULL, 0);  
    printf("[format_output_data] format_action_data returned: %d\n", ret);

}

void run_rule()
{
    format_output_data();
    __rule_function();
}

void send_data(struct keystore_rule *rule)
{
    //TODO: Ask OS to send encrypted action blob to action service
    //int *output_vector = get_action_skip_vector();
    for (int i = 0; i < NUM_RULE_ACTIONS; i++) {
        //if (output_vector[i] == 0) {
            int32_t sz = 0;
            int len_params_unescaped = strlen(rule_action_params_unescaped[i]);
            char *action_data = get_action_data(i, &sz, rule_action_params_unescaped[i], len_params_unescaped);

            int32_t action_dt_sz;
            action_data_t *action_dt = encrypt_action_data(action_data, sz + 1, (byte *)&(rule->key_action[i]), 32, &action_dt_sz);

            memcpy((void *)&action_dt->action_params, rule_action_params_unescaped[i], len_params_unescaped);
            
            int return_code = ocall_send_action_data(action_dt, action_dt_sz);
            if (return_code != 0) {
                printf("[send_data] Error sending action data %d\n", i);
            } else {
                printf("[send_data] Sent action data: %d\n", i);
            }

            free(action_data);
            free(action_dt);
        //}
    }

    return;
}
 

void event_loop(struct keystore_rule *rule, int loop_times)
{
    int i = 0;
    char *trigger_data[NUM_RULE_TRIGGERS];
    //TODO: Checkout if cleanup is needed every time
    
    
    while (i < loop_times) {
        
        clear_data();
        if (!fetch_and_validate_data(trigger_data, rule)) {

            ocall_print_buffer("[event_loop] Validation failed!\n");
            i++;
            continue;
        }

        ocall_print_buffer("[event_loop] Data Validation passed!\n");

        run_rule();

        ocall_print_buffer("[event_loop] Finished running rule\n");
        send_data(rule);
        
        i++;

    }

    ocall_print_buffer("[event_loop] Finished event_loop\n");
}