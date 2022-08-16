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

	*nonce = n;
    *blob_size = data_size;
	return ret;
}

int fetch_and_validate_data(char **trig_data, struct keystore_rule *rule)
{
    char trigger_url[200];
    
    for(int i = 0; i < 1; i++) {
        int url_length = snprintf(trigger_url, 200, "%d", i);
        uint64_t trigger_data_sz;
        uintptr_t nonce;
        char *t_data = fetch_trigger_data(i, trigger_url, url_length, rule_params[i], &trigger_data_sz, &nonce);
        trig_data[i] = decrypt_trigger_data(t_data, trigger_data_sz, (unsigned char *)&rule->key_trigger[i], 32);

        int isvalid = validate_and_init_trigger_data(i, trig_data[i], nonce, trigger_url, url_length, rule_params_unescaped[i], TRIGGER_TIMEOUT);
        if (!isvalid) {
            printf("[fetch_and_validate_data] Invalid Trigger data for trigger %d\n", i);
            return 0;
        }
    }

    return 1;
}

void format_output_data()
{
    //TODO: Do default string replacement in JSON
    return;
}

void run_rule()
{
    format_output_data();
    __rule_function();
}

void send_data()
{
    //TODO: Ask OS to send encrypted action blob to action service
    return;
}


void event_loop(struct keystore_rule *rule, int loop_times)
{
    int i = 0;
    char *trigger_data[NUM_RULE_TRIGGERS];
    //TODO: Checkout if cleanup is needed every time
    

    while (i < loop_times) {
        
        if (!fetch_and_validate_data(trigger_data, rule)) {
            i++;
            continue;
        }

        run_rule();
        send_data();
        
        i++;

    }
}