#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/certs_test.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/types.h>


#include "../eapp/event_loop.h"
#include "../eapp/rule_params.h"
#include "../eapp/rule_keystore.h"
#include <stdio.h>


static char *rule_params[NUM_RULE_TRIGGERS] = RULE_PARAMS;
static char *rule_params_unescaped[NUM_RULE_TRIGGERS] = RULE_PARAMS_UNESCAPED;
//static char *rule_action_params[NUM_RULE_ACTIONS] = RULE_ACTION_PARAMS;
static char *rule_action_params_unescaped[NUM_RULE_ACTIONS] = RULE_ACTION_PARAMS_UNESCAPED;

extern "C" void __rule_function();
void *get_trigger_data(trigger_data_t *data, size_t *trigger_data_sz);
int32_t send_action_data(action_data_t *data);


static char dec_data[4096];
void *decrypt_trigger_data(void *encrypted_blob, int encrypted_blob_sz, unsigned char *key, int key_sz)
{
    trigger_response_t *resp = (trigger_response_t *)encrypted_blob;
	// IV is at the beginning of the blob
	char *iv = (char *)&resp->iv;
	int iv_sz = 16;

	// Followed by the tag
	char *code_tag = (char *)&resp->tag;
	int tag_sz = 16;

	char *enc_dat_start = (char *)&resp->ciphertext;

	Aes enc;
    wc_AesInit(&enc, NULL, INVALID_DEVID);

	//void *decrypted_data = (void *)malloc(encrypted_blob_sz + 1);
    void *decrypted_data = (void *)dec_data;
    memset(decrypted_data, 0, encrypted_blob_sz + 1);

	int ret;
	if ((ret = wc_AesGcmSetKey(&enc, (const byte *)key, key_sz)) != 0) {
            printf("[-][decrypt_trigger_data] Error setting key!");
            return NULL;
    }

	if ((ret = wc_AesGcmDecrypt(&enc, (byte *)decrypted_data, (byte *)enc_dat_start, resp->ciphertext_size, (byte *)iv, iv_sz,
                (byte *)code_tag, tag_sz, NULL, 0)) != 0) {
            printf("[decrypt_trigger_data] Error decrypting! ret: %d\n", ret);
            printf("[decrypt_trigger_data] AES_GCM_AUTH_E == ret: %d\n", AES_GCM_AUTH_E == ret);
	    	//free(decrypted_data);
            return NULL;
    }

	return decrypted_data;
}

static char randbuf[16];
char *gen_iv_urandom(int iv_size) {
    //char *res = (char *) malloc(iv_size * sizeof(char));
    char *res = (char *)randbuf;
    //FILE *fp = fopen("/dev/urandom", "r+");
    //fread(res, 1, iv_size, fp);
    //fclose(fp);
    for (int i = 0; i < iv_size; i++)
        res[i] = 0xaa;
    return res;
}

static char action_dt_array[sizeof(action_data_t) + 5 * 4096];
action_data_t *encrypt_action_data(void *action_data, int action_data_sz, unsigned char *key, int key_sz, int32_t *struct_sz) {
    //action_data_t *action_dt = (action_data_t *)malloc(sizeof(action_data_t) + action_data_sz * sizeof(unsigned char));
    action_data_t *action_dt = (action_data_t *)action_dt_array;
    memset(action_dt, 0, sizeof(action_data_t) + action_data_sz * sizeof(unsigned char));
    
    char *iv = gen_iv_urandom(16);
    int iv_sz = 16;

    memcpy((void *)&action_dt->iv, (void *)iv, 16);
    //free(iv);
    action_dt->ciphertext_size = action_data_sz;

    Aes enc;
    wc_AesInit(&enc, NULL, INVALID_DEVID);

    int ret;
    if ((ret = wc_AesGcmSetKey(&enc, (const byte *)key, key_sz)) != 0) {
            printf("[-][encrypt_action_data] Error setting key!\n");
            return NULL;
    }

    // No Additional data here
    if ((ret = wc_AesGcmEncrypt(&enc, (byte *)&action_dt->ciphertext, (byte *)action_data, action_data_sz, (byte *)&action_dt->iv, iv_sz, (byte *)&action_dt->tag,
                sizeof(action_dt->tag), NULL, 0)) != 0) {
        printf("[encrypt_action_data] Error encrypting! ret: %d\n", ret);
        //printf("[encrypt_action_data] AES_GCM_AUTH_E == ret: %d\n", AES_GCM_AUTH_E == ret);
	    //free(action_dt);
        return NULL;
    }

    

    *struct_sz = sizeof(action_data_t) + action_data_sz * sizeof(unsigned char);
    return action_dt;
}

static char trigger_data[sizeof(trigger_data_t) + 5 * 4096];
void *fetch_trigger_data(int trig_id, char *trigger_name, int trigger_name_sz, char *rule_params, uint64_t *blob_size, uintptr_t *nonce)
{
	uintptr_t n = 0x0a0a0a0a;
    int rule_param_size = strlen(rule_params);

    //trigger_data_t *data = (trigger_data_t *)malloc(sizeof(trigger_data_t) + (rule_param_size + 1) * sizeof(char));
    trigger_data_t *data = (trigger_data_t *)trigger_data;
    memset(data, 0, sizeof(trigger_data_t) + (rule_param_size + 1) * sizeof(char));
    memcpy(&data->trigger_name, trigger_name, trigger_name_sz);
    data->trigger_name_size = trigger_name_sz;
    data->nonce = n;
    memcpy(&data->rule_params, rule_params, rule_param_size);

	size_t data_size;
    void *ret = get_trigger_data(data, &data_size);

    // Freeing data
    //free(data);

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
        void*t_data = fetch_trigger_data(i, trigger_url, url_length, rule_params[i], &trigger_data_sz, &nonce);
        printf("[fetch_and_validate_data] Fetched trigger data\n");

        trig_data[i] = (char *)decrypt_trigger_data(t_data, trigger_data_sz, (unsigned char *)&rule->key_trigger[i], 32);
        if (trig_data[i] == NULL) {
            printf("[fetch_and_validate_data] Failed to decrypt trigger data\n");
            return 0;
        }

        //free(t_data);

        printf("[fetch_and_validate_data] Decrypted trigger data\n");
        printf(trig_data[i]);
        printf("\n");

        int isvalid = init_trigger_data(i, trig_data[i], nonce, trigger_url, url_length, rule_params_unescaped[i], TRIGGER_TIMEOUT);

        //free(trig_data[i]);
        if (isvalid < 0) {

            printf("[fetch_and_validate_data] Validation failed!\n");
            snprintf(printbuf, 200, "[fetch_and_validate_data] validate_and_init_trigger_data return code: %d\n", isvalid);
            printf(printbuf);
            //printf("[fetch_and_validate_data] Invalid Trigger data for trigger %d\n", i);
            return 0;
        }

        printf("[fetch_and_validate_data] After validate_and_init_trigger_data data\n");
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
            
            int return_code = send_action_data(action_dt);
            if (return_code != 0) {
                printf("[send_data] Error sending action data %d\n", i);
            } else {
                printf("[send_data] Sent action data: %d\n", i);
            }

            //free(action_data);
            //free(action_dt);
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

            printf("[event_loop] Validation failed!\n");
            i++;
            continue;
        }

        printf("[event_loop] Data Validation passed!\n");

        run_rule();

        printf("[event_loop] Finished running rule\n");
        send_data(rule);
        
        i++;

    }

    printf("[event_loop] Finished event_loop\n");
}