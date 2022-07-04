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
#include <wolfssl/wolfcrypt/aes.h>
#include "encl_message.h"
#include "edge_wrapper.h"
#include "keystore_cert.h"
#include "keystore_user.h"
#include "keystore_rule.h"
#include "keystore_report.h"
#include "keystore_request.h"
#include "app/syscall.h"

#define MAXSZ 65535
#define MAX_COMMAND_SIZE 65535
#define MAX_REQUEST_SIZE 65535
#define USER_RECORD_SIZE MAXSZ
#define SYSCALL_GENRAND_WORD 1006

char command_buf[MAX_COMMAND_SIZE];
byte user_record[USER_RECORD_SIZE];

int strncmp(const char *s1, const char *s2, size_t n);
int copy_from_shared(void* dst, uintptr_t offset, size_t data_len);
int CbIOSend(WOLFSSL *ssl, char *buf, int sz, void *ctx);
int CbIORecv(WOLFSSL *ssl, char *buf, int sz, void *ctx);
WOLFSSL* Client(WOLFSSL_CTX* ctx, char* suite, int setSuite, int doVerify);
WOLFSSL_METHOD* SetMethodClient(int i);


struct WOLFSSL_SOCKADDR {
    unsigned int sz;
    void*        sa;
};

static int fpSendRecv;
static int verboseFlag = 0;

static uintptr_t rand_gen_keystone(void)
{
    uintptr_t ret = SYSCALL_0(SYSCALL_GENRAND_WORD);
    return ret;
}

char *generate_iv(char *password) {
    char *res = (char *) malloc(16 * sizeof(char));
    int len_passwd = strlen(password);
    for (int i = 0, j = 0; i < 16; i++) {
        res[i] = password[j % len_passwd];
        j++;
    }

    return res;
}

char *gen_iv_sm() {
    char *res = (char *) malloc(16 * sizeof(char));
    for(int i = 0; i < (16 / sizeof(uintptr_t)); i++) {
        uintptr_t rand = rand_gen_keystone();
        memcpy(res + i * sizeof(uintptr_t), &rand, sizeof(uintptr_t));
    }

    return res;
}


/*--------------------------------------------------------------*/
/* Function implementations */
/*--------------------------------------------------------------*/
int CbIORecv(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    (void) ssl; /* will not need ssl context, just using the file system */
 /* will not need ctx, we're just using the file system */
    int ret = -1;
    int i;

	network_recv_request_t req;
	req.fd = *((int *)ctx);
	req.req_size = sz;

    struct edge_data msg;
    while (ret < 0) {
        ret = (int) ocall_recv_buffer_fd(&req, sizeof(network_recv_request_t), &msg);
		if (ret > 0 && msg.size <= sz) 
			copy_from_shared(buf, msg.offset, msg.size);
	}
	
    if (verboseFlag == 1) {
        printf("/*-------------------- CLIENT READING -----------------*/\n");
        for (i = 0; i < ret; i++) {
            printf("%02x ", (unsigned char)buf[i]);
            if (i > 0 && (i % 16) == 0)
                printf("\n");
        }
        printf("\n/*-------------------- CLIENT READING -----------------*/\n");
    }
    
    if (ret == 0) return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    return ret;
}

int CbIOSend(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    (void) ssl; /* will not need ssl context, just using the file system */
     /* will not need ctx, we're just using the file system */
    int ret;
    int i;

	// Naive implementation with copying, can optimize by sending just the user pointer
	network_send_data_t *data = malloc(sizeof(network_send_data_t) + sz * sizeof(char));
	data->fd = *((int *)ctx);
	data->data_len = sz;

	memcpy(data->data, buf, sz);

    ret = (int) ocall_send_buffer_fd(data, sizeof(network_send_data_t) + sz * sizeof(char));
    if (verboseFlag == 1) {
        printf("/*-------------------- CLIENT SENDING -----------------*/\n");
        for (i = 0; i < sz; i++) {
            printf("%02x ", (unsigned char) buf[i]);
            if (i > 0 && (i % 16) == 0)
                printf("\n");
        }
        printf("\n/*-------------------- CLIENT SENDING -----------------*/\n");
    } else {
        (void) i;
    }/* Definition of AT_* constants */
    
    free(data);
    return ret;
}


WOLFSSL* Server(WOLFSSL_CTX* ctx, char* suite, int setSuite, byte *certBuf, 
        int cert_buf_sz, byte* pvtKeyBuf, int pvt_key_buf)
{
    WOLFSSL* ssl;
    int ret = -1;

    if ((ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method())) == NULL) {
        printf("Error in setting server ctx\n");
        return NULL;
    }

#ifndef NO_PSK
    wolfSSL_CTX_SetTmpDH_buffer(ctx, dh_key_der_1024, sizeof_dh_key_der_1024,
                                                        SSL_FILETYPE_ASN1);
#endif

    if (wolfSSL_CTX_use_certificate_buffer(ctx, certBuf, cert_buf_sz, SSL_FILETYPE_ASN1) != SSL_SUCCESS) {
        printf("Error loading certificate from buffer\n");
        return NULL;
    }

    if (wolfSSL_CTX_use_PrivateKey_buffer(ctx, pvtKeyBuf, pvt_key_buf, SSL_FILETYPE_ASN1) != SSL_SUCCESS) {
        printf("Error loading server pvt key buffer\n");
        return NULL;
    }

    if (setSuite == 1) {
        if (( ret = wolfSSL_CTX_set_cipher_list(ctx, suite)) != SSL_SUCCESS) {
            printf("ret = %d\n", ret);
            printf("Error :can't set cipher\n");
            wolfSSL_CTX_free(ctx);
            return NULL;
        }
    } else {
        (void) suite;
    }

    wolfSSL_SetIORecv(ctx, CbIORecv);
    wolfSSL_SetIOSend(ctx, CbIOSend);

    if ((ssl = wolfSSL_new(ctx)) == NULL) {
        printf("issue when creating ssl\n");
        wolfSSL_CTX_free(ctx);
        return NULL;
    }

    wolfSSL_set_fd(ssl, fpSendRecv);
    return ssl;
}



int64_t read_buffer(WOLFSSL *sslcli, void *buffer, size_t sz)
{
	int64_t pos = 0;
	int64_t ret = wolfSSL_read(sslcli, buffer, sz);
    int error;

	while (ret > 0) {
		pos += ret;
		ret = wolfSSL_read(sslcli, (void *) (buffer + pos), sz - pos);
	}

    error = wolfSSL_get_error(sslcli, 0);
    if (ret < 0) {
        if (error != SSL_ERROR_WANT_READ &&
                error != SSL_ERROR_WANT_WRITE) {
                printf("server read failed\n");
        }
    }

	return pos;
}

int64_t write_buffer(WOLFSSL *sslserv, void *buffer, size_t sz)
{
    int64_t pos = 0;
    int64_t ret = wolfSSL_write(sslserv, buffer, sz);
    int error;

    while (ret > 0) {
        pos += ret;
        ret = wolfSSL_write(sslserv, (void *) (buffer + pos), sz - pos);
    }

    error = wolfSSL_get_error(sslserv, 0);
    if (ret < 0) {
        if (error != SSL_ERROR_WANT_READ &&
                error != SSL_ERROR_WANT_WRITE) {
                printf("server write failed\n");
        }
    }

    return pos;
}

void error_response(char *response, WOLFSSL *sslServ) {
    write_buffer(sslServ, response, strlen(response));
    wolfSSL_shutdown(sslServ);
}

void register_rule(char *username, char *password, char *rule_id, char *rule_bin_hash, char *runtime_bin_hash,
                    char **key_triggers, int num_triggers, char **key_actions, int num_actions,
                    char *key_rule, WOLFSSL *sslServ) {
    
    //TODO: Pass a struct into this function
    struct enc_keystore_user e_usr;
    struct edge_data msg;
    int user_exists = ocall_get_user_record(username, &msg);
    if (!user_exists) {
        return error_response("[Reg Rule] User does not exist", sslServ);
    }

    copy_from_shared(&e_usr, msg.offset, msg.size);

    struct sealing_key key_buffer;
    int ret = get_sealing_key((void *)&key_buffer, sizeof(key_buffer), (void *)username, strlen(username));
    if (ret != 0) {
        return error_response("[Reg Rule] Internal Error 1", sslServ);
    }

    Aes enc;
    wc_AesInit(&enc, NULL, INVALID_DEVID);

    if ((ret = wc_AesGcmSetKey(&enc, key_buffer.key, 32)) != 0) {
        return error_response("[Reg Rule] Internal Error 2", sslServ);
    }

    struct keystore_user usr;
    char *iv = generate_iv(password);
    if ((ret = wc_AesGcmDecrypt(&enc, (byte *)&usr, (byte *)&e_usr.ciphertext, sizeof(struct keystore_user), (byte *)iv, 16, 
            (byte *)&e_usr.auth_tag, 16, (byte *)password, strlen(password))) != 0) {
        return error_response("[Reg Rule] Invalid Password 1", sslServ);
    }

    // Redundant Check for Password here
    if (strncmp(usr.password, password, 20) != 0) {
        return error_response("[Reg Rule] Invalid Password 2", sslServ);
    }

    // User provided correct credentials
    uintptr_t rid = atoll(rule_id);

    // Check if rule exists
    int rule_exists = ocall_get_rule_record(usr.uid, rid, NULL);
    if (rule_exists) {
        return error_response("[Reg Rule] Rule Exists", sslServ);
    }

    struct keystore_rule rule;
    // Initialize Rule
    memset((void *)&rule, 0, sizeof(rule));

    rule.rid = rid;
    rule.num_actions = num_actions;
    rule.num_triggers = num_triggers;

    for(int i = 0; i < num_triggers; i++) {
        strncpy(rule.key_trigger[i], key_triggers[i], TRIGGER_KEY_LEN);
    }

    for(int i = 0; i < num_actions; i++) {
        strncpy(rule.key_action[i], key_actions[i], ACTION_KEY_LEN);
    }

    memcpy(rule.rule_bin_hash, rule_bin_hash, RULE_BIN_HASH_LEN);
    memcpy(rule.runtime_bin_hash, runtime_bin_hash, RUNTIME_BIN_HASH_LEN);

    //Encrypt rule
    Aes enc_r;
    struct enc_keystore_rule enc_rule;

    char *iv1 = gen_iv_sm();
    memcpy(enc_rule.iv, iv1, 16);

    char uid_rid[sizeof(usr.uid) + sizeof(rid) + 1];
    memset(uid_rid, 0, sizeof(uid_rid));
    memcpy(uid_rid, &usr.uid, sizeof(rid));
    memcpy(&uid_rid[sizeof(usr.uid)], &rid, sizeof(rid));

    struct sealing_key key_buffer_rule;
    ret = get_sealing_key((void *)&key_buffer_rule, sizeof(struct sealing_key), (void *)uid_rid, sizeof(uid_rid));
    if (ret != 0) {
        return error_response("[Reg Rule] Internal Error 1", sslServ);
    }

    wc_AesInit(&enc_r, NULL, INVALID_DEVID);

    if ((ret = wc_AesGcmSetKey(&enc_r, key_buffer_rule.key, 32)) != 0) {
        return error_response("[Reg Rule] Internal Error 2", sslServ);
    }

    char hash_concat[64 + 64];
    memset(hash_concat, 0, 128);
    memcpy(hash_concat, rule_bin_hash, 64);
    memcpy(&hash_concat[64], runtime_bin_hash, 64);

    if ((ret = wc_AesGcmEncrypt(&enc_r, (byte *)&enc_rule.rule, (byte *)&rule, sizeof(struct keystore_rule), 
                (byte *)iv1, 16, (byte *)&enc_rule.auth_tag, sizeof(enc_rule.auth_tag), (byte *)hash_concat, 128)) != 0) {
        return error_response("[Reg Rule] Internal Error 3", sslServ);
    }
    
    int r = ocall_set_rule_record(usr.uid, rid, enc_rule);
    if (r) {
        return error_response("[Reg Rule] Error setting record", sslServ);
    }

    return error_response("[Reg Rule] Success", sslServ);

}

void process_dec_request(char *command_buf, WOLFSSL *sslServ) 
{
    runtime_request_t rpt;
    memcpy(&rpt, command_buf, sizeof(runtime_request_t));

    // Get the rule
    struct enc_keystore_rule enc_rule;
    struct edge_data msg;
    int ret = ocall_get_rule_record(rpt.user_id, rpt.rule_id, &msg);
    if (!ret) {
        return error_response("[proc dec request] Rule does not exist", sslServ);
    }

    copy_from_shared(&enc_rule, msg.offset, msg.size);

    byte *rule_bin_hash = rpt.report.enclave.hash;
    byte *runtime_bin_hash = rpt.report.sm.hash;

    char uid_rid[sizeof(rpt.user_id) + sizeof(rpt.rule_id) + 1];
    memset(uid_rid, 0, sizeof(uid_rid));
    memcpy(uid_rid, &rpt.user_id, sizeof(rpt.user_id));
    memcpy(&uid_rid[sizeof(rpt.user_id)], &rpt.rule_id, sizeof(rpt.rule_id));

    struct sealing_key key_buffer;
    ret = get_sealing_key((void *)&key_buffer, sizeof(key_buffer), (void *)uid_rid, sizeof(uid_rid));

    // Decrypt encrypted rule
    struct keystore_rule rule;
    Aes enc;
    wc_AesInit(&enc, NULL, INVALID_DEVID);

    if ((ret = wc_AesGcmSetKey(&enc, key_buffer.key, 32)) != 0) {
        return error_response("Internal Error 2", sslServ);
    }

    char hash_concat[64 + 64];
    memset(hash_concat, 0, 128);
    memcpy(hash_concat, rule_bin_hash, 64);
    memcpy(&hash_concat[64], runtime_bin_hash, 64);

    if ((ret = wc_AesGcmDecrypt(&enc, (byte *)&rule, (byte *)&enc_rule.rule, sizeof(struct keystore_rule), (byte *)&enc_rule.iv, 16, 
            (byte *)&enc_rule.auth_tag, 16, (byte *)hash_concat, 128)) != 0) {
        return error_response("[Dec Req] Invalid Decryption", sslServ);
    }

    //TODO: Verify report here
    if ((memcmp(rule_bin_hash, rule.rule_bin_hash, RULE_BIN_HASH_LEN) == 0) && 
        (memcmp(runtime_bin_hash, rule.runtime_bin_hash, RUNTIME_BIN_HASH_LEN) == 0)) {
        //TODO: Include the size of the transmission
        size_t sz = sizeof(struct keystore_rule);
        write_buffer(sslServ, &sz, sizeof(size_t));
        write_buffer(sslServ, &rule, sizeof(struct keystore_rule));
    }

    wolfSSL_shutdown(sslServ);
}

void process_invalid_cmd(WOLFSSL *sslServ)
{

}


void register_user(char *username, char *password, char *user_id, WOLFSSL *sslServ)
{
    int userExists = ocall_get_user_record(username, NULL);
    if (userExists) {
        return error_response("User Exists", sslServ);
    }

    struct keystore_user usr;
    uintptr_t uid = rand_gen_keystone();
    usr.uid = uid;
    strncpy(usr.username, username, 20);
    strncpy(usr.password, password, 20);

    struct sealing_key key_buffer;
    int ret = get_sealing_key((void *)&key_buffer, sizeof(key_buffer), (void *)username, strlen(username));
    if (ret != 0) {
        return error_response("Internal Error 1", sslServ);
    }

    Aes enc;
    wc_AesInit(&enc, NULL, INVALID_DEVID);

    if ((ret = wc_AesGcmSetKey(&enc, key_buffer.key, 32)) != 0) {
        return error_response("Internal Error 2", sslServ);
    }

    // Repeat Password till 16 bytes to generate IV
    char *iv = generate_iv(password);
    struct enc_keystore_user enc_usr;

    if ((ret = wc_AesGcmEncrypt(&enc, (byte *)enc_usr.ciphertext, (byte *)&usr, sizeof(struct keystore_user), 
                (byte *)iv, 16, (byte *)&enc_usr.auth_tag, sizeof(enc_usr.auth_tag), (byte *)password, strlen(password))) != 0) {
        return error_response("Internal Error 3", sslServ);
    }

    ret = ocall_set_user_record(username, enc_usr);

    if (ret != 0) {
        return error_response("Internal Error 4", sslServ);
    }

    return error_response("REGUSR - Success", sslServ);

}

/// Commands are:
/// REGUSR <username> <password>
/// REGRUL <username> <password> <rule id> <rule binary hash in hex> <runtime binary hash in hex> <n> <m> <K_t1 in hex>..<K_tn> <K_a1 in hex>..<K_an> <K_rule in hex>
/// REQRUL <runtime_request in binary>
void process_request(char *command_buf, int cmd_size, WOLFSSL *sslServ) {
    if (cmd_size < 6) return;
    if (strncmp(command_buf, "REGUSR", (size_t)6) == 0) {
        char user_id[20];

        char *username = strtok(&command_buf[5], " ");
        if (!username || strlen(username) >= 20) return error_response("Invalid Username", sslServ); 

        char *password = strtok(NULL, " ");
        if (!password || strlen(password) >= 20) return error_response("Invalid Password", sslServ);
        
        register_user(username, password, user_id, sslServ);
    } else if (strncmp(command_buf, "REGRUL", (size_t)6) == 0) {
        char *username = strtok(&command_buf[5], " ");
        if (!username) return error_response("[regrule] Invalid Input", sslServ);

        char *password = strtok(NULL, " ");
        if (!password) return error_response("[regrule] Invalid Input", sslServ);

        char *rule_id = strtok(NULL, " ");
        if (!rule_id) return error_response("[regrule] Invalid Input", sslServ);

        char *rule_bin_hash = strtok(NULL, " ");
        if (!rule_bin_hash) return error_response("[regrule] Invalid Input", sslServ);

        char *runtime_bin_hash = strtok(NULL, " ");
        if (!runtime_bin_hash) return error_response("[regrule] Invalid Input", sslServ);

        char *num_triggers = strtok(NULL, " ");
        if (!num_triggers) return error_response("[regrule] Invalid Input", sslServ);

        int nt = atoi(num_triggers);
        char **trigger_keys = (char **) malloc(nt * sizeof(char **));

        char *num_actions = strtok(NULL, " ");
        if (!num_actions) return error_response("[regrule] Invalid Input", sslServ);;

        int na = atoi(num_actions);
        char **action_keys = (char **) malloc(na * sizeof(char **));

        for (int i = 0; i < nt; i++) {
                char *key_trigger = strtok(NULL, " ");
                if (!key_trigger) return error_response("[regrule] Invalid Input", sslServ);

                trigger_keys[i] = key_trigger;
        }

        //char *key_trigger2 = strtok(NULL, " ");
        //if (!key_trigger2) return -1;

        for (int i = 0; i < na; i++) {
                char *key_action = strtok(NULL, " ");
                if (!key_action) return error_response("[regrule] Invalid Input", sslServ);

                action_keys[i] = key_action;
        }

        char *key_rule = strtok(NULL, " ");
        if (!key_rule) return error_response("[regrule] Invalid Input", sslServ);

        register_rule(username, 
                      password, 
                      rule_id, 
                      rule_bin_hash, 
                      runtime_bin_hash, 
                      trigger_keys, nt, 
                      action_keys, na, key_rule, sslServ);
    } else if (strncmp(command_buf, "REQRUL", (size_t)6) == 0) {
        process_dec_request(command_buf, sslServ);
    } else {
        process_invalid_cmd(sslServ);
    }
}


int start_request_server(WOLFSSL *sslServ, char *bind_addr, int bind_port) {
    printf("Starting Keystore Server\n");
    
    int bind_addr_len = strlen(bind_addr);
    connection_data_t *data = malloc(sizeof(connection_data_t) + bind_addr_len * sizeof(unsigned char));
    int *clientfd = malloc(sizeof(int));

    data->portnumber = bind_port;
    memcpy(data->hostname, bind_addr, bind_addr_len);
    int servSocket = ocall_init_serv_connection(data, sizeof(connection_data_t) + bind_addr_len * sizeof(unsigned char));

    printf("ServSocket: %d\n", servSocket);

    while (1) {

        //TODO: Need to allocate private fd on the heap if we want to parallelize
        *clientfd = ocall_wait_for_conn(servSocket);

        printf("ClientSocket: %d\n", *clientfd);

        wolfSSL_SetIOReadCtx(sslServ, (void *) clientfd);
        wolfSSL_SetIOWriteCtx(sslServ, (void *) clientfd);

        int ret = SSL_FAILURE;
        while (ret != SSL_SUCCESS) {
            int error;
            ret = wolfSSL_accept(sslServ);
            error = wolfSSL_get_error(sslServ, 0);
            if (ret != SSL_SUCCESS) {
                if (error != SSL_ERROR_WANT_READ &&
                    error != SSL_ERROR_WANT_WRITE) {
                    wolfSSL_free(sslServ);
                    printf("server ssl accept failed ret = %d error = %d wr = %d\n",
                                               ret, error, SSL_ERROR_WANT_READ);
                    return -1;
                                        
                }
            }
        }

        //TODO: Read size of the request first and then read the rest of the command
        ret = read_buffer(sslServ, command_buf, sizeof(size_t));
        size_t req_size = *(size_t *)(command_buf);

        ret = read_buffer(sslServ, command_buf, req_size);
        command_buf[ret] = 0;

        process_request(command_buf, ret, sslServ);
    }

    return 0;
}


int main(int argc, char** argv)
{

    WOLFSSL* sslServ;
    WOLFSSL_CTX* ctxServ = NULL;
    wolfSSL_Init();

    byte *cert_buf;
    int cert_size;

    byte *pvt_key;
    int pvtkey_size;

    if (generate_attested_cert_with_evidence(NULL, NULL, 0, &cert_buf, &cert_size, 
                &pvt_key, &pvtkey_size) < 0) {
        printf("Error in certificate generation\n");
        return -1;
    }

    sslServ = Server(ctxServ, "let-wolfssl-choose", 0, cert_buf, cert_size, pvt_key, pvtkey_size);
    start_request_server(sslServ, "localhost", 7777);

    printf("Cleaning up...\n");
    return 0;

    wolfSSL_shutdown(sslServ);
    /*
    wolfSSL_free(sslCli);
    wolfSSL_CTX_free(ctxCli);
    wolfSSL_Cleanup();*/

    /* close the streams so client can reset file contents */
}