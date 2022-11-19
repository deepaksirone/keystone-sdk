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
#include "keystore_defs.h"
#include "app/syscall.h"

#define MAXSZ 65535
#define MAX_COMMAND_SIZE 65535
#define PRINT_BUF_SIZE 1000
#define MAX_REQUEST_SIZE 65535
#define USER_RECORD_SIZE MAXSZ
#define SYSCALL_GENRAND_WORD 1006

char command_buf[MAX_COMMAND_SIZE];
byte user_record[USER_RECORD_SIZE];
char printf_buf[PRINT_BUF_SIZE];

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
    char *res = (char *) malloc(IV_SIZE* sizeof(char));
    int len_passwd = strlen(password);
    for (int i = 0, j = 0; i < IV_SIZE; i++) {
        res[i] = password[j % len_passwd];
        j++;
    }

    return res;
}

char *gen_iv_sm() {
    char *res = (char *) malloc(IV_SIZE * sizeof(char));
    for(int i = 0; i < (IV_SIZE / sizeof(uintptr_t)); i++) {
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
            if (i > 0 && (i % 16) == 0) {
                printf("\n");
            }
        }
        printf("\n/*-------------------- CLIENT READING -----------------*/\n");
    }
    
    if (ret == 0) {
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    }

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
            if (i > 0 && (i % 16) == 0) {
                printf("\n");
            }
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



uint64_t read_buffer(WOLFSSL *sslcli, void *buffer, size_t sz)
{
	uint64_t pos = 0;
	int64_t ret = wolfSSL_read(sslcli, buffer, sz);
    int error;

	while (ret > 0) {
		pos += ret;
        //printf("Current pos: %ld, sz - pos : %lu", pos, sz - pos);
        if (pos == sz) {
            return pos;
        }
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
    uint64_t pos = 0;
    int64_t ret = wolfSSL_write(sslserv, buffer, sz);
    int error;

    while (ret > 0) {
        pos += ret;
        if (pos == sz) {
            return pos;
        }
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
    uint64_t size;
    size = strlen(response) + 1;
    write_buffer(sslServ, &size, sizeof(uint64_t));
    write_buffer(sslServ, response, strlen(response) + 1);
    //wolfSSL_shutdown(sslServ);
}

void success_response(char *response, WOLFSSL *sslServ) {
    uint64_t size;
    size = strlen(response) + 1;
    write_buffer(sslServ, &size, sizeof(uint64_t));
    write_buffer(sslServ, response, strlen(response) + 1);
    //wolfSSL_shutdown(sslServ);
}

void register_rule(char *username, char *password, uintptr_t rule_id, char *rule_bin_hash, char *sm_bin_hash,
                    char key_triggers[20][32], int32_t num_triggers, char key_actions[20][32], int32_t num_actions,
                    char *key_rule, WOLFSSL *sslServ) {
    
    //TODO: Pass a struct into this function
    //printf("[register_rule] username: %s, password: %s, rule_id: %lu\n", username, password, rule_id);
    snprintf(printf_buf, PRINT_BUF_SIZE, "[register_rule] username: %s, password: %s, rule_id: %lu, num_triggers: %d, num_actions: %d\n", username, password, rule_id, num_triggers, num_actions);
    ocall_print_buffer(printf_buf);

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

    printf("[register_rule] Decrypted user record: uid: %lu, username: %s, password: %s\n", usr.uid, usr.username, usr.password);
    // Redundant Check for Password here
    if (strncmp(usr.password, password, 20) != 0) {
        return error_response("[Reg Rule] Invalid Password 2", sslServ);
    }

    // User provided correct credentials
    uintptr_t rid = rule_id;

    // Check if rule exists
    int rule_exists = ocall_get_rule_record(usr.uid, rid, NULL);
    if (rule_exists) {
        return error_response("[Reg Rule] Rule Exists", sslServ);
    }

    ocall_print_buffer("[register_rule] rule_exists: False\n");

    struct keystore_rule rule;
    // Initialize Rule
    memset((void *)&rule, 0, sizeof(rule));

    ocall_print_buffer("[register_rule] After rule memset 0\n");

    rule.rid = rid;
    rule.num_actions = num_actions;
    rule.num_triggers = num_triggers;

    //snprintf(print_buf, PRINT_BUF_SIZE, "[register_rule] username: %s, password: %s, rule_id: %lu\n", username, password, rule_id);

    for(int i = 0; i < num_triggers; i++) {
        memcpy(rule.key_trigger[i], key_triggers[i], TRIGGER_KEY_LEN);
    }

    for(int i = 0; i < num_actions; i++) {
        memcpy(rule.key_action[i], key_actions[i], ACTION_KEY_LEN);
    }

    memcpy(rule.rule_bin_hash, rule_bin_hash, RULE_BIN_HASH_LEN);
    memcpy(rule.sm_bin_hash, sm_bin_hash, SM_BIN_HASH_LEN);

    ocall_print_buffer("[register_rule] Finished copying rule entries\n");
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

    ocall_print_buffer("[register_rule] Derived sealing key\n");

    wc_AesInit(&enc_r, NULL, INVALID_DEVID);

    if ((ret = wc_AesGcmSetKey(&enc_r, key_buffer_rule.key, 32)) != 0) {
        return error_response("[Reg Rule] Internal Error 2", sslServ);
    }

    char hash_concat[64 + 64];
    memset(hash_concat, 0, 128);
    memcpy(hash_concat, rule_bin_hash, 64);
    memcpy(&hash_concat[64], sm_bin_hash, 64);

    if ((ret = wc_AesGcmEncrypt(&enc_r, (byte *)&enc_rule.rule, (byte *)&rule, sizeof(struct keystore_rule), 
                (byte *)iv1, 16, (byte *)&enc_rule.auth_tag, sizeof(enc_rule.auth_tag), (byte *)hash_concat, 128)) != 0) {
        return error_response("[Reg Rule] Internal Error 3", sslServ);
    }

    ocall_print_buffer("[register_rule] Finished Rule Encryption\n");
    
    int r = ocall_set_rule_record(usr.uid, rid, enc_rule);
    if (r) {
        return error_response("[Reg Rule] Error setting record", sslServ);
    }

    return success_response("[Reg Rule] Success", sslServ);

}

void process_dec_request(runtime_request_t *runtime_req, WOLFSSL *sslServ) 
{

    // Get the rule
    struct enc_keystore_rule enc_rule;
    struct edge_data msg;
    int ret = ocall_get_rule_record(runtime_req->user_id, runtime_req->rule_id, &msg);
    if (!ret) {
        return error_response("[proc dec request] Rule does not exist", sslServ);
    }

    copy_from_shared(&enc_rule, msg.offset, msg.size);

    byte *rule_bin_hash = runtime_req->report.enclave.hash;
    byte *sm_bin_hash = runtime_req->report.sm.hash;

    char uid_rid[sizeof(runtime_req->user_id) + sizeof(runtime_req->rule_id) + 1];
    memset(uid_rid, 0, sizeof(uid_rid));
    memcpy(uid_rid, &runtime_req->user_id, sizeof(runtime_req->user_id));
    memcpy(&uid_rid[sizeof(runtime_req->user_id)], &runtime_req->rule_id, sizeof(runtime_req->rule_id));

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
    memcpy(&hash_concat[64], sm_bin_hash, 64);

    if ((ret = wc_AesGcmDecrypt(&enc, (byte *)&rule, (byte *)&enc_rule.rule, sizeof(struct keystore_rule), (byte *)&enc_rule.iv, 16, 
            (byte *)&enc_rule.auth_tag, 16, (byte *)hash_concat, 128)) != 0) {
        return error_response("[Dec Req] Invalid Decryption", sslServ);
    }

    //TODO: Verify report here
    if ((memcmp(rule_bin_hash, rule.rule_bin_hash, RULE_BIN_HASH_LEN) == 0) && 
        (memcmp(sm_bin_hash, rule.sm_bin_hash, SM_BIN_HASH_LEN) == 0)) {
        //TODO: Include the size of the transmission
        size_t sz = sizeof(struct keystore_rule);
        write_buffer(sslServ, &sz, sizeof(size_t));
        write_buffer(sslServ, &rule, sizeof(struct keystore_rule));
    }

    //wolfSSL_shutdown(sslServ);
}

void process_invalid_cmd(WOLFSSL *sslServ)
{

}


void register_user(char *username, char *password, uintptr_t *user_id, WOLFSSL *sslServ)
{
    int userExists = ocall_get_user_record(username, NULL);
    if (userExists) {
        return error_response("User Exists", sslServ);
    }

    struct keystore_user usr;
    //TODO: TEST ONLY
    //uintptr_t uid = rand_gen_keystone();
    uintptr_t uid = 0;
    usr.uid = uid;
    *user_id = uid;

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

    char buffer[50];
    snprintf(buffer, 50, "REGUSR - Success. UID: %lu", uid);
    return success_response(buffer, sslServ);

}

/// Commands are:
/// REGUSR <username> <password>
/// REGRUL <username> <password> <rule id> <rule binary hash in hex> <runtime binary hash in hex> <n> <m> <K_t1 in hex>..<K_tn> <K_a1 in hex>..<K_an> <K_rule in hex>
/// REQRUL <runtime_request in binary>
void process_request(request_t* request, int cmd_size, WOLFSSL *sslServ) {
    char *username;
    char *password;
    char *key_rule;
    switch (request->type) {
        case REGUSER_REQUEST:
            printf("Processing reg_user request\n");
            uintptr_t user_id;
            reguser_request_t *reguser_req = (reguser_request_t *)&(request->data);
            username = reguser_req->username;
            if (!username || strlen(username) >= 20) {
                return error_response("Invalid Username", sslServ);
            }

            password = reguser_req->password;
            if (!password || strlen(password) >= 20) {
                return error_response("Invalid Password", sslServ);
            }
            
            register_user(username, password, &user_id, sslServ);

            //return error_response("Successful registration, UID: %lu\n", sslServ);
            break;
        case REGRULE_REQUEST:
            printf("Processing reg_rule request\n");
            regrule_request_t *regrule_req = (regrule_request_t *)&(request->data);
            username = regrule_req->username;
            if (!username) {
                return error_response("[regrule] Invalid Input", sslServ);
            }

            password = regrule_req->password;
            if (!password) {
                return error_response("[regrule] Invalid Input", sslServ);
            }

            uintptr_t rule_id = regrule_req->rid;

            char *rule_bin_hash = regrule_req->rule_bin_hash;
            if (!rule_bin_hash) {
                return error_response("[regrule] Invalid Input", sslServ);
            }

            char *sm_bin_hash = regrule_req->sm_bin_hash;
            if (!sm_bin_hash) {
                return error_response("[regrule] Invalid Input", sslServ);
            }

            int32_t num_triggers = regrule_req->num_triggers;
            int32_t num_actions = regrule_req->num_actions;

            //char **trigger_keys = (char **)regrule_req->key_trigger;
            //char **action_keys = (char **) regrule_req->key_action;

            key_rule = regrule_req->key_rule;
            if (!key_rule) {
                return error_response("[regrule] Invalid Input", sslServ);
            }

            register_rule(username, 
                      password, 
                      rule_id, 
                      rule_bin_hash, 
                      sm_bin_hash, 
                      regrule_req->key_trigger, num_triggers, 
                      regrule_req->key_action, num_actions, key_rule, sslServ);
            break;
        case RUNTIME_REQUEST:
            runtime_request_t *runtime_req = (runtime_request_t *)&(request->data);
            process_dec_request(runtime_req, sslServ);
            break;
        default:
            return error_response("[regrule] Invalid request type", sslServ);
    }
}


int start_request_server(char *bind_addr, int bind_port, byte *cert_buf, 
            int cert_size, byte *pvt_key, int pvtkey_size) {
    printf("Starting Keystore Server\n");
    
    int bind_addr_len = strlen(bind_addr);
    connection_data_t *data = malloc(sizeof(connection_data_t) + bind_addr_len * sizeof(unsigned char));
    int *clientfd = malloc(sizeof(int));

    data->portnumber = bind_port;
    memcpy(data->hostname, bind_addr, bind_addr_len);
    int servSocket = ocall_init_serv_connection(data, sizeof(connection_data_t) + bind_addr_len * sizeof(unsigned char));

    

    printf("ServSocket: %d\n", servSocket);

    while (1) {

        WOLFSSL_CTX *ctxServ = NULL;
        WOLFSSL *sslServ = Server(ctxServ, "let-wolfssl-choose", 0, cert_buf, cert_size, pvt_key, pvtkey_size);
        //TODO: Need to allocate private fd on the heap if we want to parallelize
        *clientfd = ocall_wait_for_conn(servSocket);
        printf("[Keystore] Serving User Connection\n");
        printf("[Keystore] ClientSocket: %d\n", *clientfd);

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
        ret = read_buffer(sslServ, command_buf, sizeof(uint64_t));
        uint64_t req_size = *(uint64_t *)(command_buf);

        printf("The request size: %lu\n", req_size);
        
        if (req_size != sizeof(request_t)) {
            error_response("Invalid Request Size", sslServ);
            return -1;
        }
        
        ret = read_buffer(sslServ, command_buf, req_size);
        command_buf[ret] = 0;

        printf("After reading request_t: %d\n", ret);

        process_request((request_t *)command_buf, ret, sslServ);
        
        wolfSSL_shutdown(sslServ);
        wolfSSL_free(sslServ);
        ocall_terminate_conn(*clientfd);

    }

    return 0;
}


int main(int argc, char** argv)
{

    //WOLFSSL* sslServ;
    //WOLFSSL_CTX* ctxServ = NULL;
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

    //sslServ = Server(ctxServ, "let-wolfssl-choose", 0, cert_buf, cert_size, pvt_key, pvtkey_size);
    start_request_server("localhost", KEYSTORE_PORT, cert_buf, cert_size, pvt_key, pvtkey_size);

    printf("Cleaning up...\n");
    return 0;

    //wolfSSL_shutdown(sslServ);
    /*
    wolfSSL_free(sslCli);
    wolfSSL_CTX_free(ctxCli);
    wolfSSL_Cleanup();*/

    /* close the streams so client can reset file contents */
}