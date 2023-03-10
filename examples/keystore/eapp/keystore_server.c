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
#include <wolfssl/wolfcrypt/asn.h>
#include "encl_message.h"
#include "edge_wrapper.h"
#include "keystore_conn.h"
#include "keystore_cert.h"
#include "keystore_user.h"
#include "keystore_rule.h"
#include "keystore_report.h"
#include "keystore_request.h"
#include "keystore_queue.h"
#include "keystore_defs.h"
#include "app/syscall.h"
#include "./ed25519/ed25519.h"
#include "./mtwister/mtwister.h"

#define MAXSZ 65535
#define MAX_COMMAND_SIZE 65535
#define PRINT_BUF_SIZE 1000
#define MAX_REQUEST_SIZE 65535
#define USER_RECORD_SIZE MAXSZ
#define SYSCALL_GENRAND_WORD 1006

char command_buf[MAX_COMMAND_SIZE];
byte reply[MAX_COMMAND_SIZE];
char printf_buf[PRINT_BUF_SIZE];
char pub_key[2048];


//int CbIOSend(WOLFSSL *ssl, char *buf, int sz, void *ctx);
//int CbIORecv(WOLFSSL *ssl, char *buf, int sz, void *ctx);
//WOLFSSL* Client(WOLFSSL_CTX* ctx, char* suite, int setSuite, int doVerify, byte *cert_buf, 
//int cert_size, byte *pvt_key, int pvtkey_size);
//WOLFSSL_METHOD* SetMethodClient(int i);

// Chain Replication Stuff
int has_attested_tls = 0;
static int64_t server_id = -1;
static char storage_key[STORAGE_KEY_SIZE];
static int storage_key_isinit = 0;

struct WOLFSSL_SOCKADDR {
    unsigned int sz;
    void*        sa;
};

//static int fpSendRecv;
static int fpFwd;
int verboseFlag = 0;
 
static uintptr_t rand_gen_keystone(void)
{
    uintptr_t ret = SYSCALL_0(SYSCALL_GENRAND_WORD);
    return ret;
}

static void generate_storage_key() {
    if (!storage_key_isinit) {
        uintptr_t seed = rand_gen_keystone();
        // Use the Mersenne Twister for keygen
        MTRand r = seedRand(seed);

        for (int i = 0; i < STORAGE_KEY_SIZE; i++) {
            unsigned long rand_pt = genRandLong(&r);
            byte rand_byte = rand_pt & 0xff;
            storage_key[i] = rand_byte;
        }

        storage_key_isinit = 1;
    }
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




static void forward_storage_key(byte *cert_buf, 
            int cert_size, byte *pvt_key, int pvtkey_size) {
    
    storage_key_request_t storage_req;
    memcpy(storage_req.storage_key, storage_key, STORAGE_KEY_SIZE);

    // Prepare the request struct
    request_t req;
    req.type = CHAIN_R_SET_STORAGE_KEY;
    req.data.storage_key_req = storage_req;

    char hostname[64];
    
    // The next host from the server
    int host_len = snprintf(hostname, 64, "keystone.tap-%ld", server_id + 1);

    connection_data_t *data = (connection_data_t *) malloc(sizeof(connection_data_t) + (host_len + 1) * sizeof(unsigned char));
    memset(data, 0, sizeof(connection_data_t) + (host_len + 1) * sizeof(unsigned char));
    data->portnumber = 7777;
    memcpy(data->hostname, hostname, host_len);
    fpFwd = ocall_init_connection(data, sizeof(connection_data_t) + (host_len + 1) * sizeof(unsigned char));

    if (fpFwd == CHAIN_R_END_OF_CHAIN) {
        return;
    }

    //TODO: Make this use fpFwdKey: done
    WOLFSSL *sslCli = Client(NULL, NULL, 0, 0, cert_buf, cert_size, pvt_key, pvtkey_size, &fpFwd);

    int ret = SSL_FAILURE;

    printf("Starting connection to fwd key\n");
    while (ret != SSL_SUCCESS) {
        int error;
        printf("Connecting..\n");
        /* client connect */
        ret |= wolfSSL_connect(sslCli);
        error = wolfSSL_get_error(sslCli, 0);
        if (ret != SSL_SUCCESS) {
            if (error != SSL_ERROR_WANT_READ &&
                error != SSL_ERROR_WANT_WRITE) {
                printf("client ssl connect failed, error: %d\n", error);
                fflush(stdout);
                goto cleanup;
            }
        }
        printf("Fwd key connection successful...\n");
    }

    send_message(sslCli, &req, sizeof(request_t));
    int sz = recv_message(sslCli, reply, sizeof(reply));

    printf("Reply: %s, Reply size: %d\n", reply, sz);
    
cleanup:
    wolfSSL_free(sslCli);
    ocall_terminate_conn(fpFwd);

}

static void forward_request(request_t *request, byte *cert_buf, 
            int cert_size, byte *pvt_key, int pvtkey_size) {
    char hostname[64];
    
    // The next host from the server
    int host_len = snprintf(hostname, 64, "keystone.tap-%ld", server_id + 1);

    connection_data_t *data = (connection_data_t *) malloc(sizeof(connection_data_t) + (host_len + 1) * sizeof(unsigned char));
    memset(data, 0, sizeof(connection_data_t) + (host_len + 1) * sizeof(unsigned char));
    data->portnumber = 7777;
    memcpy(data->hostname, hostname, host_len);
    fpFwd = ocall_init_connection(data, sizeof(connection_data_t) + (host_len + 1) * sizeof(unsigned char));

    if (fpFwd == CHAIN_R_END_OF_CHAIN) {
        return;
    }

    WOLFSSL *sslCli = Client(NULL, NULL, 0, 0, cert_buf, cert_size, pvt_key, pvtkey_size, &fpFwd);

    int ret = SSL_FAILURE;

    printf("Starting connection to fwd key\n");
    while (ret != SSL_SUCCESS) {
        int error;
        printf("Connecting..\n");
        /* client connect */
        ret |= wolfSSL_connect(sslCli);
        error = wolfSSL_get_error(sslCli, 0);
        if (ret != SSL_SUCCESS) {
            if (error != SSL_ERROR_WANT_READ &&
                error != SSL_ERROR_WANT_WRITE) {
                printf("client ssl connect failed, error: %d\n", error);
                fflush(stdout);
                goto cleanup;
            }
        }
        printf("Fwd key connection successful...\n");
    }

    send_message(sslCli, (void *)request, sizeof(request_t));
    int sz = recv_message(sslCli, reply, sizeof(reply));

    printf("Reply: %s, Reply size: %d\n", reply, sz);
    
cleanup:
    wolfSSL_free(sslCli);
    ocall_terminate_conn(fpFwd);
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

static void process_regrule_request(regrule_request_t *regrule_req, WOLFSSL *sslServ) {
    char *username;
    char *password;
    char *key_rule;
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
}

static void process_reguser_request(reguser_request_t *reguser_req, WOLFSSL *sslServ) {
    uintptr_t user_id;

    char *username = reguser_req->username;
    if (!username || strlen(username) >= 20) {
        return error_response("Invalid Username", sslServ);
    }

    char *password = reguser_req->password;
    if (!password || strlen(password) >= 20) {
        return error_response("Invalid Password", sslServ);
    }
            
    register_user(username, password, &user_id, sslServ);
}

/// Commands are:
/// REGUSR <username> <password>
/// REGRUL <username> <password> <rule id> <rule binary hash in hex> <runtime binary hash in hex> <n> <m> <K_t1 in hex>..<K_tn> <K_a1 in hex>..<K_an> <K_rule in hex>
/// REQRUL <runtime_request in binary>
void process_request(request_t* request, int cmd_size, WOLFSSL *sslServ, byte *cert_buf, 
            int cert_size, byte *pvt_key, int pvtkey_size) {
    switch (request->type) {
        case REGUSER_REQUEST:
            printf("Processing reg_user request\n");
            reguser_request_t *reguser_req = (reguser_request_t *)&(request->data);
            process_reguser_request(reguser_req, sslServ);

            //return error_response("Successful registration, UID: %lu\n", sslServ);
            break;
        case REGRULE_REQUEST:
            printf("Processing reg_rule request\n");
            regrule_request_t *regrule_req = (regrule_request_t *)&(request->data);
            process_regrule_request(regrule_req, sslServ);
            break;
        case RUNTIME_REQUEST:
            runtime_request_t *runtime_req = (runtime_request_t *)&(request->data);
            process_dec_request(runtime_req, sslServ);
            break;

        // Request Types for Chain Replication
        case CHAIN_R_ASGN_SVR_ID:
            server_id_request_t *serv_id_req = (server_id_request_t *)&(request->data);
            server_id = serv_id_req->server_id;
            // If I am the head, then generate and forward keys to the successor
            if (server_id == 1) {
                generate_storage_key();
                forward_storage_key(cert_buf, cert_size, pvt_key, pvtkey_size);
                //TODO: forward queue
                //forward_outstanding_queue(cert_buf, cert_size, pvt_key, pvtkey_size);
            }
            break;

        case CHAIN_R_SET_STORAGE_KEY:
            storage_key_request_t *strg_key_req = (storage_key_request_t *)&(request->data);
            if (has_attested_tls) {
                memcpy(storage_key, strg_key_req->storage_key, STORAGE_KEY_SIZE);
                forward_storage_key(cert_buf, cert_size, pvt_key, pvtkey_size);
            }
            break;
        
        case CHAIN_R_FORWARD_REQUEST_REGRULE: {
            if (has_attested_tls) {
                regrule_request_t *regrule_req = (regrule_request_t *)&(request->data);
                process_regrule_request(regrule_req, sslServ);
                //TODO: Add to the queue: and defer forwarding?
                forward_request(request, cert_buf, cert_size, pvt_key, pvtkey_size);
            } else {
                error_response("[fwd_rule] Does not have attested TLS", sslServ);
            }

            break;
        }

        case CHAIN_R_FORWARD_REQUEST_REGUSER: {
            if (has_attested_tls) {
                reguser_request_t *reguser_req = (reguser_request_t *)&(request->data);
                process_reguser_request(reguser_req, sslServ);
                forward_request(request, cert_buf, cert_size, pvt_key, pvtkey_size);
            } else {
                error_response("[fwd_rule] Does not have attested TLS", sslServ);
            }
        }
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
        WOLFSSL *sslServ = Server(ctxServ, "let-wolfssl-choose", 0, cert_buf, cert_size, pvt_key, pvtkey_size, clientfd);
        //TODO: Need to allocate private fd on the heap if we want to parallelize
        *clientfd = ocall_wait_for_conn(servSocket);
        printf("[Keystore] Serving User Connection\n");
        printf("[Keystore] ClientSocket: %d\n", *clientfd);

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

        process_request((request_t *)command_buf, ret, sslServ, cert_buf, 
            cert_size, pvt_key, pvtkey_size);
        
        wolfSSL_shutdown(sslServ);
        wolfSSL_free(sslServ);
        ocall_terminate_conn(*clientfd);
        has_attested_tls = 0;
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