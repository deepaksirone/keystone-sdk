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
#include "app/syscall.h"
#include "encl_message.h"
#include "edge_wrapper.h"
#include "rule_keystore.h"
#include "keystore_report.h"
#include "keystore_request.h"
#include "keystore_defs.h"
#include "message.h"
#include "./ed25519/ed25519.h"

#define MAXSZ 65535
int copy_from_shared(void* dst, uintptr_t offset, size_t data_len);
int CbIOSend(WOLFSSL *ssl, char *buf, int sz, void *ctx);
int CbIORecv(WOLFSSL *ssl, char *buf, int sz, void *ctx);
WOLFSSL* Client(WOLFSSL_CTX* ctx, char* suite, int setSuite, int doVerify);
WOLFSSL_METHOD* SetMethodClient(int i);
static char reply[MAXSZ];
static char pub_key[2048];

struct WOLFSSL_SOCKADDR {
    unsigned int sz;
    void*        sa;
};

static int fpSendRecv;
static int verboseFlag = 0;

char *gen_iv_sm(int iv_size) {
    char *res = (char *) malloc(iv_size * sizeof(char));
    for(int i = 0; i < (iv_size / sizeof(uintptr_t)); i++) {
        uintptr_t rand = SYSCALL_0(SYSCALL_GENRAND_WORD);
        memcpy(res + i * sizeof(uintptr_t), &rand, sizeof(uintptr_t));
    }

    return res;
}


int myCustomExtCallback(const word16* oid, word32 oidSz, int crit,
                               const unsigned char* der, word32 derSz) {
    //word32 i;

    printf("Custom Extension found!\n");
    /*printf("(");
    for (i = 0; i < oidSz; i++) {
        printf("%d", oid[i]);
        if (i < oidSz - 1) {
            printf(".");
        }
    }
    printf(") : ");

    if (crit) {
        printf("CRITICAL");
    } else {
        printf("NOT CRITICAL");
    }
    printf(" : ");

    for (i = 0; i < derSz; i ++) {
        printf("%x ", der[i]);
    }
    printf("\n");*/
    printf("Extension Size: %u\n", derSz);

    report_t report;
    memcpy((void *)&report, der, sizeof(report_t));


    // Verify the signature here and later check if the public key matches that in the certificate
    if (ed25519_verify((unsigned char *)&report.enclave.signature, (unsigned char *)&report.enclave, 
        sizeof(struct enclave_report_t) - ATTEST_DATA_MAXLEN - SIGNATURE_SIZE + report.enclave.data_len, (unsigned char *)&report.sm.public_key)) {
        ocall_print_buffer("[Custom Extension] Successfully verified signature!\n");
    } else {
        ocall_print_buffer("[Custom Extension] Successfully verified signature!\n");
    }

    // Store the DER public key for later verification
    printf("[Custom Extension] report.enclave.data_len: %lu\n", report.enclave.data_len);
    memcpy((void *)&pub_key, (void *)&report.enclave.data, report.enclave.data_len);


    //fflush(stdout);

    /* NOTE: by returning zero, we are accepting this extension and informing
     *       wolfSSL that it is acceptable. If you find an extension that you
     *       do not find acceptable, you should return an error. The standard 
     *       behavior upon encountering an unknown extension with the critical
     *       flag set is to return ASN_CRIT_EXT_E. For the sake of brevity,
     *       this example is always accepting every extension; you should use
     *       different logic. */
    return 0;
}


int verify_attested_tls(int preverify, WOLFSSL_X509_STORE_CTX* store_ctx) {
    printf("[verify_attested_tls] Entering\n");
	WOLFSSL_X509 *current_cert = store_ctx->current_cert;
	DecodedCert *decodedCert = (DecodedCert *)malloc(sizeof(DecodedCert));
    int ret;
    //char *derbuf = (char *)malloc(8000 * sizeof(char));

    unsigned char *derBuffer[1];
    derBuffer[0] = NULL;

    int derSz = wolfSSL_i2d_X509(current_cert, derBuffer);
    //fflush(stdout);
    wc_InitDecodedCert(decodedCert, derBuffer[0], derSz, 0);
    
    wc_SetUnknownExtCallback(decodedCert, myCustomExtCallback);

    ret = ParseCert(decodedCert, CERT_TYPE, NO_VERIFY, NULL);
    if (ret == 0) {
        printf("[verify_attested_tls] Cert issuer: %s\n", decodedCert->issuer);
    }

    if (memcmp(decodedCert->publicKey, pub_key, decodedCert->pubKeySize) == 0) {
        ocall_print_buffer("[verify_attested_tls] Public Keys Match!\n");
    } else {
        ocall_print_buffer("[verify_attested_tls] Public Keys Do Not Match!\n");
    }

    printf("[verify_attested_tls] decodedCert->pubKeySize: %u\n", decodedCert->pubKeySize);

    return 1;
}


/*--------------------------------------------------------------*/
/* Function implementations */
/*--------------------------------------------------------------*/
int CbIORecv(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    (void) ssl; /* will not need ssl context, just using the file system */
    (void) ctx; /* will not need ctx, we're just using the file system */
    int ret = -1;
    int i;

	network_recv_request_t req;
	req.fd = fpSendRecv;
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
    (void) ctx; /* will not need ctx, we're just using the file system */
    int ret;
    int i;

	// Naive implementation with copying, can optimize by sending just the user pointer
	network_send_data_t *data = (network_send_data_t *) malloc(sizeof(network_send_data_t) + sz * sizeof(char));
	data->fd = fpSendRecv;
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
    }

    free(data);
    return ret;
}

WOLFSSL* Client(WOLFSSL_CTX* ctx, char* suite, int setSuite, int doVerify)
{
    WOLFSSL*     ssl = NULL;
    int ret;

    if ((ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method())) == NULL) {
        printf("Error in setting client ctx\n");
        return NULL;
    }

    if (doVerify == 1) {
        /*if ((wolfSSL_CTX_load_verify_locations(ctx, peerAuthority, 0))
                                                              != SSL_SUCCESS) {
            printf("Failed to load CA (peer Authority) file\n");
            return NULL;
        }*/
    } else {
        wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_attested_tls);
    }

    if (setSuite == 1) {
        if ((ret = wolfSSL_CTX_set_cipher_list(ctx, suite)) != SSL_SUCCESS) {
            printf("ret = %d\n", ret);
            printf("can't set cipher\n");
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
        if (pos == sz) {
            return pos;
        }
		ret = wolfSSL_read(sslcli, (void *) (buffer + pos), sz - pos);
	}

    error = wolfSSL_get_error(sslcli, 0);
    if (ret < 0) {
        if (error != SSL_ERROR_WANT_READ &&
                error != SSL_ERROR_WANT_WRITE) {
                printf("client read failed\n");
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

int connect_client(WOLFSSL *sslCli, WOLFSSL_CTX *ctxCli) {
    int ret = SSL_FAILURE;

    printf("[dec_request] Starting client\n");
    while (ret != SSL_SUCCESS) {
        int error;
        printf("Connecting..\n");
        /* client connect */
        ret |= wolfSSL_connect(sslCli);
        error = wolfSSL_get_error(sslCli, 0);
        if (ret != SSL_SUCCESS) {
            if (error != SSL_ERROR_WANT_READ &&
                error != SSL_ERROR_WANT_WRITE) {
                wolfSSL_free(sslCli);
                wolfSSL_CTX_free(ctxCli);
                printf("[dec_request] client ssl connect failed\n");
                return -1;
            }
        }
    }

    printf("[dec_request] Connection Successfully Established\n");
    return 0;
}

int64_t send_message(WOLFSSL *sslcli, void *buffer, size_t sz) {
    uint64_t request_sz = sz;
    write_buffer(sslcli, &request_sz, sizeof(uint64_t));
    int64_t ret = write_buffer(sslcli, buffer, sz);
    return ret;
}

int64_t recv_message(WOLFSSL *sslcli, void *buffer, size_t sz) {
    uint64_t request_sz;
    read_buffer(sslcli, &request_sz, sizeof(uint64_t));
    //DEBUG_PRINT("Receiving message of size: %lu\n", request_sz);

    int64_t ret = read_buffer(sslcli, buffer, request_sz);
    return ret;
}

int send_key_retrieval_message(uintptr_t uid, uintptr_t rule_id, struct report_t *report, struct keystore_rule *rule) {
    //Working message here:
    //char msg[] = "GET / HTTP/1.1\r\nHost: google.com\r\nConnection: close\r\nUser-Agent: curl/7.65.3\r\nAccept: */*\r\n\r\n";
    // Working:
    //char msg[] = "GET / HTTP/1.1\r\nConnection: close\r\n\r\n";
    //Not working!: 
    //char msg[] = "GET / HTTP/1.1\r\n";
    
    //int ret, msgSz;
    WOLFSSL* sslCli;
    WOLFSSL_CTX* ctxCli = NULL;

    char *hostname = "keystore.tap";
    int host_len = strlen(hostname);

    connection_data_t *data = (connection_data_t *) malloc(sizeof(connection_data_t) + (host_len + 1) * sizeof(unsigned char));
    memset(data, 0, sizeof(connection_data_t) + (host_len + 1) * sizeof(unsigned char));
    data->portnumber = 7777;
    memcpy(data->hostname, hostname, host_len);
    fpSendRecv = ocall_init_connection(data, sizeof(connection_data_t) + (host_len + 1) * sizeof(unsigned char));

    free(data);
    
    wolfSSL_Init();

    sslCli  = Client(ctxCli, "let-wolfssl-decide", 0, 0);

    if (sslCli == NULL) {
        printf("[dec_request] Failed to start client\n");
        return -1;
    }

    if (connect_client(sslCli, ctxCli) != 0) {
        return -1;
    }

    request_t request;
    request.type = RUNTIME_REQUEST;
    runtime_request_t req;
    req.user_id = uid;
    req.rule_id = rule_id;
    memcpy(&req.report, report, sizeof(report_t));

    request.data.runtime_req = req;
    send_message(sslCli, &request, sizeof(request_t));

    int recv_size = recv_message(sslCli, reply, MAXSZ - 1);

    //int ret = wolfSSL_shutdown(sslCli);
    int ret = wolfSSL_shutdown(sslCli);
    while (ret != SSL_SUCCESS) {
        if (ret != SSL_SHUTDOWN_NOT_DONE) {
            printf("Error shutting down SSL connection\n");
            break;
        }
        ret = wolfSSL_shutdown(sslCli);
    }

    if (ocall_terminate_conn(fpSendRecv) != 0) {
        printf("Error closing connection to Keystore\n");
    }

    if (recv_size == sizeof(struct keystore_rule)) {
        memcpy(rule, reply, sizeof(struct keystore_rule));
        return 0;
    }

    printf("Error from Keystore: %s\n", reply);

    return -1;
}


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

	void *decrypted_data = (void *)malloc(encrypted_blob_sz + 1);
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
	    	free(decrypted_data);
            return NULL;
    }

	return decrypted_data;
}

action_data_t *encrypt_action_data(void *action_data, int action_data_sz, unsigned char *key, int key_sz, int32_t *struct_sz) {
    action_data_t *action_dt = (action_data_t *)malloc(sizeof(action_data_t) + action_data_sz * sizeof(unsigned char));
    memset(action_dt, 0, sizeof(action_data_t) + action_data_sz * sizeof(unsigned char));
    
    char *iv = gen_iv_sm(16);
    int iv_sz = 16;

    memcpy((void *)&action_dt->iv, (void *)iv, 16);
    free(iv);
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
	    free(action_dt);
        return NULL;
    }

    

    *struct_sz = sizeof(action_data_t) + action_data_sz * sizeof(unsigned char);
    return action_dt;
}