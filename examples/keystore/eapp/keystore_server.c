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
#include "encl_message.h"
#include "edge_wrapper.h"
#include "keystone_cert.h"

#define MAXSZ 65535
#define MAX_COMMAND_SIZE 65535
#define MAX_REQUEST_SIZE 65535

char command_buf[MAX_COMMAND_SIZE];
char request_buf[MAX_REQUEST_SIZE];

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
	network_send_data_t *data = malloc(sizeof(network_send_data_t) + sz * sizeof(char));
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
        wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);
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

/*
// Same as client, except has a private fd which can be used with the ctx param in the I/O callbacks
WOLFSSL* Server(WOLFSSL_CTX* ctx, char* suite, int setSuite)
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

    if (wolfSSL_CTX_use_certificate_file(ctx, serverCert, SSL_FILETYPE_PEM)
                                                    != SSL_SUCCESS) {
        printf("trouble loading server cert file\n");
        return NULL;
    }

    if (wolfSSL_CTX_use_PrivateKey_file(ctx, serverKey, SSL_FILETYPE_PEM)
                                                    != SSL_SUCCESS) {
        printf("trouble loading server key file\n");
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

    wolfSSL_set_fd(ssl, fpRecv);
    return ssl;
}*/


int64_t read_buffer(WOLFSSL *sslcli, void *buffer, size_t sz)
{
	int64_t pos = 0;printf("Before MakeSelfCert\n");
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
                printf("client read failed\n");
        }
    }

	return pos;
}

void register_rule(int fd, char *username, char *password, char *rule_id, char *rule_bin_hash, 
                    char *key_trigger, char *key_action, char *key_rule) {
    

}

void process_dec_request(int fd) 
{

}

void process_invalid_cmd(int fd)
{

}

void register_user(int fd, char *username, char *password)
{

}

/// Commands are:
/// REGUSR <username> <password>
/// REGRUL <username> <password> <rule id> <rule binary hash in hex> <n> <m> <K_t1 in hex>..<K_tn> <K_a1 in hex>..<K_an> <K_rule in hex>
/// REQRUL : keystore sends back a challenge, enclave responds with attestation report signed with challenge, keystore responds with decryption key
void process_request(char *command_buf, int cmd_size, int fd) {
    if (cmd_size < 6) return;
    if (strncmp(command_buf, "REGUSR", (size_t)6) == 0) {
        char *username = strtok(&command_buf[5], " ");
        if (!username) return;

        char *password = strtok(NULL, " ");
        if (!password) return;
        
        register_user(fd, username, password);
    } else if (strncmp(command_buf, "REGRUL", (size_t)6) == 0) {
        char *username = strtok(&command_buf[5], " ");
        if (!username) return;

        char *password = strtok(NULL, " ");
        if (!password) return;

        char *rule_id = strtok(NULL, " ");
        if (!rule_id) return;

        char *rule_bin_hash = strtok(NULL, " ");
        if (!rule_bin_hash) return;

        char *key_trigger = strtok(NULL, " ");
        if (!key_trigger) return;

        char *key_action = strtok(NULL, " ");
        if (!key_action) return;

        char *key_rule = strtok(NULL, " ");
        if (!key_rule) return;

        register_rule(fd, username, password, rule_id, rule_bin_hash, key_trigger, key_action, key_rule);
    } else if (strncmp(command_buf, "REQRUL", (size_t)6) == 0) {
        process_dec_request(fd);
    } else {
        process_invalid_cmd(fd);
    }
}

//TODO: Implement this -- dummy impl for now
int ocall_wait_for_client_connection()
{
    return 10;
}

int start_request_server(char *bind_addr, int bind_port) {
    printf("Starting Keystore Server\n");
    
    while (1) {

        //TODO: Need to allocate private fd on the heap if we want to parallelize
        fpSendRecv = ocall_wait_for_client_connection();

        WOLFSSL* sslCli;
        WOLFSSL_CTX* ctxCli = NULL;

        sslCli = Client(ctxCli, "let-wolfssl-decide", 0, 0);

        int ret = read_buffer(sslCli, command_buf, MAX_COMMAND_SIZE - 1);
        command_buf[ret] = 0;
        
        process_request(command_buf, ret, fpSendRecv);
    }
}


int main(int argc, char** argv)
{

    WOLFSSL* sslCli;
    WOLFSSL_CTX* ctxCli = NULL;
    wolfSSL_Init();

    generate_attested_cert_with_evidence(NULL, NULL, 0, NULL, NULL);
    /* Example usage */
    // sslServ = Server(ctxServ, "ECDHE-RSA-AES128-SHA", 1);
    // Turning off verification for now
    /*
    start_request_server();

    if (sslCli == NULL) {
        printf("Failed to start client\n");
        goto cleanup;
    }

    ret = SSL_FAILURE;

    printf("Starting client\n");
    while (ret != SSL_SUCCESS) {
        int error;
        printf("Connecting..\n");

        ret |= wolfSSL_connect(sslCli);
        error = wolfSSL_get_error(sslCli, 0);
        if (ret != SSL_SUCCESS) {
            if (error != SSL_ERROR_WANT_READ &&
                error != SSL_ERROR_WANT_WRITE) {
                wolfSSL_free(sslCli);
                wolfSSL_CTX_free(ctxCli);
                printf("client ssl connect failed\n");
                goto cleanup;
            }
        }
        printf("Client connected successfully...\n");
    }



    while (1) {
        int error;


        msgSz = (int) strlen(msg);
        ret   = wolfSSL_write(sslCli, msg, msgSz);
        error = wolfSSL_get_error(sslCli, 0);
        if (ret != msgSz) {
            if (error != SSL_ERROR_WANT_READ &&
                error != SSL_ERROR_WANT_WRITE) {
                printf("client write failed\n");
                break;
            }
        }

	    ret = read_buffer(sslCli, reply, MAXSZ - 1);
        if (ret > 0) {
	        reply[ret] = '\0';
	        printf("Client Received Reply: %s\n", reply);
        }

        break;

    }*/

//cleanup:
    printf("Cleaning up...\n");
    return 0;
    wolfSSL_shutdown(sslCli);
    wolfSSL_free(sslCli);
    wolfSSL_CTX_free(ctxCli);
    wolfSSL_Cleanup();
    /* close the streams so client can reset file contents */
}