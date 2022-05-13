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

int start_request_server(WOLFSSL *sslServ, char *bind_addr, int bind_port) {
    printf("Starting Keystore Server\n");
    
    int bind_addr_len = strlen(bind_addr);
    connection_data_t *data = malloc(sizeof(connection_data_t) + bind_addr_len * sizeof(unsigned char));
    data->portnumber = bind_port;
    memcpy(data->hostname, bind_addr, bind_addr_len);
    int servSocket = ocall_init_serv_connection(data, sizeof(connection_data_t) + bind_addr_len * sizeof(unsigned char));

    printf("ServSocket: %d\n", servSocket);

    while (1) {

        //TODO: Need to allocate private fd on the heap if we want to parallelize
        fpSendRecv = ocall_wait_for_conn(servSocket);

        printf("ClientSocket: %d\n", fpSendRecv);

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

        ret = read_buffer(sslServ, command_buf, MAX_COMMAND_SIZE - 1);
        command_buf[ret] = 0;
        
        process_request(command_buf, ret, fpSendRecv);
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

    printf("Cleaning up...\n");
    return 0;

    wolfSSL_shutdown(sslServ);
    /*
    wolfSSL_free(sslCli);
    wolfSSL_CTX_free(ctxCli);
    wolfSSL_Cleanup();*/

    /* close the streams so client can reset file contents */
}