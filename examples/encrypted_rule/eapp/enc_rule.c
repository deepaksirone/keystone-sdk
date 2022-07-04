#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/certs_test.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/aes.h>
#include "encl_message.h"
#include "edge_wrapper.h"

#define MAXSZ 65535
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

const volatile uintptr_t __secure_code_start = 0xdeadbeef;
const volatile uintptr_t __secure_code_size = 0xaaaaaaaa;
const volatile uintptr_t __secure_data_start = 0xbbbbbbbb;
const volatile uintptr_t __secure_data_size = 0xcccccccc;

const volatile uintptr_t __secure_code_tag_lower = 0xdddddddd;
const volatile uintptr_t __secure_code_tag_upper = 0xeeeeeeee;
const volatile uintptr_t __secure_code_nonce_lower = 0xffffffff;
const volatile uintptr_t __secure_code_nonce_upper = 0x11111111;

const volatile uintptr_t __secure_data_tag_lower = 0x22222222;
const volatile uintptr_t __secure_data_tag_upper = 0x33333333;
const volatile uintptr_t __secure_data_nonce_lower = 0x44444444;
const volatile uintptr_t __secure_data_nonce_upper = 0x55555555;

const volatile uintptr_t __dec_key_upper = 0x66666666;
const volatile uintptr_t __dec_key_lower = 0x77777777;

extern char __decrypt_buffer_start;
extern char __decrypt_buffer_end;

/*--------------------------------------------------------------*/
/* Function implementations */
/*--------------------------------------------------------------*/

__attribute__ ((section(".secure_code"))) void secure_print() {
    printf("Secure printf\n");
}

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

int main(int argc, char** argv)
{
    /*
    //Working message here:
    //char msg[] = "GET / HTTP/1.1\r\nHost: google.com\r\nConnection: close\r\nUser-Agent: curl/7.65.3\r\nAccept: *//*\r\n\r\n";
    // Working:
    char msg[] = "GET / HTTP/1.1\r\nConnection: close\r\n\r\n";
    //Not working!: 
    //char msg[] = "GET / HTTP/1.1\r\n";
    char reply[MAXSZ];
    int    ret, msgSz;
    WOLFSSL* sslCli;
    WOLFSSL_CTX* ctxCli = NULL;

    if (argc == 2) {
        if (strncmp(argv[1], "-verbose", (size_t)8) == 0 ||
            strncmp(argv[1], "-v", (size_t)2)       == 0) {
            verboseFlag = 1;
        }
    }

    char *hostname = "google.com";
    int host_len = strlen(hostname);

    connection_data_t *data = malloc(sizeof(connection_data_t) + host_len * sizeof(unsigned char));
    data->portnumber = 443;
    memcpy(data->hostname, hostname, host_len);
    fpSendRecv = ocall_init_connection(data, sizeof(connection_data_t) + host_len * sizeof(unsigned char));

    wolfSSL_Init();


//    sslServ = Server(ctxServ, "ECDHE-RSA-AES128-SHA", 1);
    // Turning off verification for now
    sslCli  = Client(ctxCli, "let-wolfssl-decide", 0, 0);

    if (sslCli == NULL) {
        printf("Failed to start client\n");
        goto cleanup;
    }

    ret = SSL_FAILURE;

    printf("Starting client\n");
    while (ret != SSL_SUCCESS) {
        int error;
        printf("Connecting..\n");
        //
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


    // read and write 
    while (1) {
        int error;

        // client send/read
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
/*
cleanup:
    printf("Cleaning up...\n");
    return 0;
    wolfSSL_shutdown(sslCli);
    wolfSSL_free(sslCli);
    wolfSSL_CTX_free(ctxCli);
    wolfSSL_Cleanup();
    */


    unsigned char key[16];
    char code_tag[16];
    char code_nonce[16];
    char *secure_code_enc = (char *)__secure_code_start;
    size_t secure_code_size = (size_t)__secure_code_size;
    uintptr_t dec_key_lower = __dec_key_lower;
    uintptr_t dec_key_upper = __dec_key_upper;
    uintptr_t secure_code_tag_lower = __secure_code_tag_lower;
    uintptr_t secure_code_tag_upper = __secure_code_tag_upper;
    uintptr_t secure_code_nonce_lower = __secure_code_nonce_lower;
    uintptr_t secure_code_nonce_upper = __secure_code_nonce_upper;

    int ret;


    memcpy(key, &dec_key_lower, sizeof(uintptr_t));
    memcpy(key + sizeof(uintptr_t), &dec_key_upper, sizeof(uintptr_t));

    memcpy(code_tag, &secure_code_tag_lower, sizeof(uintptr_t));
    memcpy(code_tag + sizeof(uintptr_t), &secure_code_tag_upper, sizeof(uintptr_t));

    memcpy(code_nonce, &secure_code_nonce_lower, sizeof(uintptr_t));
    memcpy(code_nonce + sizeof(uintptr_t), &secure_code_nonce_upper, sizeof(uintptr_t));

    printf("Decrypting .secure_code section\n");
    printf(" __secure_code_start: %016lx\n", __secure_code_start);
    printf(" __decrypt_buffer_start: %016lx\n", (uintptr_t)&__decrypt_buffer_start);


    Aes enc;
    wc_AesInit(&enc, NULL, INVALID_DEVID);

    if ((ret = wc_AesGcmSetKey(&enc, (const byte *)key, 16)) != 0) {
            printf("Error setting key!");
            return -1;
    }

    if ((ret = wc_AesGcmDecrypt(&enc, (byte *)&__decrypt_buffer_start, (byte *)secure_code_enc, secure_code_size, (byte *)code_nonce, 16, 
                (byte *)code_tag, 16, NULL, 0)) != 0) {
            printf("Error decrypting! ret: %d\n", ret);
            printf("AES_GCM_AUTH_E == ret: %d\n", AES_GCM_AUTH_E == ret);
            return -1;
    } else {
            printf(".secure_code decrypted successfully!\n");
    }

    printf("Running mprotect on .secure_code section\n");
    ret = mprotect(secure_code_enc, secure_code_size, PROT_READ | PROT_WRITE);
    printf("mprotect return value: %d\n", ret);

    if (ret != 0) {
        printf("mprotect falied!\n");
        return -1;
    }

    printf("Copying decrypted code to .secure_code section\n");
    memcpy(secure_code_enc, &__decrypt_buffer_start, secure_code_size);

    printf("Restoring mprotect perms\n");
    ret = mprotect(secure_code_enc, secure_code_size, PROT_READ | PROT_EXEC);
    printf("mprotect return value: %d\n", ret);


    printf("Calling secure_print\n");
    secure_print();
}

/*int main()
{
	printf("[NEW] hello, world!\n");

	int sockfd;
	WOLFSSL_CTX* ctx;
	WOLFSSL* ssl;
	WOLFSSL_METHOD* method;
	struct  sockaddr_in servAddr;
	const char message[] = "Hello, World!";

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		printf("Error creating socket\n");
		exit(1);
	}

	memset(&servAddr, 0, sizeof(servAddr));
	servAddr.sin_family = AF_INET;
	servAddr.sin_port = htons(SERV_PORT);

	if (connect(sockfd, (struct sockaddr *) &servAddr, sizeof(servAddr)) < 0 ) {
		printf("Error connecting socket\n");
		exit(1);
	}

	wolfSSL_Init();
	method = wolfTLSv1_2_client_method(); 

	if ( (ctx = wolfSSL_CTX_new(method)) == NULL) {
		err_sys("wolfSSL_CTX_new error");
	}

	if ( (ssl = wolfSSL_new(ctx)) == NULL) {
     		err_sys("wolfSSL_new error");
	}

	if (wolfSSL_CTX_load_verify_locations(ctx, "certs/ca-cert.pem", 0) != SSL_SUCCESS) {
     		err_sys("Error loading certs/ca-cert.pem");
	}

	wolfSSL_set_fd(ssl, sockfd);
	wolfSSL_connect(ssl);
	wolfSSL_write(ssl, message, strlen(message));

	wolfSSL_free(ssl);
	wolfSSL_CTX_free(ctx);
	wolfSSL_Cleanup();
	return 0;
}*/
