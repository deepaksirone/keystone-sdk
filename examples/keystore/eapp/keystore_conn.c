#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>

#include "encl_message.h"
#include "edge_wrapper.h"
#include "keystore_conn.h"
#include "keystore_cert.h"
#include "keystore_user.h"
#include "keystore_rule.h"
#include "keystore_report.h"
#include "keystore_request.h"
#include "keystore_defs.h"
#include "app/syscall.h"
#include "./ed25519/ed25519.h"
#include "./mtwister/mtwister.h"

//TODO: set the has_attested_tls variable here
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
        has_attested_tls = 1;
    } else {
        ocall_print_buffer("[Custom Extension] Successfully verified signature!\n");
        has_attested_tls = 0;
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
        int cert_buf_sz, byte* pvtKeyBuf, int pvt_key_buf, int *fd)
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

    wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_attested_tls);

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

    //wolfSSL_set_fd(ssl, *fd);

    wolfSSL_SetIOReadCtx(ssl, (void *) fd);
    wolfSSL_SetIOWriteCtx(ssl, (void *) fd);
    return ssl;
}

WOLFSSL* Client(WOLFSSL_CTX* ctx, char* suite, int setSuite, int doVerify, byte *cert_buf, 
            int cert_size, byte *pvt_key, int pvtkey_size, int *fd)
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
        if (wolfSSL_CTX_use_certificate_buffer(ctx, cert_buf, cert_size, SSL_FILETYPE_ASN1) != SSL_SUCCESS) {
            printf("[Client] Error loading certificate from buffer\n");
            return NULL;
        }

        if (wolfSSL_CTX_use_PrivateKey_buffer(ctx, pvt_key, pvtkey_size, SSL_FILETYPE_ASN1) != SSL_SUCCESS) {
            printf("[Client] Error loading server pvt key buffer\n");
            return NULL;
        }
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

    //wolfSSL_set_fd(ssl, *fd);

    wolfSSL_SetIOReadCtx(ssl, (void *) fd);
    wolfSSL_SetIOWriteCtx(ssl, (void *) fd);

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

int64_t send_message(WOLFSSL *sslcli, void *buffer, size_t sz) {
    uint64_t request_sz = sz;
    write_buffer(sslcli, &request_sz, sizeof(uint64_t));
    int64_t ret = write_buffer(sslcli, buffer, sz);
    return ret;
}

int64_t recv_message(WOLFSSL *sslcli, void *buffer, size_t sz) {
    uint64_t request_sz;
    read_buffer(sslcli, &request_sz, sizeof(uint64_t));
    DEBUG_PRINT("Receiving message of size: %lu\n", request_sz);

    int64_t ret = read_buffer(sslcli, buffer, request_sz);
    return ret;
}

