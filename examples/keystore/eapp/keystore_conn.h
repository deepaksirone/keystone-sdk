#ifndef _H_KEYSTORE_CONN_H_
#define _H_KEYSTORE_CONN_H

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/certs_test.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/asn.h>

extern int has_attested_tls;
extern int verboseFlag;
extern char pub_key[2048];

int CbIORecv(WOLFSSL *ssl, char *buf, int sz, void *ctx);
int CbIOSend(WOLFSSL *ssl, char *buf, int sz, void *ctx);
WOLFSSL* Server(WOLFSSL_CTX* ctx, char* suite, int setSuite, byte *certBuf, 
        int cert_buf_sz, byte* pvtKeyBuf, int pvt_key_buf, int *fd);
WOLFSSL* Client(WOLFSSL_CTX* ctx, char* suite, int setSuite, int doVerify, byte *cert_buf, 
            int cert_size, byte *pvt_key, int pvtkey_size, int *fd);
uint64_t read_buffer(WOLFSSL *sslcli, void *buffer, size_t sz);
int64_t write_buffer(WOLFSSL *sslserv, void *buffer, size_t sz);
void error_response(char *response, WOLFSSL *sslServ);
void success_response(char *response, WOLFSSL *sslServ);
int64_t send_message(WOLFSSL *sslcli, void *buffer, size_t sz);
int64_t recv_message(WOLFSSL *sslcli, void *buffer, size_t sz);

#endif