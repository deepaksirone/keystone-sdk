#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/test.h>
#include <errno.h>
#include <stdio.h>
#define SERV_PORT 11111

int main()
{
  printf("[NEW] hello, world!\n");
/*
  int sockfd;
WOLFSSL_CTX* ctx;
WOLFSSL* ssl;
WOLFSSL_METHOD* method;
struct  sockaddr_in servAddr;
const char message[] = "Hello, World!";

sockfd = socket(AF_INET, SOCK_STREAM, 0);
memset(&servAddr, 0, sizeof(servAddr));
servAddr.sin_family = AF_INET;
servAddr.sin_port = htons(SERV_PORT);

connect(sockfd, (struct sockaddr *) &servAddr, sizeof(servAddr));

wolfSSL_Init();
method = wolfTLSv1_2_client_method(); 

if ( (ctx = wolfSSL_CTX_new(method)) == NULL) {
      err_sys("wolfSSL_CTX_new error");
}

if ( (ssl = wolfSSL_new(ctx)) == NULL) {
     err_sys("wolfSSL_new error");
}

if (wolfSSL_CTX_load_verify_locations(ctx, "certs/ca-cert.pem", 0) !=
SSL_SUCCESS) {
     err_sys("Error loading certs/ca-cert.pem");
}

wolfSSL_set_fd(ssl, sockfd);
wolfSSL_connect(ssl);
wolfSSL_write(ssl, message, strlen(message));

wolfSSL_free(ssl);
wolfSSL_CTX_free(ctx);
wolfSSL_Cleanup();*/
  return 0;
}
