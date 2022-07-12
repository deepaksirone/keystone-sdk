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
#include "rule_keystore.h"
#include "keystore_report.h"
#include "message.h"
#include "app/syscall.h"

#define MAXSZ 65535
int copy_from_shared(void* dst, uintptr_t offset, size_t data_len);
int CbIOSend(WOLFSSL *ssl, char *buf, int sz, void *ctx);
int CbIORecv(WOLFSSL *ssl, char *buf, int sz, void *ctx);
WOLFSSL* Client(WOLFSSL_CTX* ctx, char* suite, int setSuite, int doVerify);
WOLFSSL_METHOD* SetMethodClient(int i);


struct WOLFSSL_SOCKADDR {
    unsigned int sz;
    void*        sa;
};

//static int fpSendRecv;
//static int verboseFlag = 0;

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

const volatile uintptr_t __dec_key_1 = 0x66666666;
const volatile uintptr_t __dec_key_2 = 0x77777777;
const volatile uintptr_t __dec_key_3 = 0x88888888;
const volatile uintptr_t __dec_key_4 = 0x99999999;

const volatile uintptr_t __rule_id = 0x00000000;
const volatile uintptr_t __user_id = 0x12345678;

extern char __decrypt_buffer_start;
extern char __decrypt_buffer_end;

struct keystore_rule rule;

void get_keys() {
    struct report_t report;
    char buffer[2048];
    char uid_rid[100];
    snprintf(uid_rid, 100, "%lu-%lu", __rule_id, __user_id);
    attest_enclave((void *)buffer, uid_rid, 100);
    memcpy(&report, buffer, sizeof(report_t));

    if (send_key_retrieval_message(__user_id, __rule_id, &report, &rule) != 0) {
        printf("[-] Failed to retrieve keys\n");
    } else {
        printf("[+] get_keys returned 0\n");
    }
}

/*--------------------------------------------------------------*/
/* Function implementations */
/*--------------------------------------------------------------*/

__attribute__ ((section(".secure_code"), noinline)) void secure_print() {
    printf("--w00t w00t from decrypted code--\n");
}


int main(int argc, char** argv)
{

    printf("[+] Retreiving keys from keystore\n");
    get_keys();
    
    unsigned char key[32];
    char code_tag[16];
    char code_nonce[16];
    char *secure_code_enc = (char *)__secure_code_start;
    size_t secure_code_size = (size_t)__secure_code_size;
    uintptr_t dec_key_1 = __dec_key_1;
    uintptr_t dec_key_2 = __dec_key_2;
    uintptr_t dec_key_3 = __dec_key_3;
    uintptr_t dec_key_4 = __dec_key_4;
    uintptr_t secure_code_tag_lower = __secure_code_tag_lower;
    uintptr_t secure_code_tag_upper = __secure_code_tag_upper;
    uintptr_t secure_code_nonce_lower = __secure_code_nonce_lower;
    uintptr_t secure_code_nonce_upper = __secure_code_nonce_upper;

    int ret;


    memcpy(key, &dec_key_1, sizeof(uintptr_t));
    memcpy(key + sizeof(uintptr_t), &dec_key_2, sizeof(uintptr_t));
    memcpy(key + 2 * sizeof(uintptr_t), &dec_key_3, sizeof(uintptr_t));
    memcpy(key + 3 * sizeof(uintptr_t), &dec_key_4, sizeof(uintptr_t));

    memcpy(code_tag, &secure_code_tag_lower, sizeof(uintptr_t));
    memcpy(code_tag + sizeof(uintptr_t), &secure_code_tag_upper, sizeof(uintptr_t));

    memcpy(code_nonce, &secure_code_nonce_lower, sizeof(uintptr_t));
    memcpy(code_nonce + sizeof(uintptr_t), &secure_code_nonce_upper, sizeof(uintptr_t));

    printf("[+] Decrypting .secure_code section\n");
    printf(" __secure_code_start: 0x%016lx\n", __secure_code_start);
    printf(" __decrypt_buffer_start: 0x%016lx\n", (uintptr_t)&__decrypt_buffer_start);
    printf(" __secure_code_nonce_lower: 0x%016lx\n", __secure_code_nonce_lower);
    printf(" __secure_code_nonce_upper: 0x%016lx\n", __secure_code_nonce_upper);
    printf(" __secure_code_tag_lower: 0x%016lx\n", __secure_code_tag_lower);
    printf(" __secure_code_tag_upper: 0x%016lx\n", __secure_code_tag_upper);

    printf(" __dec_key_1: 0x%016lx\n", __dec_key_1);
    printf(" __dec_key_2: 0x%016lx\n", __dec_key_2);
    printf(" __dec_key_3: 0x%016lx\n", __dec_key_3);
    printf(" __dec_key_4: 0x%016lx\n", __dec_key_4);

    Aes enc;
    wc_AesInit(&enc, NULL, INVALID_DEVID);

    if ((ret = wc_AesGcmSetKey(&enc, (const byte *)key, 32)) != 0) {
            printf("[-] Error setting key!");
            return -1;
    }

    if ((ret = wc_AesGcmDecrypt(&enc, (byte *)&__decrypt_buffer_start, (byte *)secure_code_enc, secure_code_size, (byte *)code_nonce, 16, 
                (byte *)code_tag, 16, NULL, 0)) != 0) {
            printf("Error decrypting! ret: %d\n", ret);
            printf("AES_GCM_AUTH_E == ret: %d\n", AES_GCM_AUTH_E == ret);
            return -1;
    }

    printf("[++] .secure_code decrypted successfully!\n");


    printf("[+] Running mprotect on .secure_code section: PROT_READ | PROT_WRITE\n");
    ret = mprotect(secure_code_enc, secure_code_size, PROT_READ | PROT_WRITE);
    printf("mprotect return value: %d\n", ret);

    if (ret != 0) {
        printf("mprotect falied!\n");
        return -1;
    }

    printf("[+] Copying decrypted code to .secure_code section\n");
    memcpy(secure_code_enc, &__decrypt_buffer_start, secure_code_size);

    printf("[+] Restoring mprotect perms: PROT_READ | PROT_EXEC\n");
    ret = mprotect(secure_code_enc, secure_code_size, PROT_READ | PROT_EXEC);
    printf("mprotect return value: %d\n", ret);


    printf("[+] Calling secure_print\n");
    secure_print();

    //printf("Hello world\n");
    return 0;
}