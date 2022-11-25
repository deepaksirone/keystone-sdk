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
#include "keystore_defs.h"
#include "message.h"
#include "app/syscall.h"
#include "event_loop.h"

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

static uint64_t get_ticks()
{
  uint64_t n;
  __asm__ __volatile__("rdtime %0" : "=r"(n));
  return n;
}

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
const volatile uintptr_t __user_id = 0x00000000;

extern char __decrypt_buffer_start;
extern char __decrypt_buffer_end;

char secure_buf[] __attribute__((section(".secure_data"))) = "--w00t w00t from decrypted code--\n";

struct keystore_rule rule;

void print_array(unsigned char *array, int array_sz, char *array_name)
{
    printf("unsigned char %s[] = {\n", array_name);
    for(int i = 0; i < array_sz - 1; i++) {
        printf("0x%02x, ", array[i]);
    }

    printf("0x%02x };\n", array[array_sz - 1]);
}

void print_report(struct report_t *report)
{
    printf("\n----SM Report----\n");
    print_array((unsigned char *)&report->sm.hash, MDSIZE, "sm_hash");
    print_array((unsigned char *)&report->sm.public_key, PUBLIC_KEY_SIZE, "sm_public_key");
    print_array((unsigned char *)&report->sm.signature, SIGNATURE_SIZE, "sm_signature");

    printf("\n----Enclave Report----\n");
    print_array((unsigned char *)&report->enclave.hash, MDSIZE, "enclave_hash");
    printf("uint64_t data_len = %lu;\n", report->enclave.data_len);
    print_array((unsigned char *)&report->enclave.data, ATTEST_DATA_MAXLEN, "enclave_data");
    print_array((unsigned char *)&report->enclave.signature, SIGNATURE_SIZE, "enclave_signature");
    
    printf("\n----Device Public Key----\n");
    print_array((unsigned char *)&report->dev_public_key, PUBLIC_KEY_SIZE, "dev_public_key");
}

void populate_default(struct keystore_rule *rule)
{
    memcpy(&rule->key_action[0], "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 32);
    memcpy(&rule->key_trigger[0], "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 32);
    rule->num_actions = 1;
    rule->num_triggers = 1;
    rule->rid = 0;

}

void get_keys() {
    struct report_t report;
    char buffer[2048];
    char uid_rid[100];
    snprintf(uid_rid, 100, "%lu-%lu", __rule_id, __user_id);
    attest_enclave((void *)buffer, uid_rid, 100);
    memcpy(&report, buffer, sizeof(report_t));

    print_report(&report);

    if (send_key_retrieval_message(__user_id, __rule_id, &report, &rule) != 0) {
        printf("[-] Failed to retrieve keys, setting default keys for trigger0\n");
        populate_default(&rule);
    } else {
        printf("[+] get_keys returned 0\n");
    }
}

/*--------------------------------------------------------------*/
/* Function implementations */
/*--------------------------------------------------------------*/

SECURE_CODE void secure_print() {
    
    ocall_print_buffer(secure_buf);
}


int main(int argc, char** argv)
{

    char print_buf[100];
    printf("[+] Retreiving keys from keystore\n");
    uint64_t start_enclave = get_ticks();
    get_keys();
    uint64_t get_keys_end = get_ticks();
    
    
    unsigned char key[32];
    char code_tag[16];
    char code_nonce[16];
    char *secure_code_enc = (char *)__secure_code_start;
    char *secure_data_enc = (char *)__secure_data_start;
    size_t secure_code_size = (size_t)__secure_code_size;
    size_t secure_data_size = (size_t)__secure_data_size;

    uintptr_t dec_key_1 = __dec_key_1;
    uintptr_t dec_key_2 = __dec_key_2;
    uintptr_t dec_key_3 = __dec_key_3;
    uintptr_t dec_key_4 = __dec_key_4;

    uintptr_t secure_code_tag_lower = __secure_code_tag_lower;
    uintptr_t secure_code_tag_upper = __secure_code_tag_upper;
    uintptr_t secure_code_nonce_lower = __secure_code_nonce_lower;
    uintptr_t secure_code_nonce_upper = __secure_code_nonce_upper;

    uintptr_t secure_data_tag_lower = __secure_data_tag_lower;
    uintptr_t secure_data_tag_upper = __secure_data_tag_upper;
    uintptr_t secure_data_nonce_lower = __secure_data_nonce_lower;
    uintptr_t secure_data_nonce_upper = __secure_data_nonce_upper;

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

    printf("[+] Decrypting .secure_data section\n");
    char data_tag[16];
    char data_nonce[16];

    memcpy(data_tag, &secure_data_tag_lower, sizeof(uintptr_t));
    memcpy(data_tag + sizeof(uintptr_t), &secure_data_tag_upper, sizeof(uintptr_t));

    memcpy(data_nonce, &secure_data_nonce_lower, sizeof(uintptr_t));
    memcpy(data_nonce + sizeof(uintptr_t), &secure_data_nonce_upper, sizeof(uintptr_t));

    if ((ret = wc_AesGcmDecrypt(&enc, (byte *)&__decrypt_buffer_start, (byte *)secure_data_enc, secure_data_size, (byte *)data_nonce, 16, 
                (byte *)data_tag, 16, NULL, 0)) != 0) {
            printf("Error decrypting .secure_data! ret: %d\n", ret);
            printf("AES_GCM_AUTH_E == ret: %d\n", AES_GCM_AUTH_E == ret);
            return -1;
    }

    printf("[++] .secure_data decrypted successfully!\n");

    printf("[+] Running mprotect on .secure_data section: PROT_READ | PROT_WRITE\n");
    ret = mprotect(secure_data_enc, secure_data_size, PROT_READ | PROT_WRITE);
    printf("mprotect return value: %d\n", ret);

    memcpy(secure_data_enc, &__decrypt_buffer_start, secure_data_size);

    printf("[+] Restoring mprotect perms: PROT_READ | PROT_EXEC\n");
    ret = mprotect(secure_data_enc, secure_data_size, PROT_READ | PROT_EXEC);
    printf("mprotect return value: %d\n", ret);

    uint64_t init_end = get_ticks();
    
    snprintf(print_buf, 100, "[time] Keystore get_keys: %lu ticks\n", get_keys_end - start_enclave);
    ocall_print_buffer(print_buf);

    snprintf(print_buf, 100, "[time] Decrypt + init: %lu ticks\n", init_end - get_keys_end);
    ocall_print_buffer(print_buf);

    printf("[+] Calling secure_print\n");
    secure_print();

    event_loop(&rule, 1000000000);
    //printf("Hello world\n");
    return 0;
}