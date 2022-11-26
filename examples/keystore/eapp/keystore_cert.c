#include <wolfssl/options.h>

//#include <wolfssl/ssl.h>
//#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/signature.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>
#include "app/syscall.h"


//static const unsigned char oid_keystone_evidence[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x15, 0x0A, 0x01, 0x02 };
static byte* generateEvidenceExtension(RsaKey *gen_key, size_t *evidence_sz) {
    byte *report_buf = (byte *)calloc(2048, sizeof(byte));
    byte *pubkey = (byte *)calloc(1024, sizeof(byte));
    int ret = wc_RsaKeyToPublicDer(gen_key, pubkey, 1024 * sizeof(byte));
    if (ret < 0) {
        printf("Error in writing public key to DER format: %d", ret);
        return NULL;
    }

    if ((ret = attest_enclave((void *)report_buf, pubkey, ret)) != 0) {
        printf("Error getting report %d", ret);
        return NULL;
    }

    *evidence_sz = 2048 * sizeof(byte);
    return report_buf;
}

//TODO: optimize buffers
int generate_attested_cert_with_evidence(
    const unsigned char* subject_name,
    const void* optional_parameters,
    size_t optional_parameters_size,
    byte** output_certificate,
    int* output_certificate_size,
    byte** pvtkey,
    int *pvtkey_size) {

    RsaKey gen_key;
    Cert   *cert = (Cert *) malloc(sizeof(Cert));
    RNG    rng;
    int    ret;

    printf("Before InitRng\n");
    ret = wc_InitRng(&rng);
    printf("InitRng returned: %d\n", ret);
    
    printf("Before InitRsaKey\n");
    wc_InitRsaKey(&gen_key, 0);
    //printf("Before InitCert\n");
    ret = wc_InitCert(cert);
    printf("InitCert returned: %d\n", ret);
    printf("Sizeof Cert: %lu\n", sizeof(Cert));

    printf("Before MakeRSAKey\n");
    ret = wc_MakeRsaKey(&gen_key, 1024, 65537, &rng);
    
    byte *derCert = (byte *) malloc(8000 * sizeof(byte));

    size_t evidence_sz;
    byte *evidence_ext = generateEvidenceExtension(&gen_key, &evidence_sz);

    // Initialize Certificate

    strncpy(cert->subject.country, "US", CTC_NAME_SIZE);
    strncpy(cert->subject.state, "WI", CTC_NAME_SIZE);
    strncpy(cert->subject.locality, "Madison", CTC_NAME_SIZE);
    strncpy(cert->subject.org, "KeystoneTAP", CTC_NAME_SIZE);
    strncpy(cert->subject.unit, "Development", CTC_NAME_SIZE);
    strncpy(cert->subject.commonName, "Keystore.Tap", CTC_NAME_SIZE);
    strncpy(cert->subject.email, "info@keystoreTap", CTC_NAME_SIZE);


    strncpy(cert->issuer.country, "US", CTC_NAME_SIZE);
    strncpy(cert->issuer.state, "WI", CTC_NAME_SIZE);
    strncpy(cert->issuer.locality, "Madison", CTC_NAME_SIZE);
    strncpy(cert->issuer.org, "KeystoneTAP", CTC_NAME_SIZE);
    strncpy(cert->issuer.unit, "Development", CTC_NAME_SIZE);
    strncpy(cert->issuer.commonName, "Keystore.Tap", CTC_NAME_SIZE);
    strncpy(cert->issuer.email, "info@keystoreTap", CTC_NAME_SIZE);

    if ((ret = wc_SetCustomExtension(cert, 1, "1.2.3.4.5", evidence_ext, evidence_sz)) < 0) {
        printf("Error setting evidence extension: %d", ret);
        return -1;
    }
    
    printf("Before MakeSelfCert\n");
    
    int certSz = wc_MakeSelfCert(cert, derCert, 8000 * sizeof(byte), &gen_key, &rng);
    if (certSz < 0) {
        printf("Error in cert generation!\n");
        return -1;
    }

    byte *rsa_key = (byte *)malloc(4096 * sizeof(byte));
    int rsa_key_size = wc_RsaKeyToDer(&gen_key, rsa_key, 4096 * sizeof(byte));
    if (rsa_key_size < 0) {
        printf("Error in writing key to DER format\n");
        return -1;
    }

    *output_certificate = derCert;
    *output_certificate_size = certSz;

    *pvtkey = rsa_key;
    *pvtkey_size = rsa_key_size;

    return 0;
}