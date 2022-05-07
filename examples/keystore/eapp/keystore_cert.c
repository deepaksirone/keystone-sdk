#include <wolfssl/options.h>

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/signature.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>

//static const unsigned char oid_keystone_evidence[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x15, 0x0A, 0x01, 0x02 };

int generate_attested_cert_with_evidence(
    const unsigned char* subject_name,
    const void* optional_parameters,
    size_t optional_parameters_size,
    uint8_t** output_certificate,
    size_t* output_certificate_size) {

    RsaKey genKey;
    Cert   cert;
    RNG    rng;
    int    ret;

    printf("Before InitRng\n");
    int r = wc_InitRng(&rng);
    printf("InitRng returned: %d\n", r);
    
    printf("Before InitRsaKey\n");
    wc_InitRsaKey(&genKey, 0);
    printf("Before InitCert\n");
    wc_InitCert(&cert);

    printf("Before MakeRSAKey\n");
    ret = wc_MakeRsaKey(&genKey, 1024, 65537, &rng);
    
    byte derCert[4096];

    strncpy(cert.subject.country, "US", CTC_NAME_SIZE);
    strncpy(cert.subject.state, "WI", CTC_NAME_SIZE);
    strncpy(cert.subject.locality, "Madison", CTC_NAME_SIZE);
    strncpy(cert.subject.org, "KeystoneTAP", CTC_NAME_SIZE);
    strncpy(cert.subject.unit, "Development", CTC_NAME_SIZE);
    strncpy(cert.subject.commonName, "Keystore.Tap", CTC_NAME_SIZE);
    strncpy(cert.subject.email, "info@keystoreTap", CTC_NAME_SIZE);

    printf("Before MakeSelfCert\n");
    int certSz = wc_MakeSelfCert(&cert, derCert, sizeof(derCert), &genKey, &rng);
    if (certSz < 0) {
        printf("Error in cert generation!\n");
    }

    byte pemCert[8000];
    printf("Before DerToPem\n");
    int pemSz = wc_DerToPem(derCert, certSz, pemCert, sizeof(pemCert), CERT_TYPE);
    if (pemSz < 0) {
        printf("Error in DER to PEM conversion\n");
    }

    printf("PEM cert: \n%s\n", pemCert);
    return ret;     
}