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

int generate_attested_cert_with_evidence(
    const unsigned char* subject_name,
    const void* optional_parameters,
    size_t optional_parameters_size,
    uint8_t** output_certificate,
    size_t* output_certificate_size) {

    RsaKey genKey;
    RNG    rng;
    int    ret;

    wc_InitRng(&rng);
    wc_InitRsaKey(&genKey, 0);

    ret = wc_MakeRsaKey(&genKey, 1024, 65537, &rng);
    
    

    return ret;

         
}