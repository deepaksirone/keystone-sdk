#include <sys/types.h>
#include <stdint.h>
#include <cyassl/ctaocrypt/rsa.h>

int generate_attested_cert_with_evidence(
    const unsigned char* subject_name,
    const void* optional_parameters,
    size_t optional_parameters_size,
    uint8_t** output_certificate,
    size_t* output_certificate_size) {

    RsaKey genKey;
    RNG    rng;
    int    ret;

    InitRng(&rng);
    InitRsaKey(&genKey, 0);

    ret = MakeRsaKey(&genKey, 1024, 65537, &rng);
    

    return ret;

         
}