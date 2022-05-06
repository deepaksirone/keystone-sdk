#ifndef _H_KEYSTONE_CERT_H
#define _H_KEYSTONE_CERT_H

int generate_attested_cert_with_evidence(
    const unsigned char* subject_name,
    const void* optional_parameters,
    size_t optional_parameters_size,
    uint8_t** output_certificate,
    size_t* output_certificate_size);

#endif