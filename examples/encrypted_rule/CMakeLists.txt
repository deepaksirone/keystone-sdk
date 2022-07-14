set(eapp_bin enc_rule)
set(eapp_src eapp/enc_rule.c eapp/edge_wrapper.c eapp/message.c)
set(host_bin enc_rule-runner)
set(host_src host/enclave-host.cpp host/edge_wrapper.cpp)
set(package_name "enc_rule.ke")
set(package_script "./enc_rule-runner enc_rule.enc eyrie-rt")

add_definitions(-DDEBUG_RULE -DHAVE_THREAD_LS -DNDEBUG -DNO_DO178 -DSINGLE_THREADED -DTFM_TIMING_RESISTANT -DECC_TIMING_RESISTANT -DWC_RSA_BLINDING -DWOLFSSL_USE_ALIGN -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DSESSION_CERTS -DHAVE_HKDF -DNO_DSA -DHAVE_ECC -DTFM_ECC256 -DECC_SHAMIR -DWC_RSA_PSS -DWOLFSSL_ASN_TEMPLATE -DHAVE_POLY1305 -DHAVE_CHACHA -DHAVE_HASHDRBG -DNO_FILESYSTEM -DHAVE_TLS_EXTENSIONS -DHAVE_SUPPORTED_CURVES -DHAVE_FFDHE_2048 -DHAVE_SUPPORTED_CURVES -DWOLFSSL_TLS13 -DHAVE_TLS_EXTENSIONS -DHAVE_EXTENDED_MASTER -DNO_RC4 -DHAVE_ENCRYPT_THEN_MAC -DNO_PSK -DNO_MD4 -DWC_NO_ASYNC_THREADING -DHAVE_DH_DEFAULT_PARAMS -DWOLFSSL_KEY_GEN -DWOLFSSL_CERT_REQ -DWOLFSSL_CERT_GEN -DWOLFSSL_CERT_EXT -DNO_DES3 -DGCM_TABLE_4BIT -DHAVE_AESGCM -DHAVE_TLS_EXTENSIONS -DHAVE_SERVER_RENEGOTIATION_INFO  -DHAVE___UINT128_T=1 -DHAVE_WC_INTROSPECTION -DCUSTOM_RAND_GENERATE=rand_gen_keystone -DCUSTOM_RAND_TYPE=uintptr_t -DWOLFSSL_SMALL_STACK -DKEYSTONE -DWOLFSSL_CUSTOM_OID -DHAVE_OID_ENCODING -DHAVE_OID_DECODING -DOPENSSL_EXTRA -DWOLFSSL_SMALL_STACK -DWOLFSSL_CUSTOM_OID -DHAVE_OID_ENCODING -DHAVE_OID_DECODING -DOPENSSL_EXTRA -DWOLFSSL_VERIFY_CB_ALL_CERTS -DWOLFSSL_ALWAYS_VERIFY_CB -DWOLFSSL_NO_ASN_STRICT)

if(RISCV32)
  set(eyrie_plugins "freemem untrusted_io_syscall linux_syscall env_setup rv32")
else()
  set(eyrie_plugins "freemem untrusted_io_syscall linux_syscall env_setup")
endif()

# Library dependencies for the eapp bin
include("./libs.cmake")

# Add include directory
include_directories(include)
#include_directories(${KEYSTONE_SDK_DIR}/include/app)

# eapp
add_executable(${eapp_bin} ${eapp_src})
add_dependencies(${eapp_bin} ${eapp_bin}-wolfssl)
set_target_properties(${eapp_bin}
  PROPERTIES LINK_FLAGS "-static -T ${CMAKE_CURRENT_SOURCE_DIR}/app.lds")
target_link_libraries(${eapp_bin} "-static" 
			      ${KEYSTONE_LIB_EDGE}
                              ${KEYSTONE_LIB_EAPP}
			      ${WOLFSSL_LIB}
			      "-lm")
add_cryptor(${eapp_bin})
add_dependencies(${eapp_bin}-cryptor ${eapp_bin})

# host

add_executable(${host_bin} ${host_src})
target_link_libraries(${host_bin} "-static" ${KEYSTONE_LIB_HOST} ${KEYSTONE_LIB_EDGE})


# add target for Eyrie runtime (see keystone.cmake)

set(eyrie_files_to_copy .options_log eyrie-rt)
add_eyrie_runtime(${eapp_bin}-eyrie
  "f8acd1fef36c8010ab6339b655b89e524546bca7"
  ${eyrie_plugins}
  ${eyrie_files_to_copy})

# add target for packaging (see keystone.cmake)

add_keystone_package(${eapp_bin}-package
  ${package_name}
  ${package_script}
  ${eyrie_files_to_copy} ${eapp_bin}.enc ${host_bin})

add_dependencies(${eapp_bin}-package ${eapp_bin}-wolfssl ${eapp_bin}-eyrie ${eapp_bin}-cryptor)

# add package to the top-level target
add_dependencies(examples ${eapp_bin}-package)
