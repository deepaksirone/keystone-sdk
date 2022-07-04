set(eapp_bin enc_rule)
set(eapp_src eapp/enc_rule eapp/edge_wrapper.c)
set(host_bin enc_rule-runner)
set(host_src host/enclave-host.cpp host/edge_wrapper.cpp)
set(package_name "enc_rule.ke")
set(package_script "./enc_rule-runner enc_rule.enc eyrie-rt")

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
  "aafae0f6f288cd8e9258260f353b3982b739e993"
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
