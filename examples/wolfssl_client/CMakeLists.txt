set(eapp_bin wolfssl_client)
set(eapp_src eapp/wolfssl_client.c eapp/edge_wrapper.c)
set(host_bin wolfssl_client-runner)
set(host_src host/enclave-host.cpp host/edge_wrapper.cpp)
set(package_name "wolfssl_client.ke")
set(package_script "./wolfssl_client-runner wolfssl_client eyrie-rt")

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

# host

add_executable(${host_bin} ${host_src})
target_link_libraries(${host_bin} "-static" ${KEYSTONE_LIB_HOST} ${KEYSTONE_LIB_EDGE})


# add target for Eyrie runtime (see keystone.cmake)

set(eyrie_files_to_copy .options_log eyrie-rt)
add_eyrie_runtime(${eapp_bin}-eyrie
  "2ce55797786def8a029c6456f0d9b6173efb2914"
  ${eyrie_plugins}
  ${eyrie_files_to_copy})

# add target for packaging (see keystone.cmake)

add_keystone_package(${eapp_bin}-package
  ${package_name}
  ${package_script}
  ${eyrie_files_to_copy} ${eapp_bin} ${host_bin})

add_dependencies(${eapp_bin}-package ${eapp_bin}-wolfssl ${eapp_bin}-eyrie)

# add package to the top-level target
add_dependencies(examples ${eapp_bin}-package)
