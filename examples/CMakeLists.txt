enable_language(C CXX ASM)

include(../macros.cmake)
include(ExternalProject)
find_package(Git REQUIRED)

if(RISCV32)
  message(STATUS "riscv32")
  set(BITS 32)
else()
  message(STATUS "riscv64")
  set(BITS 64)
endif()

#use_riscv_toolchain(${BITS})
use_riscv_musl_toolchain(${BITS})

# check if SDK has been built and KEYSTONE_SDK_DIR environment variable exists
if (NOT DEFINED ENV{KEYSTONE_SDK_DIR})
  message(FATAL_ERROR "Please set KEYSTONE_SDK_DIR environment variable to an installed SDK path")
endif()

set(KEYSTONE_SDK_DIR $ENV{KEYSTONE_SDK_DIR})

# export include directory
include_directories(AFTER ${KEYSTONE_SDK_DIR}/include)
# TODO: Fix this
include_directories(AFTER ${KEYSTONE_SDK_DIR}/include/host
			  ${KEYSTONE_SDK_DIR}/include/edge
  		          ${KEYSTONE_SDK_DIR}/include/verifier)
		          


# set paths to the libraries
set(KEYSTONE_LIB_HOST ${KEYSTONE_SDK_DIR}/lib/libkeystone-host.a)
set(KEYSTONE_LIB_EDGE ${KEYSTONE_SDK_DIR}/lib/libkeystone-edge.a)
set(KEYSTONE_LIB_VERIFIER ${KEYSTONE_SDK_DIR}/lib/libkeystone-verifier.a)
set(KEYSTONE_LIB_EAPP ${KEYSTONE_SDK_DIR}/lib/libkeystone-eapp.a)

# find program "makeself"
find_program(MAKESELF makeself)

# create a phony target "examples"
add_custom_target("examples")

# add all examples below
#add_subdirectory(hello)
#add_subdirectory(hello-native)
#add_subdirectory(attestation)
#add_subdirectory(tests)
#add_subdirectory(hello_new)
#add_subdirectory(wolfssl_client)

# All eapps below are needed for the artifact

#add_subdirectory(ntp_client)
#add_subdirectory(keystore)
#add_subdirectory(encrypted_rule)
#add_subdirectory(rule_process)
