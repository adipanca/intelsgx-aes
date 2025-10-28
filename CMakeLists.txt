cmake_minimum_required(VERSION 3.16)
project(sgx_aead_agent C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(ENABLE_KMS_HMAC "Enable HMAC opcode support" ON)
option(USE_HMAC_KID    "Select HMAC key by KID inside enclave/host" ON)

# ----- SGX SDK root -----
if (NOT DEFINED SGX_SDK)
  # coba dari environment
  if (DEFINED ENV{SGX_SDK})
    set(SGX_SDK "$ENV{SGX_SDK}")
  else()
    set(SGX_SDK "/opt/intel/sgxsdk")
  endif()
endif()

# ----- SGX mode: SIM (default) / HW -----
if (NOT DEFINED SGX_MODE)
  set(SGX_MODE "SIM")
endif()

message(STATUS "SGX_SDK = ${SGX_SDK}")
message(STATUS "SGX_MODE = ${SGX_MODE}")

# ----- edger8r & sign tools (bin/x64 fallback) -----
if (EXISTS "${SGX_SDK}/bin/x64/sgx_edger8r")
  set(SGX_EDGER8R "${SGX_SDK}/bin/x64/sgx_edger8r")
else()
  set(SGX_EDGER8R "${SGX_SDK}/bin/sgx_edger8r")
endif()

find_program(SGX_SIGN NAMES sgx_sign HINTS
  ${SGX_SDK}/bin ${SGX_SDK}/bin/x64
)

if (NOT EXISTS ${SGX_EDGER8R})
  message(FATAL_ERROR "sgx_edger8r not found. Check SGX_SDK path: ${SGX_SDK}")
endif()
if (NOT SGX_SIGN)
  message(FATAL_ERROR "sgx_sign not found in ${SGX_SDK}/bin or bin/x64")
endif()

# ----- include dirs for both targets -----
include_directories(${SGX_SDK}/include)

add_subdirectory(enclave)
add_subdirectory(host)
