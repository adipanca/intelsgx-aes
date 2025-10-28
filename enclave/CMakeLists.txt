# =========================
# enclave/CMakeLists.txt
# =========================
cmake_minimum_required(VERSION 3.16)

# -------- Options --------
option(HAVE_TSEAL       "Enable sealing (needs sgx_tseal or sgx_tservice)" ON)
option(ENABLE_KMS_HMAC  "Enable HMAC opcode support"                        ON)
option(USE_HMAC_KID     "Select HMAC key by KID inside enclave"             ON)

# -------- Names/paths --------
set(ENCLAVE_NAME Enclave)
set(ENCLAVE_EDL  ${CMAKE_CURRENT_SOURCE_DIR}/Enclave.edl)

set(EDGER8R_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/edger8r)
file(MAKE_DIRECTORY ${EDGER8R_GEN_DIR})

# -------- SGX toolchain vars from parent --------
if (NOT DEFINED SGX_SDK)
  message(FATAL_ERROR "SGX_SDK not set (pass -DSGX_SDK=$ENV{SGX_SDK})")
endif()
if (NOT DEFINED SGX_MODE)
  set(SGX_MODE "SIM")
endif()
if (NOT DEFINED SGX_EDGER8R)
  find_program(SGX_EDGER8R NAMES sgx_edger8r HINTS ${SGX_SDK}/bin ${SGX_SDK}/bin/x64)
  if (NOT SGX_EDGER8R)
    message(FATAL_ERROR "sgx_edger8r not found; set SGX_EDGER8R or ensure in ${SGX_SDK}/bin(/x64)")
  endif()
endif()

message(STATUS "SGX_SDK      = ${SGX_SDK}")
message(STATUS "SGX_MODE     = ${SGX_MODE}")
message(STATUS "SGX_EDGER8R  = ${SGX_EDGER8R}")

# -------- edger8r (trusted) --------
add_custom_command(
  OUTPUT ${EDGER8R_GEN_DIR}/Enclave_t.c ${EDGER8R_GEN_DIR}/Enclave_t.h
  COMMAND ${SGX_EDGER8R} --trusted ${ENCLAVE_EDL}
          --search-path ${SGX_SDK}/include
          --search-path ${SGX_SDK}/include/tlibc
          --search-path ${SGX_SDK}/include/libcxx
          --trusted-dir ${EDGER8R_GEN_DIR}
  DEPENDS ${ENCLAVE_EDL}
  COMMENT "edger8r (trusted) generating Enclave_t.[ch]"
)

# -------- Sources --------
set(ENCLAVE_SRC
  ${CMAKE_CURRENT_SOURCE_DIR}/Enclave.cpp
  ${EDGER8R_GEN_DIR}/Enclave_t.c
)

# Build as OBJECT first (so we can control CFLAGS)
add_library(${ENCLAVE_NAME}_obj OBJECT ${ENCLAVE_SRC})
target_include_directories(${ENCLAVE_NAME}_obj PRIVATE
  ${SGX_SDK}/include
  ${SGX_SDK}/include/tlibc
  ${SGX_SDK}/include/libcxx
  ${EDGER8R_GEN_DIR}
)

target_compile_options(${ENCLAVE_NAME}_obj PRIVATE
  -fPIC
  -fno-stack-protector
  -U_FORTIFY_SOURCE
  -fvisibility=hidden
  -Wno-attributes
)

# Macro definitions for enclave code
target_compile_definitions(${ENCLAVE_NAME}_obj PRIVATE
  $<$<BOOL:${ENABLE_KMS_HMAC}>:ENABLE_KMS_HMAC=1>
  $<$<BOOL:${USE_HMAC_KID}>:USE_HMAC_KID=1>
  $<$<BOOL:${HAVE_TSEAL}>:HAVE_TSEAL=1>
)

# -------- Trusted libs & mode --------
set(TRUSTED_LIB_DIR ${SGX_SDK}/lib64)
if (SGX_MODE STREQUAL "HW")
  set(TRTS_LIB sgx_trts)
else()
  set(TRTS_LIB sgx_trts_sim)
endif()

# Optional C++ runtime (some SDKs provide libsgx_tcxx, some not)
set(HAVE_TCXX OFF)
if (EXISTS "${TRUSTED_LIB_DIR}/libsgx_tcxx.a")
  set(HAVE_TCXX ON)
endif()

# Sealing library autodetect
set(SEAL_LIB "")
if (HAVE_TSEAL)
  if (EXISTS "${TRUSTED_LIB_DIR}/libsgx_tseal.a")
    set(SEAL_LIB sgx_tseal)
  elseif (EXISTS "${TRUSTED_LIB_DIR}/libsgx_tservice.a")
    set(SEAL_LIB sgx_tservice)
  else()
    message(STATUS "Sealing requested but libsgx_tseal/tservice not found; disabling HAVE_TSEAL")
    set(HAVE_TSEAL OFF)
  endif()
endif()

# -------- Build unsigned enclave (shared) --------
add_library(${ENCLAVE_NAME} SHARED $<TARGET_OBJECTS:${ENCLAVE_NAME}_obj>)
set_target_properties(${ENCLAVE_NAME} PROPERTIES OUTPUT_NAME "Enclave")
target_link_directories(${ENCLAVE_NAME} PRIVATE ${TRUSTED_LIB_DIR})

# Link & ldflags for enclave
target_link_options(${ENCLAVE_NAME} PRIVATE
  -nostdlib -nodefaultlibs -nostartfiles
  -Wl,-Bsymbolic
  -Wl,--no-undefined
  -Wl,-pie,-eenclave_entry
  -Wl,--export-dynamic
  -Wl,--defsym,__ImageBase=0
  -Wl,-z,noexecstack
)

# Core trusted libs (order matters)
target_link_libraries(${ENCLAVE_NAME} PRIVATE
  -Wl,--whole-archive ${TRTS_LIB} -Wl,--no-whole-archive
  -Wl,--start-group
    sgx_tstdc
    sgx_tcrypto
    $<$<BOOL:${HAVE_TCXX}>:sgx_tcxx>
    $<$<BOOL:${HAVE_TSEAL}>:${SEAL_LIB}>
  -Wl,--end-group
)

# -------- Signing --------
find_program(SGX_SIGN NAMES sgx_sign HINTS ${SGX_SDK}/bin ${SGX_SDK}/bin/x64)
if (NOT SGX_SIGN)
  message(FATAL_ERROR "sgx_sign not found in ${SGX_SDK}/bin(/x64)")
endif()

set(ENCLAVE_CONFIG ${CMAKE_CURRENT_SOURCE_DIR}/Enclave.config.xml)
set(ENCLAVE_KEY    ${CMAKE_CURRENT_BINARY_DIR}/Enclave_private.pem)

add_custom_command(
  OUTPUT ${ENCLAVE_KEY}
  COMMAND ${CMAKE_COMMAND} -E echo "Generating enclave key (RSA-3072, e=3) ..."
  COMMAND openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -pkeyopt rsa_keygen_pubexp:3 -out ${ENCLAVE_KEY}
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  COMMENT "Generating ${ENCLAVE_KEY}"
  VERBATIM
)

add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${ENCLAVE_NAME}.signed.so
  COMMAND ${SGX_SIGN} sign
          -key ${ENCLAVE_KEY}
          -enclave $<TARGET_FILE:${ENCLAVE_NAME}>
          -out ${CMAKE_CURRENT_BINARY_DIR}/${ENCLAVE_NAME}.signed.so
          -config ${ENCLAVE_CONFIG}
  DEPENDS ${ENCLAVE_NAME} ${ENCLAVE_CONFIG} ${ENCLAVE_KEY}
  COMMENT "Signing enclave -> ${ENCLAVE_NAME}.signed.so"
  VERBATIM
)

add_custom_target(${ENCLAVE_NAME}_signed ALL
  DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${ENCLAVE_NAME}.signed.so
)

# Export paths back to parent
set(ENCLAVE_SIGNED_PATH ${CMAKE_CURRENT_BINARY_DIR}/${ENCLAVE_NAME}.signed.so PARENT_SCOPE)
set(EDGER8R_GEN_DIR     ${EDGER8R_GEN_DIR} PARENT_SCOPE)
