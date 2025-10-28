# =========================
# host/CMakeLists.txt
# =========================
cmake_minimum_required(VERSION 3.16)

project(host_agent C CXX)

# Var dari parent:
# - SGX_SDK
# - SGX_MODE (SIM/HW)
# - ENCLAVE_SIGNED_PATH (path Enclave.signed.so hasil sign)
# - (opsional) SGX_EDGER8R; kalau tidak, kita cari otomatis

if (NOT DEFINED SGX_SDK)
  message(FATAL_ERROR "SGX_SDK not set")
endif()
if (NOT DEFINED SGX_MODE)
  set(SGX_MODE "SIM")
endif()

# Cari sgx_edger8r bila belum diset
if (NOT DEFINED SGX_EDGER8R)
  find_program(SGX_EDGER8R NAMES sgx_edger8r HINTS ${SGX_SDK}/bin ${SGX_SDK}/bin/x64)
  if (NOT SGX_EDGER8R)
    message(FATAL_ERROR "sgx_edger8r tidak ditemukan; set SGX_EDGER8R atau pastikan ada di ${SGX_SDK}/bin(/x64)")
  endif()
endif()

# Path EDL (asumsi berada di ../enclave/Enclave.edl dari folder host/)
set(ENCLAVE_EDL_PATH ${CMAKE_SOURCE_DIR}/enclave/Enclave.edl)
if (NOT EXISTS "${ENCLAVE_EDL_PATH}")
  message(FATAL_ERROR "Tidak menemukan ${ENCLAVE_EDL_PATH}")
endif()

# Direktori output untuk Enclave_u.[ch]
set(U_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/edger8r)
file(MAKE_DIRECTORY ${U_GEN_DIR})

# === Generate Enclave_u.[ch] (untrusted) ===
add_custom_command(
  OUTPUT ${U_GEN_DIR}/Enclave_u.c ${U_GEN_DIR}/Enclave_u.h
  COMMAND ${SGX_EDGER8R} --untrusted ${ENCLAVE_EDL_PATH}
          --search-path ${SGX_SDK}/include
          --search-path ${SGX_SDK}/include/tlibc
          --search-path ${SGX_SDK}/include/libcxx
          --untrusted-dir ${U_GEN_DIR}
  DEPENDS ${ENCLAVE_EDL_PATH}
  COMMENT "edger8r (untrusted) generating Enclave_u.[ch]"
)

add_custom_target(edger8r_untrusted ALL
  DEPENDS ${U_GEN_DIR}/Enclave_u.c ${U_GEN_DIR}/Enclave_u.h
)

# ===== Sumber host =====
set(HOST_SRC
  ${CMAKE_CURRENT_SOURCE_DIR}/agent.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/HostIO.cpp     # <= pastikan baris ini ada
  ${U_GEN_DIR}/Enclave_u.c
)


add_executable(sgx-agent ${HOST_SRC})
add_dependencies(sgx-agent Enclave_signed)
add_dependencies(sgx-agent edger8r_untrusted)

target_compile_features(sgx-agent PRIVATE cxx_std_11)
target_include_directories(sgx-agent PRIVATE
  ${U_GEN_DIR}
  ${SGX_SDK}/include
)

# ===== Link ke host libs SGX =====
set(SGX_HOST_LIB_DIRS
  ${SGX_SDK}/sdk_libs
  ${SGX_SDK}/lib64
)
foreach(D ${SGX_HOST_LIB_DIRS})
  if (EXISTS "${D}")
    target_link_directories(sgx-agent PRIVATE ${D})
  endif()
endforeach()

set(HAVE_URTS_SIM FALSE)
set(HAVE_UAE_SIM  FALSE)
set(HAVE_URTS     FALSE)
set(HAVE_UAE      FALSE)

foreach(D ${SGX_HOST_LIB_DIRS})
  if (EXISTS "${D}/libsgx_urts_sim.so")
    set(HAVE_URTS_SIM TRUE)
  endif()
  if (EXISTS "${D}/libsgx_uae_service_sim.so")
    set(HAVE_UAE_SIM TRUE)
  endif()
  if (EXISTS "${D}/libsgx_urts.so")
    set(HAVE_URTS TRUE)
  endif()
  if (EXISTS "${D}/libsgx_uae_service.so")
    set(HAVE_UAE TRUE)
  endif()
endforeach()

set(LINK_LIBS pthread dl)
if (SGX_MODE STREQUAL "SIM")
  if (HAVE_URTS_SIM AND HAVE_UAE_SIM)
    list(APPEND LINK_LIBS sgx_urts_sim sgx_uae_service_sim)
    message(STATUS "Linking against SIM host libs: sgx_urts_sim, sgx_uae_service_sim")
  elseif (HAVE_URTS AND HAVE_UAE)
    message(WARNING "SIM mode diminta tapi lib SIM tidak ada; fallback ke HW host libs")
    list(APPEND LINK_LIBS sgx_urts sgx_uae_service)
  else()
    message(FATAL_ERROR "Host libs SGX tidak ditemukan (SIM/HW). Cek ${SGX_SDK}/sdk_libs dan ${SGX_SDK}/lib64")
  endif()
else()
  if (HAVE_URTS AND HAVE_UAE)
    list(APPEND LINK_LIBS sgx_urts sgx_uae_service)
    message(STATUS "Linking against HW host libs: sgx_urts, sgx_uae_service")
  elseif (HAVE_URTS_SIM AND HAVE_UAE_SIM)
    message(WARNING "HW mode diminta tapi HW libs tidak ada; fallback ke SIM")
    list(APPEND LINK_LIBS sgx_urts_sim sgx_uae_service_sim)
  else()
    message(FATAL_ERROR "Host libs SGX tidak ditemukan untuk mode ${SGX_MODE}")
  endif()
endif()

target_link_libraries(sgx-agent PRIVATE ${LINK_LIBS})

# Copy Enclave.signed.so ke direktori binary host agar mudah ditemukan saat runtime
# Salin Enclave.signed.so ke folder binary host setelah build
if (DEFINED ENCLAVE_SIGNED_PATH)
  add_custom_command(TARGET sgx-agent POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${ENCLAVE_SIGNED_PATH}
            $<TARGET_FILE_DIR:sgx-agent>/Enclave.signed.so
    COMMENT "Copy Enclave.signed.so next to sgx-agent"
  )
endif()

target_compile_definitions(sgx-agent PRIVATE
  ENABLE_KMS_HMAC=1
  USE_HMAC_KID=1
)
