#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void e_init(void);
int e_encrypt(uint8_t* p, size_t len_p, uint8_t* aad, size_t len_a, uint8_t* out, size_t len_out, size_t* written);
int e_decrypt(uint8_t* blob, size_t len_b, uint8_t* aad, size_t len_a, uint8_t* out, size_t len_out, size_t* written);
int e_hmac_sha256_kid(uint32_t kid, uint8_t* data, size_t data_len, uint8_t* mac32);
int e_hmac_sha256(uint8_t* key, size_t key_len, uint8_t* data, size_t data_len, uint8_t* mac32);

sgx_status_t SGX_CDECL u_read_file(int* retval, const char* path, uint8_t* buf, size_t maxlen, size_t* outlen);
sgx_status_t SGX_CDECL u_write_file(int* retval, const char* path, uint8_t* buf, size_t len);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
