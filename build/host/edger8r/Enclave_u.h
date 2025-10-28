#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef U_READ_FILE_DEFINED__
#define U_READ_FILE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_read_file, (const char* path, uint8_t* buf, size_t maxlen, size_t* outlen));
#endif
#ifndef U_WRITE_FILE_DEFINED__
#define U_WRITE_FILE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_write_file, (const char* path, uint8_t* buf, size_t len));
#endif
#ifndef SGX_OC_CPUIDEX_DEFINED__
#define SGX_OC_CPUIDEX_DEFINED__
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
#endif
#ifndef SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
#endif
#ifndef SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
#endif
#ifndef SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
#endif
#ifndef SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
#endif

sgx_status_t e_init(sgx_enclave_id_t eid);
sgx_status_t e_encrypt(sgx_enclave_id_t eid, int* retval, uint8_t* p, size_t len_p, uint8_t* aad, size_t len_a, uint8_t* out, size_t len_out, size_t* written);
sgx_status_t e_decrypt(sgx_enclave_id_t eid, int* retval, uint8_t* blob, size_t len_b, uint8_t* aad, size_t len_a, uint8_t* out, size_t len_out, size_t* written);
sgx_status_t e_hmac_sha256_kid(sgx_enclave_id_t eid, int* retval, uint32_t kid, uint8_t* data, size_t data_len, uint8_t* mac32);
sgx_status_t e_hmac_sha256(sgx_enclave_id_t eid, int* retval, uint8_t* key, size_t key_len, uint8_t* data, size_t data_len, uint8_t* mac32);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
