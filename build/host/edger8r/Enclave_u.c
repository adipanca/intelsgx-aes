#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_e_encrypt_t {
	int ms_retval;
	uint8_t* ms_p;
	size_t ms_len_p;
	uint8_t* ms_aad;
	size_t ms_len_a;
	uint8_t* ms_out;
	size_t ms_len_out;
	size_t* ms_written;
} ms_e_encrypt_t;

typedef struct ms_e_decrypt_t {
	int ms_retval;
	uint8_t* ms_blob;
	size_t ms_len_b;
	uint8_t* ms_aad;
	size_t ms_len_a;
	uint8_t* ms_out;
	size_t ms_len_out;
	size_t* ms_written;
} ms_e_decrypt_t;

typedef struct ms_e_hmac_sha256_kid_t {
	int ms_retval;
	uint32_t ms_kid;
	uint8_t* ms_data;
	size_t ms_data_len;
	uint8_t* ms_mac32;
} ms_e_hmac_sha256_kid_t;

typedef struct ms_e_hmac_sha256_t {
	int ms_retval;
	uint8_t* ms_key;
	size_t ms_key_len;
	uint8_t* ms_data;
	size_t ms_data_len;
	uint8_t* ms_mac32;
} ms_e_hmac_sha256_t;

typedef struct ms_u_read_file_t {
	int ms_retval;
	const char* ms_path;
	uint8_t* ms_buf;
	size_t ms_maxlen;
	size_t* ms_outlen;
} ms_u_read_file_t;

typedef struct ms_u_write_file_t {
	int ms_retval;
	const char* ms_path;
	uint8_t* ms_buf;
	size_t ms_len;
} ms_u_write_file_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL Enclave_u_read_file(void* pms)
{
	ms_u_read_file_t* ms = SGX_CAST(ms_u_read_file_t*, pms);
	ms->ms_retval = u_read_file(ms->ms_path, ms->ms_buf, ms->ms_maxlen, ms->ms_outlen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_write_file(void* pms)
{
	ms_u_write_file_t* ms = SGX_CAST(ms_u_write_file_t*, pms);
	ms->ms_retval = u_write_file(ms->ms_path, ms->ms_buf, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[7];
} ocall_table_Enclave = {
	7,
	{
		(void*)Enclave_u_read_file,
		(void*)Enclave_u_write_file,
		(void*)Enclave_sgx_oc_cpuidex,
		(void*)Enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)Enclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t e_init(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t e_encrypt(sgx_enclave_id_t eid, int* retval, uint8_t* p, size_t len_p, uint8_t* aad, size_t len_a, uint8_t* out, size_t len_out, size_t* written)
{
	sgx_status_t status;
	ms_e_encrypt_t ms;
	ms.ms_p = p;
	ms.ms_len_p = len_p;
	ms.ms_aad = aad;
	ms.ms_len_a = len_a;
	ms.ms_out = out;
	ms.ms_len_out = len_out;
	ms.ms_written = written;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t e_decrypt(sgx_enclave_id_t eid, int* retval, uint8_t* blob, size_t len_b, uint8_t* aad, size_t len_a, uint8_t* out, size_t len_out, size_t* written)
{
	sgx_status_t status;
	ms_e_decrypt_t ms;
	ms.ms_blob = blob;
	ms.ms_len_b = len_b;
	ms.ms_aad = aad;
	ms.ms_len_a = len_a;
	ms.ms_out = out;
	ms.ms_len_out = len_out;
	ms.ms_written = written;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t e_hmac_sha256_kid(sgx_enclave_id_t eid, int* retval, uint32_t kid, uint8_t* data, size_t data_len, uint8_t* mac32)
{
	sgx_status_t status;
	ms_e_hmac_sha256_kid_t ms;
	ms.ms_kid = kid;
	ms.ms_data = data;
	ms.ms_data_len = data_len;
	ms.ms_mac32 = mac32;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t e_hmac_sha256(sgx_enclave_id_t eid, int* retval, uint8_t* key, size_t key_len, uint8_t* data, size_t data_len, uint8_t* mac32)
{
	sgx_status_t status;
	ms_e_hmac_sha256_t ms;
	ms.ms_key = key;
	ms.ms_key_len = key_len;
	ms.ms_data = data;
	ms.ms_data_len = data_len;
	ms.ms_mac32 = mac32;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

