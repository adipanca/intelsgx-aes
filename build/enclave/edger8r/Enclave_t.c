#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_e_init(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	e_init();
	return status;
}

static sgx_status_t SGX_CDECL sgx_e_encrypt(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_e_encrypt_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_e_encrypt_t* ms = SGX_CAST(ms_e_encrypt_t*, pms);
	ms_e_encrypt_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_e_encrypt_t), ms, sizeof(ms_e_encrypt_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_p = __in_ms.ms_p;
	size_t _tmp_len_p = __in_ms.ms_len_p;
	size_t _len_p = _tmp_len_p;
	uint8_t* _in_p = NULL;
	uint8_t* _tmp_aad = __in_ms.ms_aad;
	size_t _tmp_len_a = __in_ms.ms_len_a;
	size_t _len_aad = _tmp_len_a;
	uint8_t* _in_aad = NULL;
	uint8_t* _tmp_out = __in_ms.ms_out;
	size_t _tmp_len_out = __in_ms.ms_len_out;
	size_t _len_out = _tmp_len_out;
	uint8_t* _in_out = NULL;
	size_t* _tmp_written = __in_ms.ms_written;
	size_t _len_written = sizeof(size_t);
	size_t* _in_written = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_p, _len_p);
	CHECK_UNIQUE_POINTER(_tmp_aad, _len_aad);
	CHECK_UNIQUE_POINTER(_tmp_out, _len_out);
	CHECK_UNIQUE_POINTER(_tmp_written, _len_written);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_p != NULL && _len_p != 0) {
		if ( _len_p % sizeof(*_tmp_p) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_p = (uint8_t*)malloc(_len_p);
		if (_in_p == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_p, _len_p, _tmp_p, _len_p)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_aad != NULL && _len_aad != 0) {
		if ( _len_aad % sizeof(*_tmp_aad) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_aad = (uint8_t*)malloc(_len_aad);
		if (_in_aad == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_aad, _len_aad, _tmp_aad, _len_aad)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_out != NULL && _len_out != 0) {
		if ( _len_out % sizeof(*_tmp_out) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_out = (uint8_t*)malloc(_len_out)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_out, 0, _len_out);
	}
	if (_tmp_written != NULL && _len_written != 0) {
		if ( _len_written % sizeof(*_tmp_written) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_written = (size_t*)malloc(_len_written)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_written, 0, _len_written);
	}
	_in_retval = e_encrypt(_in_p, _tmp_len_p, _in_aad, _tmp_len_a, _in_out, _tmp_len_out, _in_written);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_out) {
		if (memcpy_verw_s(_tmp_out, _len_out, _in_out, _len_out)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_written) {
		if (memcpy_verw_s(_tmp_written, _len_written, _in_written, _len_written)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_p) free(_in_p);
	if (_in_aad) free(_in_aad);
	if (_in_out) free(_in_out);
	if (_in_written) free(_in_written);
	return status;
}

static sgx_status_t SGX_CDECL sgx_e_decrypt(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_e_decrypt_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_e_decrypt_t* ms = SGX_CAST(ms_e_decrypt_t*, pms);
	ms_e_decrypt_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_e_decrypt_t), ms, sizeof(ms_e_decrypt_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_blob = __in_ms.ms_blob;
	size_t _tmp_len_b = __in_ms.ms_len_b;
	size_t _len_blob = _tmp_len_b;
	uint8_t* _in_blob = NULL;
	uint8_t* _tmp_aad = __in_ms.ms_aad;
	size_t _tmp_len_a = __in_ms.ms_len_a;
	size_t _len_aad = _tmp_len_a;
	uint8_t* _in_aad = NULL;
	uint8_t* _tmp_out = __in_ms.ms_out;
	size_t _tmp_len_out = __in_ms.ms_len_out;
	size_t _len_out = _tmp_len_out;
	uint8_t* _in_out = NULL;
	size_t* _tmp_written = __in_ms.ms_written;
	size_t _len_written = sizeof(size_t);
	size_t* _in_written = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_blob, _len_blob);
	CHECK_UNIQUE_POINTER(_tmp_aad, _len_aad);
	CHECK_UNIQUE_POINTER(_tmp_out, _len_out);
	CHECK_UNIQUE_POINTER(_tmp_written, _len_written);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_blob != NULL && _len_blob != 0) {
		if ( _len_blob % sizeof(*_tmp_blob) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_blob = (uint8_t*)malloc(_len_blob);
		if (_in_blob == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_blob, _len_blob, _tmp_blob, _len_blob)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_aad != NULL && _len_aad != 0) {
		if ( _len_aad % sizeof(*_tmp_aad) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_aad = (uint8_t*)malloc(_len_aad);
		if (_in_aad == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_aad, _len_aad, _tmp_aad, _len_aad)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_out != NULL && _len_out != 0) {
		if ( _len_out % sizeof(*_tmp_out) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_out = (uint8_t*)malloc(_len_out)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_out, 0, _len_out);
	}
	if (_tmp_written != NULL && _len_written != 0) {
		if ( _len_written % sizeof(*_tmp_written) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_written = (size_t*)malloc(_len_written)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_written, 0, _len_written);
	}
	_in_retval = e_decrypt(_in_blob, _tmp_len_b, _in_aad, _tmp_len_a, _in_out, _tmp_len_out, _in_written);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_out) {
		if (memcpy_verw_s(_tmp_out, _len_out, _in_out, _len_out)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_written) {
		if (memcpy_verw_s(_tmp_written, _len_written, _in_written, _len_written)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_blob) free(_in_blob);
	if (_in_aad) free(_in_aad);
	if (_in_out) free(_in_out);
	if (_in_written) free(_in_written);
	return status;
}

static sgx_status_t SGX_CDECL sgx_e_hmac_sha256_kid(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_e_hmac_sha256_kid_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_e_hmac_sha256_kid_t* ms = SGX_CAST(ms_e_hmac_sha256_kid_t*, pms);
	ms_e_hmac_sha256_kid_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_e_hmac_sha256_kid_t), ms, sizeof(ms_e_hmac_sha256_kid_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_data = __in_ms.ms_data;
	size_t _tmp_data_len = __in_ms.ms_data_len;
	size_t _len_data = _tmp_data_len;
	uint8_t* _in_data = NULL;
	uint8_t* _tmp_mac32 = __in_ms.ms_mac32;
	size_t _len_mac32 = 32;
	uint8_t* _in_mac32 = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_data, _len_data);
	CHECK_UNIQUE_POINTER(_tmp_mac32, _len_mac32);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_data != NULL && _len_data != 0) {
		if ( _len_data % sizeof(*_tmp_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_data = (uint8_t*)malloc(_len_data);
		if (_in_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_data, _len_data, _tmp_data, _len_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_mac32 != NULL && _len_mac32 != 0) {
		if ( _len_mac32 % sizeof(*_tmp_mac32) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_mac32 = (uint8_t*)malloc(_len_mac32)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_mac32, 0, _len_mac32);
	}
	_in_retval = e_hmac_sha256_kid(__in_ms.ms_kid, _in_data, _tmp_data_len, _in_mac32);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_mac32) {
		if (memcpy_verw_s(_tmp_mac32, _len_mac32, _in_mac32, _len_mac32)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_data) free(_in_data);
	if (_in_mac32) free(_in_mac32);
	return status;
}

static sgx_status_t SGX_CDECL sgx_e_hmac_sha256(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_e_hmac_sha256_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_e_hmac_sha256_t* ms = SGX_CAST(ms_e_hmac_sha256_t*, pms);
	ms_e_hmac_sha256_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_e_hmac_sha256_t), ms, sizeof(ms_e_hmac_sha256_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_key = __in_ms.ms_key;
	size_t _tmp_key_len = __in_ms.ms_key_len;
	size_t _len_key = _tmp_key_len;
	uint8_t* _in_key = NULL;
	uint8_t* _tmp_data = __in_ms.ms_data;
	size_t _tmp_data_len = __in_ms.ms_data_len;
	size_t _len_data = _tmp_data_len;
	uint8_t* _in_data = NULL;
	uint8_t* _tmp_mac32 = __in_ms.ms_mac32;
	size_t _len_mac32 = 32;
	uint8_t* _in_mac32 = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_key, _len_key);
	CHECK_UNIQUE_POINTER(_tmp_data, _len_data);
	CHECK_UNIQUE_POINTER(_tmp_mac32, _len_mac32);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_key != NULL && _len_key != 0) {
		if ( _len_key % sizeof(*_tmp_key) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_key = (uint8_t*)malloc(_len_key);
		if (_in_key == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_key, _len_key, _tmp_key, _len_key)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_data != NULL && _len_data != 0) {
		if ( _len_data % sizeof(*_tmp_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_data = (uint8_t*)malloc(_len_data);
		if (_in_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_data, _len_data, _tmp_data, _len_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_mac32 != NULL && _len_mac32 != 0) {
		if ( _len_mac32 % sizeof(*_tmp_mac32) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_mac32 = (uint8_t*)malloc(_len_mac32)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_mac32, 0, _len_mac32);
	}
	_in_retval = e_hmac_sha256(_in_key, _tmp_key_len, _in_data, _tmp_data_len, _in_mac32);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_mac32) {
		if (memcpy_verw_s(_tmp_mac32, _len_mac32, _in_mac32, _len_mac32)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_key) free(_in_key);
	if (_in_data) free(_in_data);
	if (_in_mac32) free(_in_mac32);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[5];
} g_ecall_table = {
	5,
	{
		{(void*)(uintptr_t)sgx_e_init, 0, 0},
		{(void*)(uintptr_t)sgx_e_encrypt, 0, 0},
		{(void*)(uintptr_t)sgx_e_decrypt, 0, 0},
		{(void*)(uintptr_t)sgx_e_hmac_sha256_kid, 0, 0},
		{(void*)(uintptr_t)sgx_e_hmac_sha256, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[7][5];
} g_dyn_entry_table = {
	7,
	{
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL u_read_file(int* retval, const char* path, uint8_t* buf, size_t maxlen, size_t* outlen)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_path = path ? strlen(path) + 1 : 0;
	size_t _len_buf = maxlen;
	size_t _len_outlen = sizeof(size_t);

	ms_u_read_file_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_read_file_t);
	void *__tmp = NULL;

	void *__tmp_buf = NULL;
	void *__tmp_outlen = NULL;

	CHECK_ENCLAVE_POINTER(path, _len_path);
	CHECK_ENCLAVE_POINTER(buf, _len_buf);
	CHECK_ENCLAVE_POINTER(outlen, _len_outlen);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (path != NULL) ? _len_path : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (outlen != NULL) ? _len_outlen : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_read_file_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_read_file_t));
	ocalloc_size -= sizeof(ms_u_read_file_t);

	if (path != NULL) {
		if (memcpy_verw_s(&ms->ms_path, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_path % sizeof(*path) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, path, _len_path)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_path);
		ocalloc_size -= _len_path;
	} else {
		ms->ms_path = NULL;
	}

	if (buf != NULL) {
		if (memcpy_verw_s(&ms->ms_buf, sizeof(uint8_t*), &__tmp, sizeof(uint8_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_buf = __tmp;
		if (_len_buf % sizeof(*buf) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}

	if (memcpy_verw_s(&ms->ms_maxlen, sizeof(ms->ms_maxlen), &maxlen, sizeof(maxlen))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (outlen != NULL) {
		if (memcpy_verw_s(&ms->ms_outlen, sizeof(size_t*), &__tmp, sizeof(size_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_outlen = __tmp;
		if (_len_outlen % sizeof(*outlen) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_outlen, 0, _len_outlen);
		__tmp = (void *)((size_t)__tmp + _len_outlen);
		ocalloc_size -= _len_outlen;
	} else {
		ms->ms_outlen = NULL;
	}

	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (outlen) {
			if (memcpy_s((void*)outlen, _len_outlen, __tmp_outlen, _len_outlen)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_write_file(int* retval, const char* path, uint8_t* buf, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_path = path ? strlen(path) + 1 : 0;
	size_t _len_buf = len;

	ms_u_write_file_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_write_file_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(path, _len_path);
	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (path != NULL) ? _len_path : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_write_file_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_write_file_t));
	ocalloc_size -= sizeof(ms_u_write_file_t);

	if (path != NULL) {
		if (memcpy_verw_s(&ms->ms_path, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_path % sizeof(*path) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, path, _len_path)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_path);
		ocalloc_size -= _len_path;
	} else {
		ms->ms_path = NULL;
	}

	if (buf != NULL) {
		if (memcpy_verw_s(&ms->ms_buf, sizeof(uint8_t*), &__tmp, sizeof(uint8_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_buf % sizeof(*buf) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, buf, _len_buf)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}

	if (memcpy_verw_s(&ms->ms_len, sizeof(ms->ms_len), &len, sizeof(len))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(int);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;

	CHECK_ENCLAVE_POINTER(cpuinfo, _len_cpuinfo);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (cpuinfo != NULL) ? _len_cpuinfo : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));
	ocalloc_size -= sizeof(ms_sgx_oc_cpuidex_t);

	if (cpuinfo != NULL) {
		if (memcpy_verw_s(&ms->ms_cpuinfo, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_cpuinfo = __tmp;
		if (_len_cpuinfo % sizeof(*cpuinfo) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		ocalloc_size -= _len_cpuinfo;
	} else {
		ms->ms_cpuinfo = NULL;
	}

	if (memcpy_verw_s(&ms->ms_leaf, sizeof(ms->ms_leaf), &leaf, sizeof(leaf))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_subleaf, sizeof(ms->ms_subleaf), &subleaf, sizeof(subleaf))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) {
			if (memcpy_s((void*)cpuinfo, _len_cpuinfo, __tmp_cpuinfo, _len_cpuinfo)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);

	if (memcpy_verw_s(&ms->ms_self, sizeof(ms->ms_self), &self, sizeof(self))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);

	if (memcpy_verw_s(&ms->ms_waiter, sizeof(ms->ms_waiter), &waiter, sizeof(waiter))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);

	if (memcpy_verw_s(&ms->ms_waiter, sizeof(ms->ms_waiter), &waiter, sizeof(waiter))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_self, sizeof(ms->ms_self), &self, sizeof(self))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(waiters, _len_waiters);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (waiters != NULL) ? _len_waiters : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);

	if (waiters != NULL) {
		if (memcpy_verw_s(&ms->ms_waiters, sizeof(const void**), &__tmp, sizeof(const void**))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_waiters % sizeof(*waiters) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, waiters, _len_waiters)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		ocalloc_size -= _len_waiters;
	} else {
		ms->ms_waiters = NULL;
	}

	if (memcpy_verw_s(&ms->ms_total, sizeof(ms->ms_total), &total, sizeof(total))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

