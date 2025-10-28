#include "Enclave_t.h"
#include <sgx_trts.h>
#include <sgx_tcrypto.h>
#include <string.h>
#include <stdlib.h>

#ifdef HAVE_TSEAL
#  include <sgx_tseal.h>
#endif

#define KEK_SIZE 32
#define IV_LEN   12
#define TAG_LEN  16
#define PT_MAX   (4 * 1024 * 1024)  // selaras dengan agent

static uint8_t g_kek[KEK_SIZE];
static bool    g_kek_ready = false;
static const char* SEAL_PATH = "/var/lib/sgx-agent/kek.seal";

// TODO: ganti dengan tabel kunci nyata yang diisi saat e_init()
// misal: std::array<std::array<uint8_t,32>, MAX_KEYS> g_keys;
static uint8_t g_demo_key_32[32] = {
    0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
    0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,
    0x10,0x20,0x30,0x40,0x50,0x60,0x70,0x80,
    0x90,0xa0,0xb0,0xc0,0xd0,0xe0,0xf0,0x01
};

extern "C" int e_hmac_sha256_kid(uint32_t kid,
                                 uint8_t* data, size_t data_len,
                                 uint8_t* mac32) {
    (void)kid; // TODO: pilih key berdasarkan kid
    if (!data || !mac32) return -1;

    const uint8_t* key = g_demo_key_32;
    const uint32_t key_len = 32;

    uint32_t mac_len = 32;
    sgx_status_t st = sgx_hmac_sha256_msg(
        data, (uint32_t)data_len,
        key,  key_len,
        mac32, mac_len
    );
    return (st == SGX_SUCCESS) ? 0 : -1;
}

extern "C" int e_hmac_sha256(uint8_t* key, size_t key_len,
                             uint8_t* data, size_t data_len,
                             uint8_t* mac32) {
    if (!key || key_len == 0 || !data || !mac32) return -1;

    uint32_t mac_len = 32;
    sgx_status_t st = sgx_hmac_sha256_msg(
        data, (uint32_t)data_len,
        key,  (uint32_t)key_len,
        mac32, mac_len
    );
    return (st == SGX_SUCCESS) ? 0 : -1;
}


static int load_or_create_kek() {
#ifdef HAVE_TSEAL
    uint8_t buf[4096];
    size_t got = 0;

    int oc_ret = -1;
    sgx_status_t st = u_read_file(&oc_ret, SEAL_PATH, buf, sizeof(buf), &got);
    if (st == SGX_SUCCESS && oc_ret == 0 && got >= sizeof(sgx_sealed_data_t)) {
        uint32_t plain_len = sgx_get_encrypt_txt_len((const sgx_sealed_data_t*)buf);
        if (plain_len == KEK_SIZE) {
            uint32_t out_len = KEK_SIZE;
            if (sgx_unseal_data((const sgx_sealed_data_t*)buf, NULL, 0, g_kek, &out_len) == SGX_SUCCESS) {
                g_kek_ready = true;
                return 0;
            }
        }
    }

    sgx_read_rand(g_kek, KEK_SIZE);

    uint32_t seal_sz = sgx_calc_sealed_data_size(0, KEK_SIZE);
    if (seal_sz == UINT32_MAX) return -1;
    uint8_t* seal_buf = (uint8_t*)malloc(seal_sz);
    if (!seal_buf) return -2;

    if (sgx_seal_data(0, NULL, KEK_SIZE, g_kek, seal_sz, (sgx_sealed_data_t*)seal_buf) != SGX_SUCCESS) {
        free(seal_buf);
        return -3;
    }
    oc_ret = -1;
    st = u_write_file(&oc_ret, SEAL_PATH, seal_buf, seal_sz);
    free(seal_buf);
    if (st != SGX_SUCCESS || oc_ret != 0) return -4;

    g_kek_ready = true;
    return 0;
#else
    // Fallback sementara: generate KEK setiap startup (TIDAK persist)
    sgx_read_rand(g_kek, KEK_SIZE);
    g_kek_ready = true;
    return 0;
#endif
}

extern "C" void e_init() {
    if (!g_kek_ready) (void)load_or_create_kek();
}

extern "C" int e_encrypt(uint8_t* p, size_t len_p,
                         uint8_t* aad, size_t len_a,
                         uint8_t* out, size_t len_out,
                         size_t* written)
{
    if (!g_kek_ready) return -1;
    if (len_p > PT_MAX) return -2;
    if (len_out < IV_LEN + len_p + TAG_LEN) return -3;

    uint8_t* iv  = out;
    uint8_t* ct  = out + IV_LEN;
    uint8_t* tag = out + IV_LEN + len_p;

    sgx_read_rand(iv, IV_LEN);

    sgx_aes_gcm_128bit_key_t key128;
    memcpy(&key128, g_kek, 16);

    sgx_status_t st = sgx_rijndael128GCM_encrypt(
        &key128, p, (uint32_t)len_p, ct,
        iv, IV_LEN, aad, (uint32_t)len_a,
        (sgx_aes_gcm_128bit_tag_t*)tag
    );
    if (st != SGX_SUCCESS) return -4;

    *written = IV_LEN + len_p + TAG_LEN;
    return 0;
}

extern "C" int e_decrypt(uint8_t* blob, size_t len_b,
                         uint8_t* aad, size_t len_a,
                         uint8_t* out, size_t len_out,
                         size_t* written)
{
    if (!g_kek_ready) return -1;
    if (len_b < IV_LEN + TAG_LEN) return -2;

    size_t ct_len = len_b - IV_LEN - TAG_LEN;
    if (len_out < ct_len) return -3;

    uint8_t* iv  = blob;
    uint8_t* ct  = blob + IV_LEN;
    uint8_t* tag = blob + IV_LEN + ct_len;

    sgx_aes_gcm_128bit_key_t key128;
    memcpy(&key128, g_kek, 16);

    sgx_status_t st = sgx_rijndael128GCM_decrypt(
        &key128, ct, (uint32_t)ct_len, out,
        iv, IV_LEN, aad, (uint32_t)len_a,
        (const sgx_aes_gcm_128bit_tag_t*)tag
    );
    if (st != SGX_SUCCESS) return -4;

    *written = ct_len;
    return 0;
}
