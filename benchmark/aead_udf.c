// aead_udf.c - MySQL UDF: AEAD_ENCRYPT_DEFAULT, AEAD_DECRYPT_DEFAULT, HMAC_SHA256_DEFAULT
// Build example:
//   gcc -Wall -Wextra -fPIC -O2 -I/usr/include/mysql aead_udf.c -shared -o aead.so \
//       $(mysql_config --libs) -lssl -lcrypto

#include <mysql.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <string.h>
#include <strings.h>     // strcasecmp
#include <unistd.h>      // close, read, write
#include <arpa/inet.h>   // htonl, ntohl
#include <sys/socket.h>
#include <sys/un.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>

/* ===== MySQL/MariaDB UDF compatibility ===== */
#ifndef MYSQL_VERSION_ID
#define MYSQL_VERSION_ID 80000
#endif
#if MYSQL_VERSION_ID >= 80000
  #define MYSQL_BOOL bool
#else
  #define MYSQL_BOOL my_bool
#endif

/* ===== Config ===== */
#define NONCE_LEN   12
#define TAG_LEN     16
#define MAX_PLAIN   1024
#define MAX_AAD     512
#define MAX_CTEXT   (MAX_PLAIN + TAG_LEN)
#define MAX_BLOB    (NONCE_LEN + MAX_CTEXT)

/* Key backend mode via env: AEAD_KMS_MODE = "FILE" or "AGENT" */
static const char *ENV_KMS_MODE       = "AEAD_KMS_MODE";
static const char *DEFAULT_KEYS_JSON  = "/etc/aead_keys.json";
// static const char *DEFAULT_AGENT_SOCK = "/hostrun/aead-kms.sock"; // IN-CONTAINER default
static const char *DEFAULT_AGENT_SOCK = "/hostrun/aead-kms/aead-kms.sock"; // IN-CONTAINER default (sesuai docker volume)


/* ===== Key struct (avoid conflict with system key_t) ===== */
typedef struct {
    unsigned char kbytes[32];   /* 256-bit key */
    size_t        klen;
} aead_key_t;

/* ===== Forward declarations ===== */
static int hex2bin(const char *hex, unsigned char *out, size_t *outlen, size_t maxout);
static int load_key_from_file(int kid, aead_key_t *k);
static int agent_call(const char *op,
                      const unsigned char *in1, size_t in1_len,
                      const unsigned char *in2, size_t in2_len,
                      int kid,
                      unsigned char *out, size_t *out_len, size_t max_out);
static int get_key(int kid, aead_key_t *k);

static int aead_encrypt_local(const unsigned char *plain, size_t plen,
                              const unsigned char *aad, size_t aadlen,
                              int kid,
                              unsigned char *out_blob, size_t *outlen);
static int aead_decrypt_local(const unsigned char *blob, size_t blen,
                              const unsigned char *aad, size_t aadlen,
                              int kid,
                              unsigned char *plain, size_t *plen);
static int hmac_local(const unsigned char *msg, size_t mlen, int kid,
                      unsigned char out[32]);

static int get_int_arg(UDF_ARGS *args, int idx, int *out);
static int get_str_arg(UDF_ARGS *args, int idx, const unsigned char **p, size_t *n);

/* ===== Helpers ===== */
static int hex2bin(const char *hex, unsigned char *out, size_t *outlen, size_t maxout) {
    size_t n = strlen(hex);
    if (n % 2 != 0) return -1;
    if (n/2 > maxout) return -2;
    for (size_t i=0; i<n/2; i++) {
        unsigned int x = 0;
        if (sscanf(hex + 2*i, "%2x", &x) != 1) return -3;
        out[i] = (unsigned char)x;
    }
    *outlen = n/2;
    return 0;
}

static int load_key_from_file(int kid, aead_key_t *k) {
    FILE *fp = fopen(DEFAULT_KEYS_JSON, "r");
    if (!fp) return -1;
    char line[4096];
    int got = 0;
    char needle[32]; snprintf(needle, sizeof(needle), "\"%d\":\"", kid);
    while (fgets(line, sizeof(line), fp)) {
        char *p = strstr(line, needle);
        while (p) {
            p += strlen(needle);
            char *q = strchr(p, '"');
            if (!q) break;
            *q = 0;
            if (hex2bin(p, k->kbytes, &k->klen, sizeof(k->kbytes)) == 0 && k->klen == 32) {
                got = 1;
                break;
            }
            p = strstr(q+1, needle);
        }
        if (got) break;
    }
    fclose(fp);
    return got ? 0 : -2;
}

/* IPC to agent (AGENT mode) */
static int agent_call(const char *op,
                      const unsigned char *in1, size_t in1_len,
                      const unsigned char *in2, size_t in2_len,
                      int kid,
                      unsigned char *out, size_t *out_len, size_t max_out)
{
    /* Map op string to 1-byte opcode & tentukan mana AAD dan DATA sesuai agent */
    unsigned char opcode = 0;
    const unsigned char *aad = NULL, *data = NULL;
    size_t aad_len = 0, data_len = 0;

    if (strcasecmp(op, "ENC") == 0) {
        opcode  = 'E';           /* agent: 'E' atau 0x03; kita pakai 'E' */
        aad     = in2;           /* UDF: in1=plain, in2=aad → agent butuh aad dulu */
        aad_len = in2_len;
        data    = in1;           /* data (plaintext) belakangan */
        data_len= in1_len;
    } else if (strcasecmp(op, "DEC") == 0) {
        opcode  = 'D';           /* agent: 'D' atau 0x04 */
        aad     = in2;           /* UDF: in1=blob, in2=aad → agent butuh aad dulu */
        aad_len = in2_len;
        data    = in1;           /* data=blob (IV||CT||TAG) */
        data_len= in1_len;
    } else if (strcasecmp(op, "HMAC") == 0) {
        opcode  = 0x05;          /* agent-mu terima 0x05 (atau 'H' / 0x06). Pakai 0x05. */
        aad     = NULL;          /* HMAC by KID: aad kosong */
        aad_len = 0;
        data    = in1;           /* data = message */
        data_len= in1_len;
    } else {
        return -100;             /* op tak dikenal */
    }

    /* Open UNIX socket */
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_un addr; memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    const char *sock = getenv("AEAD_KMS_SOCK");
    if (!sock) sock = DEFAULT_AGENT_SOCK;
    if (strlen(sock) >= sizeof(addr.sun_path)) { close(fd); return -2; }
    strncpy(addr.sun_path, sock, sizeof(addr.sun_path)-1);

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) { close(fd); return -3; }

    /* Header: [1B op][4B kid_be][4B aad_len_be][4B data_len_be] */
    uint32_t be_kid = htonl((uint32_t)kid);
    uint32_t be_aad = htonl((uint32_t)aad_len);
    uint32_t be_dat = htonl((uint32_t)data_len);

    unsigned char hdr[1+4+4+4];
    hdr[0] = opcode;
    memcpy(hdr+1,  &be_kid, 4);
    memcpy(hdr+5,  &be_aad, 4);
    memcpy(hdr+9,  &be_dat, 4);

    /* Kirim header + AAD + DATA (urutan wajib demikian) */
    ssize_t w;
    w = write(fd, hdr, sizeof(hdr));            if (w != (ssize_t)sizeof(hdr)) { close(fd); return -4; }
    if (aad_len) {
        w = write(fd, aad, aad_len);            if (w != (ssize_t)aad_len)     { close(fd); return -5; }
    }
    if (data_len) {
        w = write(fd, data, data_len);          if (w != (ssize_t)data_len)    { close(fd); return -6; }
    }

    /* Baca out_len (big-endian). 0xFFFFFFFF berarti error dari agent. */
    uint32_t be_olen = 0;
    ssize_t r = read(fd, &be_olen, 4);
    if (r != 4) { close(fd); return -7; }

    uint32_t want = ntohl(be_olen);
    if (want == 0xFFFFFFFFu) { close(fd); return -8; }   /* agent signaled error */

    if (want > max_out) { close(fd); return -9; }

    size_t off = 0;
    while (off < want) {
        r = read(fd, out + off, want - off);
        if (r <= 0) { close(fd); return -10; }
        off += (size_t)r;
    }
    *out_len = want;
    close(fd);
    return 0;
}


static int get_key(int kid, aead_key_t *k) {
    const char *mode = getenv(ENV_KMS_MODE);
    if (!mode || strcasecmp(mode, "FILE")==0) {
        return load_key_from_file(kid, k);
    }
    if (strcasecmp(mode, "AGENT")==0) {
        /* AGENT mode: crypto done by agent; no key export. */
        return -99;
    }
    return load_key_from_file(kid, k);
}

/* ===== Local AEAD: ChaCha20-Poly1305 ===== */
static int aead_encrypt_local(const unsigned char *plain, size_t plen,
                              const unsigned char *aad, size_t aadlen,
                              int kid,
                              unsigned char *out_blob, size_t *outlen) {
    aead_key_t K;
    if (get_key(kid, &K) != 0) return -1;

    unsigned char nonce[NONCE_LEN];
    if (RAND_bytes(nonce, NONCE_LEN) != 1) return -2;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -3;

    int ok = 0, len=0, ctotal=0;
    unsigned char ctext[MAX_CTEXT];
    unsigned char tag[TAG_LEN];

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, NONCE_LEN, NULL) != 1) goto done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, K.kbytes, nonce) != 1) goto done;
    if (aad && aadlen) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aadlen) != 1) goto done;
    }
    if (EVP_EncryptUpdate(ctx, ctext, &len, plain, (int)plen) != 1) goto done;
    ctotal = len;
    if (EVP_EncryptFinal_ex(ctx, ctext + ctotal, &len) != 1) goto done;
    ctotal += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_LEN, tag) != 1) goto done;

    memcpy(out_blob, nonce, NONCE_LEN);
    memcpy(out_blob + NONCE_LEN, ctext, (size_t)ctotal);
    memcpy(out_blob + NONCE_LEN + (size_t)ctotal, tag, TAG_LEN);
    *outlen = NONCE_LEN + (size_t)ctotal + TAG_LEN;
    ok = 1;

done:
    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -4;
}

static int aead_decrypt_local(const unsigned char *blob, size_t blen,
                              const unsigned char *aad, size_t aadlen,
                              int kid,
                              unsigned char *plain, size_t *plen) {
    if (blen < NONCE_LEN + TAG_LEN) return -1;
    aead_key_t K;
    if (get_key(kid, &K) != 0) return -2;

    const unsigned char *nonce = blob;
    const unsigned char *ct    = blob + NONCE_LEN;
    size_t ctlen = blen - NONCE_LEN - TAG_LEN;
    const unsigned char *tag   = blob + blen - TAG_LEN;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -3;

    int ok=0, len=0, ptotal=0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, NONCE_LEN, NULL) != 1) goto done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, K.kbytes, nonce) != 1) goto done;
    if (aad && aadlen) {
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aadlen) != 1) goto done;
    }
    if (EVP_DecryptUpdate(ctx, plain, &len, ct, (int)ctlen) != 1) goto done;
    ptotal = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAG_LEN, (void*)tag) != 1) goto done;
    if (EVP_DecryptFinal_ex(ctx, plain + ptotal, &len) != 1) goto done;
    ptotal += len;
    *plen = (size_t)ptotal;
    ok = 1;

done:
    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -4;
}

static int hmac_local(const unsigned char *msg, size_t mlen, int kid,
                      unsigned char out[32]) {
    aead_key_t K;
    if (get_key(kid, &K) != 0) return -1;
    unsigned int olen=0;
    unsigned char *p = HMAC(EVP_sha256(), K.kbytes, (int)K.klen, msg, mlen, out, &olen);
    return (p && olen==32) ? 0 : -2;
}

/* --- helpers: robust int reader --- */
static int get_int_arg(UDF_ARGS *args, int idx, int *out) {
    if (idx >= (int)args->arg_count) return -1;
    if (!args->args[idx]) return -2;

    switch (args->arg_type[idx]) {
        case INT_RESULT: {
            long long v = *((long long*)args->args[idx]);
            *out = (int)v;
            return 0;
        }
        case STRING_RESULT: {
            char buf[32];
            size_t n = args->lengths[idx] < sizeof(buf)-1 ? args->lengths[idx] : sizeof(buf)-1;
            memcpy(buf, args->args[idx], n);
            buf[n] = '\0';
            char *end = NULL;
            long v = strtol(buf, &end, 10);
            if (end==buf) return -3;
            *out = (int)v;
            return 0;
        }
        default:
            return -4;
    }
}

static int get_str_arg(UDF_ARGS *args, int idx, const unsigned char **p, size_t *n) {
    if (idx >= (int)args->arg_count) return -1;
    if (!args->args[idx]) { *p=NULL; *n=0; return 0; }
    *p = (const unsigned char*)args->args[idx];
    *n = (size_t) args->lengths[idx];
    return 0;
}

/* ===== AEAD_ENCRYPT_DEFAULT(plain, aad, kid) ===== */
MYSQL_BOOL AEAD_ENCRYPT_DEFAULT_init(UDF_INIT *initid, UDF_ARGS *args, char *msg) {
    if (args->arg_count != 3) {
        strcpy(msg,"AEAD_ENCRYPT_DEFAULT(plain VARBINARY, aad VARBINARY, kid INT)");
        return 1;
    }
    /* force types to avoid kid being passed as string */
    args->arg_type[0] = STRING_RESULT;  // plain
    args->arg_type[1] = STRING_RESULT;  // aad
    args->arg_type[2] = INT_RESULT;     // kid

    initid->maybe_null = 0;
    initid->const_item = 0;
    initid->ptr = malloc(MAX_BLOB);
    if (!initid->ptr) { strcpy(msg, "malloc failed"); return 1; }
    return 0;
}

void AEAD_ENCRYPT_DEFAULT_deinit(UDF_INIT *initid) {
    if (initid->ptr) { free(initid->ptr); initid->ptr = NULL; }
}

char *AEAD_ENCRYPT_DEFAULT(UDF_INIT *initid, UDF_ARGS *args, char *result,
                           unsigned long *res_length, char *is_null, char *error) {
    (void)result; (void)is_null;
    const unsigned char *plain=NULL,*aad=NULL; size_t plen=0,aadlen=0; int kid=1;
    if (get_str_arg(args,0,&plain,&plen)!=0 || get_str_arg(args,1,&aad,&aadlen)!=0 ||
        get_int_arg(args,2,&kid)!=0) { *error=1; return NULL; }

    const char *mode = getenv(ENV_KMS_MODE);
    unsigned char *out = (unsigned char*)initid->ptr; size_t outlen=0;

    int rc;
    if (mode && strcasecmp(mode,"AGENT")==0) {
        rc = agent_call("ENC", plain, plen, aad, aadlen, kid, out, &outlen, MAX_BLOB);
    } else {
        rc = aead_encrypt_local(plain, plen, aad, aadlen, kid, out, &outlen);
    }
    if (rc!=0) { *error=1; return NULL; }
    *res_length = (unsigned long)outlen;
    return (char*)out;
}

/* ===== AEAD_DECRYPT_DEFAULT(blob, aad, kid) ===== */
MYSQL_BOOL AEAD_DECRYPT_DEFAULT_init(UDF_INIT *initid, UDF_ARGS *args, char *msg) {
    if (args->arg_count != 3) {
        strcpy(msg,"AEAD_DECRYPT_DEFAULT(blob VARBINARY, aad VARBINARY, kid INT)");
        return 1;
    }
    args->arg_type[0] = STRING_RESULT;  // blob
    args->arg_type[1] = STRING_RESULT;  // aad
    args->arg_type[2] = INT_RESULT;     // kid

    initid->maybe_null = 1;
    initid->const_item = 0;
    initid->ptr = malloc(MAX_PLAIN);
    if (!initid->ptr) { strcpy(msg, "malloc failed"); return 1; }
    return 0;
}

void AEAD_DECRYPT_DEFAULT_deinit(UDF_INIT *initid) {
    if (initid->ptr) { free(initid->ptr); initid->ptr = NULL; }
}

char *AEAD_DECRYPT_DEFAULT(UDF_INIT *initid, UDF_ARGS *args, char *result,
                           unsigned long *res_length, char *is_null, char *error) {
    (void)result;
    const unsigned char *blob=NULL,*aad=NULL; size_t blen=0,aadlen=0; int kid=1;
    if (get_str_arg(args,0,&blob,&blen)!=0 || get_str_arg(args,1,&aad,&aadlen)!=0 ||
        get_int_arg(args,2,&kid)!=0) { *error=1; return NULL; }

    const char *mode = getenv(ENV_KMS_MODE);
    unsigned char *out = (unsigned char*)initid->ptr; size_t outlen=0;

    int rc;
    if (mode && strcasecmp(mode,"AGENT")==0) {
        rc = agent_call("DEC", blob, blen, aad, aadlen, kid, out, &outlen, MAX_PLAIN);
    } else {
        rc = aead_decrypt_local(blob, blen, aad, aadlen, kid, out, &outlen);
    }
    if (rc!=0) { *is_null=1; *res_length=0; return NULL; }
    *res_length = (unsigned long)outlen;
    return (char*)out;
}

/* ===== HMAC_SHA256_DEFAULT(plain, kid) ===== */
MYSQL_BOOL HMAC_SHA256_DEFAULT_init(UDF_INIT *initid, UDF_ARGS *args, char *msg) {
    if (args->arg_count != 2) {
        strcpy(msg,"HMAC_SHA256_DEFAULT(plain VARBINARY, kid INT)");
        return 1;
    }
    args->arg_type[0] = STRING_RESULT;  // plain
    args->arg_type[1] = INT_RESULT;     // kid

    initid->maybe_null = 0;
    initid->const_item = 0;
    initid->ptr = malloc(32);
    if (!initid->ptr) { strcpy(msg, "malloc failed"); return 1; }
    return 0;
}

void HMAC_SHA256_DEFAULT_deinit(UDF_INIT *initid) {
    if (initid->ptr) { free(initid->ptr); initid->ptr = NULL; }
}

char *HMAC_SHA256_DEFAULT(UDF_INIT *initid, UDF_ARGS *args, char *result,
                          unsigned long *res_length, char *is_null, char *error) {
    (void)result; (void)is_null;
    const unsigned char *plain=NULL; size_t plen=0; int kid=1;
    if (get_str_arg(args,0,&plain,&plen)!=0 || get_int_arg(args,1,&kid)!=0) { *error=1; return NULL; }

    const char *mode = getenv(ENV_KMS_MODE);
    unsigned char *out = (unsigned char*)initid->ptr; size_t outlen=32; int rc;
    if (mode && strcasecmp(mode,"AGENT")==0) {
        rc = agent_call("HMAC", plain, plen, NULL, 0, kid, out, &outlen, 32);
        if (rc!=0 || outlen!=32) { *error=1; return NULL; }
    } else {
        rc = hmac_local(plain, plen, kid, out);
        if (rc!=0) { *error=1; return NULL; }
    }
    *res_length = 32;
    return (char*)out;
}
