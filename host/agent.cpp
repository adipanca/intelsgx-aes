#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <vector>
#include <string>
#include <algorithm>

#include "sgx_urts.h"
#include "Enclave_u.h"

// ---------- Konfigurasi ----------
static const char* kDefaultSockPath     = "/run/aead-kms.sock"; // override via ENV KMS_SOCK_PATH
static const char* kDefaultEnclavePath  = "Enclave.signed.so";
static const char* kSealDir             = "/var/lib/sgx-agent";
static sgx_enclave_id_t g_eid = 0;

// ---------- SGX error helper ----------
static const char* sgx_errstr(sgx_status_t s) {
    switch (s) {
    case SGX_SUCCESS: return "SGX_SUCCESS";
    case SGX_ERROR_INVALID_ENCLAVE_ID: return "SGX_ERROR_INVALID_ENCLAVE_ID";
    case SGX_ERROR_ENCLAVE_LOST: return "SGX_ERROR_ENCLAVE_LOST";
    case SGX_ERROR_INVALID_PARAMETER: return "SGX_ERROR_INVALID_PARAMETER";
    case SGX_ERROR_OUT_OF_MEMORY: return "SGX_ERROR_OUT_OF_MEMORY";
    case SGX_ERROR_ENCLAVE_FILE_ACCESS: return "SGX_ERROR_ENCLAVE_FILE_ACCESS";
    case SGX_ERROR_UNEXPECTED: return "SGX_ERROR_UNEXPECTED";
    case SGX_ERROR_NO_DEVICE: return "SGX_ERROR_NO_DEVICE";
    case SGX_ERROR_SERVICE_UNAVAILABLE: return "SGX_ERROR_SERVICE_UNAVAILABLE";
    case SGX_ERROR_SERVICE_TIMEOUT: return "SGX_ERROR_SERVICE_TIMEOUT";
    case SGX_ERROR_NETWORK_FAILURE: return "SGX_ERROR_NETWORK_FAILURE";
    case SGX_ERROR_DEVICE_BUSY: return "SGX_ERROR_DEVICE_BUSY";
    default: return "SGX_ERROR_* (unknown)";
    }
}

// ---------- Util path/env ----------
static std::string get_sock_path() {
    const char* p = ::getenv("KMS_SOCK_PATH");
    return (p && *p) ? std::string(p) : std::string(kDefaultSockPath);
}
static std::string dir_of(const std::string& p) {
    auto pos = p.find_last_of('/');
    if (pos == std::string::npos) return ".";
    if (pos == 0) return "/";
    return p.substr(0, pos);
}
static int mkdir_p(const char* path, mode_t mode) {
    if (!path || !*path) return -1;
    std::string cur;
    if (path[0] == '/') cur = "/";
    const char* s = path;
    while (*s) {
        const char* slash = strchr(s, '/');
        std::string part;
        if (slash) part.assign(s, slash - s);
        else part.assign(s);
        if (!part.empty()) {
            if (cur.size() > 1) cur += "/";
            cur += part;
            struct stat st{};
            if (stat(cur.c_str(), &st) < 0) {
                if (errno == ENOENT) {
                    if (mkdir(cur.c_str(), mode) < 0 && errno != EEXIST) {
                        perror("[AGENT] mkdir");
                        return -1;
                    }
                } else {
                    perror("[AGENT] stat");
                    return -1;
                }
            } else if (!S_ISDIR(st.st_mode)) {
                fprintf(stderr, "[AGENT] %s exists but not a directory\n", cur.c_str());
                return -1;
            }
        }
        if (!slash) break;
        s = slash + 1;
    }
    return 0;
}

// ---------- Util IO ----------
static ssize_t readn(int fd, void* buf, size_t n) {
    uint8_t* p = (uint8_t*)buf;
    size_t left = n;
    while (left > 0) {
        ssize_t r = ::read(fd, p, left);
        if (r == 0) return (ssize_t)(n - left);   // EOF
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += r;
        left -= (size_t)r;
    }
    return (ssize_t)n;
}
static ssize_t writen(int fd, const void* buf, size_t n) {
    const uint8_t* p = (const uint8_t*)buf;
    size_t left = n;
    while (left > 0) {
        ssize_t w = ::write(fd, p, left);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += w;
        left -= (size_t)w;
    }
    return (ssize_t)n;
}
static uint32_t hton32(uint32_t x) {
    return ((x & 0x000000FFu) << 24) |
           ((x & 0x0000FF00u) << 8)  |
           ((x & 0x00FF0000u) >> 8)  |
           ((x & 0xFF000000u) >> 24);
}
static uint32_t ntoh32(uint32_t x) { return hton32(x); }

// ---------- Logging helpers ----------
static void dump_prefix(const uint8_t* buf, size_t n) {
    fprintf(stderr, "[AGENT] rx:");
    for (size_t i=0;i<n;i++) fprintf(stderr, " %02X", buf[i]);
    fprintf(stderr, "\n");
}
static void log_req(const char* what, uint8_t op, uint32_t kid, uint32_t aad_len, uint32_t in_len, size_t written) {
    fprintf(stderr, "[AGENT] %s op=0x%02X kid=%u aad=%u in=%u out=%zu\n",
            what, op, kid, aad_len, in_len, written);
}

// ---------- Protokol ----------
// Header (kecuali PING):
// [1B op] [4B kid_be] [4B aad_len_be] [4B in_len_be] [aad bytes] [in bytes]
// Response: [4B out_len_be] [payload]; Error: out_len_be = 0xFFFFFFFF

static int send_error(int fd) {
    uint32_t be = hton32(0xFFFFFFFFu);
    return (writen(fd, &be, 4) == 4) ? 0 : -1;
}

// ---------- Handler ----------
static int handle_client(int cfd) {
    for (;;) {
        uint8_t op = 0;
        ssize_t rr = readn(cfd, &op, 1);
        if (rr == 0) return 0; // EOF normal
        if (rr != 1) return -1;

        // PING: 'P' atau 0x01 tanpa header
        if (op == 'P' || op == 0x01) {
            uint32_t be0 = hton32(0u);
            if (writen(cfd, &be0, 4) != 4) return -1;
            continue;
        }

        // Header umum
        uint32_t be_kid=0, be_aad_len=0, be_in_len=0;
        if (readn(cfd, &be_kid, 4) != 4) return -1;
        if (readn(cfd, &be_aad_len, 4) != 4) return -1;
        if (readn(cfd, &be_in_len, 4) != 4) return -1;

        uint32_t kid     = ntoh32(be_kid);
        uint32_t aad_len = ntoh32(be_aad_len);
        uint32_t in_len  = ntoh32(be_in_len);

        if (aad_len > (32 * 1024) || in_len > (4 * 1024 * 1024)) {
            (void)send_error(cfd);
            fprintf(stderr, "[AGENT] reject: aad_len=%u in_len=%u (too large)\n", aad_len, in_len);
            return -1;
        }

        std::vector<uint8_t> aad(aad_len);
        if (aad_len && readn(cfd, aad.data(), aad_len) != (ssize_t)aad_len) return -1;

        std::vector<uint8_t> in(in_len);
        if (in_len && readn(cfd, in.data(), in_len) != (ssize_t)in_len) return -1;

        // ===== ENC =====
        if (op == 'E' || op == 0x03) {
            std::vector<uint8_t> out((size_t)in_len + 12 + 16);
            size_t written = 0;
            int retval = -1;

            sgx_status_t st = e_encrypt(
                g_eid, &retval,
                in.data(),  in.size(),
                aad.data(), aad.size(),
                out.data(), out.size(),
                &written
            );
            if (st != SGX_SUCCESS || retval != 0) {
                fprintf(stderr, "[AGENT] e_encrypt failed: sgx=%s(0x%x) retval=%d\n",
                        sgx_errstr(st), st, retval);
                (void)send_error(cfd);
                continue;
            }

            log_req("ENC OK", op, kid, aad_len, in_len, written);

            uint32_t be_out = hton32((uint32_t)written);
            if (writen(cfd, &be_out, 4) != 4) return -1;
            if (writen(cfd, out.data(), written) != (ssize_t)written) return -1;
            continue;
        }

        // ===== DEC =====
        if (op == 'D' || op == 0x04) {
            if (in_len < 12 + 16) {
                (void)send_error(cfd);
                if (in_len > 0) // diamkan health-check yang mengirim 0
                    fprintf(stderr, "[AGENT] decrypt reject: blob too short (%u)\n", in_len);
                continue;
            }

            size_t pt_cap = in_len - 12 - 16;
            std::vector<uint8_t> out(pt_cap ? pt_cap : 1);
            size_t written = 0;
            int retval = -1;

            // 1) coba layout standar: IV || CT || TAG
            sgx_status_t st = e_decrypt(
                g_eid, &retval,
                in.data(),  in.size(),
                aad.data(), aad.size(),
                out.data(), out.size(),
                &written
            );

            if (st != SGX_SUCCESS || retval != 0) {
                // 2) fallback: IV || TAG || CT
                const size_t iv_len = 12, tag_len = 16, ct_len = in_len - iv_len - tag_len;
                if (ct_len > 0) {
                    std::vector<uint8_t> blob2(in_len);
                    // IV
                    memcpy(blob2.data(), in.data(), iv_len);
                    // CT setelah IV
                    memcpy(blob2.data()+iv_len, in.data()+iv_len+tag_len, ct_len);
                    // TAG di akhir
                    memcpy(blob2.data()+iv_len+ct_len, in.data()+iv_len, tag_len);

                    written = 0; retval = -1;
                    st = e_decrypt(
                        g_eid, &retval,
                        blob2.data(), blob2.size(),
                        aad.data(),  aad.size(),
                        out.data(),  out.size(),
                        &written
                    );
                }
            }

            if (st != SGX_SUCCESS || retval != 0) {
                fprintf(stderr, "[AGENT] e_decrypt failed after fallback: sgx=%s(0x%x) retval=%d\n",
                        sgx_errstr(st), st, retval);
                (void)send_error(cfd);
                continue;
            }

            log_req("DEC OK", op, kid, aad_len, in_len, written);

            uint32_t be_out = hton32((uint32_t)written);
            if (writen(cfd, &be_out, 4) != 4) return -1;
            if (written && writen(cfd, out.data(), written) != (ssize_t)written) return -1;
            continue;
        }

        // ===== HMAC (opsional) =====
        // ===== HMAC (agnostik: 0x05/0x06) =====
        if (op == 'H' || op == 0x05 || op == 0x06) {
        #ifndef ENABLE_KMS_HMAC
            fprintf(stderr, "[AGENT] HMAC op received but ENABLE_KMS_HMAC not set; returning error\n");
            (void)send_error(cfd);
            continue;
        #else
            std::vector<uint8_t> mac(32);
            sgx_status_t st = SGX_ERROR_UNEXPECTED;
            int retval = -1;

            if (aad_len > 0) {
                // key dikirim via AAD
                st = e_hmac_sha256(
                    g_eid, &retval,
                    /*key*/  aad.data(), aad.size(),
                    /*data*/ in.data(),  in.size(),
                    /*out*/  mac.data()
                );
                fprintf(stderr, "[AGENT] HMAC(AAD) op=0x%02X kid=%u key=%uB data=%uB\n",
                        op, kid, aad_len, in_len);
            } else {
                // key dipilih by KID
                st = e_hmac_sha256_kid(
                    g_eid, &retval,
                    /*kid*/  kid,
                    /*data*/ in.data(), in.size(),
                    /*out*/  mac.data()
                );
                fprintf(stderr, "[AGENT] HMAC(KID) op=0x%02X kid=%u data=%uB\n",
                        op, kid, in_len);
            }

            if (st != SGX_SUCCESS || retval != 0) {
                fprintf(stderr, "[AGENT] e_hmac_sha256(_kid) failed: sgx=%s(0x%x) retval=%d (kid=%u aad_len=%u in_len=%u)\n",
                        sgx_errstr(st), st, retval, kid, aad_len, in_len);
                (void)send_error(cfd);
                continue;
            }

            uint32_t be_out = hton32((uint32_t)mac.size());
            if (writen(cfd, &be_out, 4) != 4) return -1;
            if (writen(cfd, mac.data(), mac.size()) != (ssize_t)mac.size()) return -1;
            continue;
        #endif
        }




        // ===== Unknown op =====
        {
            uint8_t hdr[13];
            hdr[0] = op;
            memcpy(&hdr[1], &be_kid, 4);
            memcpy(&hdr[5], &be_aad_len, 4);
            memcpy(&hdr[9], &be_in_len, 4);
            dump_prefix(hdr, sizeof(hdr));
            fprintf(stderr, "[AGENT] unknown op=0x%02X ('%c')\n", op, (op>=32 && op<127)?op:'.');
            (void)send_error(cfd);
            continue;
        }
    }
}

// ---------- Inisialisasi enclave ----------
static int create_enclave(const char* enclave_path) {
    sgx_launch_token_t token = {0};
    int updated = 0;
    uint32_t flags = SGX_DEBUG_FLAG; // 0 untuk release

    sgx_status_t st = sgx_create_enclave(enclave_path, flags, &token, &updated, &g_eid, NULL);
    if (st != SGX_SUCCESS) {
        fprintf(stderr, "[AGENT] sgx_create_enclave('%s') failed: %s(0x%x)\n",
                enclave_path, sgx_errstr(st), st);
        return -1;
    }
    fprintf(stderr, "[AGENT] enclave created: eid=%llu (updated=%d)\n",
            (unsigned long long)g_eid, updated);
    return 0;
}
static int ensure_seal_dir() {
    struct stat st{};
    if (stat(kSealDir, &st) == 0) {
        if (!S_ISDIR(st.st_mode)) {
            fprintf(stderr, "[AGENT] %s exists but is not a directory\n", kSealDir);
            return -1;
        }
        return 0;
    }
    if (mkdir(kSealDir, 0750) < 0) {
        perror("[AGENT] mkdir seal dir");
        return -1;
    }
    return 0;
}
static int enclave_init_once() {
    sgx_status_t st = e_init(g_eid); // sesuaikan jika e_init punya argumen
    if (st != SGX_SUCCESS) {
        fprintf(stderr, "[AGENT] e_init failed: %s(0x%x)\n", sgx_errstr(st), st);
        return -1;
    }
    fprintf(stderr, "[AGENT] e_init OK (KEK siap)\n");
    return 0;
}

// ---------- Main ----------
int main(int argc, char** argv) {
    ::signal(SIGPIPE, SIG_IGN);

    const char* enclave_path = (argc >= 2) ? argv[1] : kDefaultEnclavePath;

    if (ensure_seal_dir() != 0) {
        fprintf(stderr, "[AGENT] abort: seal dir not ready: %s\n", kSealDir);
        return 1;
    }
    if (create_enclave(enclave_path) != 0) {
        fprintf(stderr, "[AGENT] abort: enclave create failed\n");
        return 1;
    }
    if (enclave_init_once() != 0) {
        fprintf(stderr, "[AGENT] abort: enclave init failed\n");
        sgx_destroy_enclave(g_eid);
        return 1;
    }

    std::string spath = get_sock_path();
    if (mkdir_p(dir_of(spath).c_str(), 0770) != 0) {
        fprintf(stderr, "[AGENT] abort: cannot create socket dir: %s\n", dir_of(spath).c_str());
        sgx_destroy_enclave(g_eid);
        return 1;
    }

    ::unlink(spath.c_str());

    int sfd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (sfd < 0) { perror("socket"); sgx_destroy_enclave(g_eid); return 1; }

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    ::strncpy(addr.sun_path, spath.c_str(), sizeof(addr.sun_path) - 1);

    if (::bind(sfd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        ::close(sfd);
        sgx_destroy_enclave(g_eid);
        return 1;
    }

    ::chmod(spath.c_str(), 0660);

    if (::listen(sfd, 16) < 0) {
        perror("listen");
        ::close(sfd);
        ::unlink(spath.c_str());
        sgx_destroy_enclave(g_eid);
        return 1;
    }

    fprintf(stderr, "[AGENT] listening on %s\n", spath.c_str());

    for (;;) {
        int cfd = ::accept(sfd, nullptr, nullptr);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            break;
        }
        int flags = fcntl(cfd, F_GETFD);
        if (flags >= 0) fcntl(cfd, F_SETFD, flags | FD_CLOEXEC);

        (void)handle_client(cfd);
        ::close(cfd);
    }

    ::close(sfd);
    ::unlink(spath.c_str());
    sgx_destroy_enclave(g_eid);
    return 0;
}
