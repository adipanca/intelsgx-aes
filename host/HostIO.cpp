#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>

// Implementasi OCALL yang dipanggil enclave (lihat Enclave.edl):
//   int u_read_file([in, string] const char* path,
//                   [out, size=len] uint8_t* buf, size_t len,
//                   [out] size_t* got);
//   int u_write_file([in, string] const char* path,
//                    [in, size=len] const uint8_t* buf, size_t len);

extern "C" int u_read_file(const char* path, uint8_t* buf, size_t len, size_t* got) {
    if (!path || !buf || !got) return -1;
    *got = 0;

    int fd = ::open(path, O_RDONLY);
    if (fd < 0) return -2;

    size_t total = 0;
    while (total < len) {
        ssize_t r = ::read(fd, buf + total, len - total);
        if (r == 0) break;            // EOF
        if (r < 0) {
            if (errno == EINTR) continue;
            ::close(fd);
            return -3;
        }
        total += (size_t)r;
    }
    ::close(fd);
    *got = total;
    return 0;
}

extern "C" int u_write_file(const char* path, const uint8_t* buf, size_t len) {
    if (!path || (!buf && len)) return -1;

    // 0600: hanya user (proses ini) yang bisa baca/tulis
    int fd = ::open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -2;

    size_t total = 0;
    while (total < len) {
        ssize_t w = ::write(fd, buf + total, len - total);
        if (w < 0) {
            if (errno == EINTR) continue;
            ::close(fd);
            return -3;
        }
        total += (size_t)w;
    }
    if (::fsync(fd) != 0) {
        // tidak fatal, tapi baiknya dicatat/log kalau ada mekanisme log
    }
    ::close(fd);
    return 0;
}
