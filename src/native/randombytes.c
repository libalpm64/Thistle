#include <stdint.h>
#include <stddef.h>

#if defined(_WIN32)
    #include <windows.h>
    #include <bcrypt.h>
    #pragma comment(lib, "bcrypt.lib")
#elif defined(__APPLE__) || defined(__OpenBSD__)
    #include <stdlib.h>
#else
    #include <sys/random.h>
    #include <unistd.h>
    #include <errno.h>
#endif

void randombytes(uint8_t *buf, size_t len) {
#if defined(_WIN32)
    BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
#elif defined(__APPLE__) || defined(__OpenBSD__)
    arc4random_buf(buf, len);
#else
    size_t offset = 0;
    while (offset < len) {
        ssize_t ret = getrandom(buf + offset, len - offset, 0);
        if (ret < 0) {
            if (errno == EINTR) continue;
            __builtin_unreachable();
        }
        offset += (size_t)ret;
    }
#endif
}
