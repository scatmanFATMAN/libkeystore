#if defined(_WIN32)
# include <Windows.h>
#endif
#include "util.h"

void
util_memzero(void *ptr, size_t len) {
#if defined(_WIN32)
    SecureZeroMemory(ptr, len);
#else
    volatile unsigned char *p;

    p = ptr;
    while (len-- > 0) {
        *p++ = 0;
    }
#endif
}
