#include <stdio.h>
#include <string.h>
#if defined(_WIN32)
# include <Windows.h>
#else
# include <unistd.h>
#endif
#include "os.h"

const char *
os_basename(const char *path, char *base, size_t size) {
    char *ptr;

    if (size == 0) {
        return path;
    }

    ptr = strchr(path, '/');
    if (ptr == NULL) {
        snprintf(base, size, "%s", path);
    }
    else {
        snprintf(base, size, "%s", ptr);
    }

    return base;
}
