#include <stdio.h>
#if defined(_WIN32)
# include <Windows.h>
#else
#endif
#include <string.h>
#include "os.h"

const char *
os_dirname(const char *path, char *dir, size_t size) {
    char *ptr;

    snprintf(dir, size, "%s", path);

    if (strcmp(dir, "/") == 0) {
        return dir;
    }

    ptr = strrchr(dir, '/');
    if (ptr == NULL) {
        snprintf(dir, size, "%s", ".");
    }
    else {
        *ptr = '\0';
    }

    return dir;
}

const char *
os_basename(const char *path, char *base, size_t size) {
    char *ptr;

    if (size == 0) {
        return path;
    }

    ptr = strrchr(path, '/');
    if (ptr == NULL) {
        snprintf(base, size, "%s", path);
    }
    else {
        snprintf(base, size, "%s", ptr + 1);
    }

    return base;
}
