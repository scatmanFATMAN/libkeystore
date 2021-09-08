#if defined(_WIN32)
#else
# include <errno.h>
# include <unistd.h>
#endif
#include "fs.h"

bool
fs_file_exists(const char *path) {
#if defined(_WIN32)
#else
    return access(path, F_OK) == 0;
#endif
}
