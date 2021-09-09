#if defined(_WIN32)
# include <fileapi.h>
#else
# include <errno.h>
# include <unistd.h>
#endif
#include "fs.h"

bool
fs_file_exists(const char *path) {
#if defined(_WIN32)
    DWORD attr;

    attr = GetFileAttributes(path);

    return attrib != INVALID_FILE_ATTRIBUTES && !(attrib & FILE_ATTRIBUTE_DIRECTORY);
#else
    return access(path, F_OK) == 0;
#endif
}
