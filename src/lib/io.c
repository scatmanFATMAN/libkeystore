#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "io.h"

keystore_error_t
keystore_read(keystore_t *keystore, unsigned char *dst, size_t count) {
    if (fread(dst, sizeof(unsigned char), count, keystore->f) != count) {
        return keystore_error_set(&keystore->error, KEYSTORE_ERROR_IO_READ, errno, "Failed to read %zu bytes: %s", count, strerror(errno));
    }

    return keystore_error_ok(&keystore->error);
}

keystore_error_t
keystore_read_strn(keystore_t *keystore, char *dst, size_t len) {
    keystore_error_t error;

    error = keystore_read(keystore, (unsigned char *)dst, len);
    if (error == KEYSTORE_ERROR_OK) {
        dst[len] = '\0';
    }

    return error;
}

keystore_error_t
keystore_write(keystore_t *keystore, unsigned char *buf, size_t count) {
    if (fwrite(buf, sizeof(unsigned char), count, keystore->f) != count) {
        return keystore_error_set(&keystore->error, KEYSTORE_ERROR_IO_WRITE, errno, "Failed to write %zu bytes: %s", count, strerror(errno));
    }

    return keystore_error_ok(&keystore->error);
}

keystore_error_t
keystore_write_strn(keystore_t *keystore, const char *data, size_t len) {
    return keystore_write(keystore, (unsigned char *)data, len);
}

keystore_error_t
keystore_write_str(keystore_t *keystore, const char *data) {
    return keystore_write(keystore, (unsigned char *)data, strlen(data));
}

keystore_error_t
keystore_write_uint8(keystore_t *keystore, uint8_t data) {
    return keystore_write(keystore, &data, sizeof(data));
}
