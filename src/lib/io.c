#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "portable_endian.h"
#include "io.h"

keystore_error_t
keystore_read(keystore_t *keystore, unsigned char *dst, size_t count) {
    if (fread(dst, sizeof(unsigned char), count, keystore->f) != count) {
        return keystore_error_set(&keystore->error, KEYSTORE_ERROR_READ, errno, "Failed to read %zu bytes: %s", count, strerror(errno));
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
keystore_read_int64(keystore_t *keystore, int64_t *dst) {
    keystore_error_t error;

    error = keystore_read(keystore, (unsigned char *)dst, sizeof(*dst));
    if (error == KEYSTORE_ERROR_OK) {
        *dst = be64toh(*dst);
    }

    return error;
}


keystore_error_t
keystore_read_uint8(keystore_t *keystore, uint8_t *dst) {
    return keystore_read(keystore, dst, sizeof(*dst));
}

keystore_error_t
keystore_read_uint16(keystore_t *keystore, uint16_t *dst) {
    keystore_error_t error;

    error = keystore_read(keystore, (unsigned char *)dst, sizeof(*dst));
    if (error == KEYSTORE_ERROR_OK) {
        *dst = be16toh(*dst);
    }

    return error;
}

keystore_error_t
keystore_read_uint32(keystore_t *keystore, uint32_t *dst) {
    keystore_error_t error;

    error = keystore_read(keystore, (unsigned char *)dst, sizeof(*dst));
    if (error == KEYSTORE_ERROR_OK) {
        *dst = be32toh(*dst);
    }

    return error;
}

keystore_error_t
keystore_write(keystore_t *keystore, unsigned char *buf, size_t count) {
    if (fwrite(buf, sizeof(unsigned char), count, keystore->f) != count) {
        return keystore_error_set(&keystore->error, KEYSTORE_ERROR_WRITE, errno, "Failed to write %zu bytes: %s", count, strerror(errno));
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
keystore_write_int64(keystore_t *keystore, int64_t data) {
    data = htobe64(data);

    return keystore_write(keystore, (unsigned char *)&data, sizeof(data));
}

keystore_error_t
keystore_write_uint8(keystore_t *keystore, uint8_t data) {
    return keystore_write(keystore, &data, sizeof(data));
}

keystore_error_t
keystore_write_uint16(keystore_t *keystore, uint16_t data) {
    data = htobe16(data);

    return keystore_write(keystore, (unsigned char *)&data, sizeof(data));
}

keystore_error_t
keystore_write_uint32(keystore_t *keystore, uint32_t data) {
    data = htobe32(data);

    return keystore_write(keystore, (unsigned char *)&data, sizeof(data));
}
