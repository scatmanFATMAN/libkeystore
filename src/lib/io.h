#pragma once

#include <stdlib.h>
#include "keystore_internal.h"
#include "error_internal.h"

keystore_error_t keystore_read(keystore_t *keystore, unsigned char *dst, size_t count);
keystore_error_t keystore_read_strn(keystore_t *keystore, char *dst, size_t len);
keystore_error_t keystore_read_int64(keystore_t *keystore, int64_t *dst);
keystore_error_t keystore_read_uint8(keystore_t *keystore, uint8_t *dst);
keystore_error_t keystore_read_uint16(keystore_t *keystore, uint16_t *dst);
keystore_error_t keystore_read_uint32(keystore_t *keystore, uint32_t *dst);

keystore_error_t keystore_write(keystore_t *keystore, unsigned char *buf, size_t count);
keystore_error_t keystore_write_strn(keystore_t *keystore, const char *data, size_t len);
keystore_error_t keystore_write_str(keystore_t *keystore, const char *data);
keystore_error_t keystore_write_int64(keystore_t *keystore, int64_t data);
keystore_error_t keystore_write_uint8(keystore_t *keystore, uint8_t data);
keystore_error_t keystore_write_uint16(keystore_t *keystore, uint16_t data);
keystore_error_t keystore_write_uint32(keystore_t *keystore, uint32_t data);
