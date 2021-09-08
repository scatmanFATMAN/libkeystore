#pragma once

#include <stdlib.h>
#include "keystore_internal.h"
#include "error_internal.h"

typedef struct keystore_t keystore_t;

keystore_error_t keystore_read(keystore_t *keystore, unsigned char *dst, size_t count);
keystore_error_t keystore_read_strn(keystore_t *keystore, char *dst, size_t len);

keystore_error_t keystore_write(keystore_t *keystore, unsigned char *buf, size_t count);
keystore_error_t keystore_write_strn(keystore_t *keystore, const char *data, size_t len);
keystore_error_t keystore_write_str(keystore_t *keystore, const char *data);
keystore_error_t keystore_write_uint8(keystore_t *keystore, uint8_t data);
