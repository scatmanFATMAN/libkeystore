#pragma once

#include "error.h"

typedef struct {
    keystore_error_t error;
    int error_sys;
    char error_str[512];
} keystore_errors_t;

keystore_error_t keystore_error_set(keystore_errors_t *errors, keystore_error_t error, int error_sys, const char *fmt, ...);
keystore_error_t keystore_error_ok(keystore_errors_t *errors);
