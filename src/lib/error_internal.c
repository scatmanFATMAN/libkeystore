#include <stdio.h>
#include <stdarg.h>
#include "error_internal.h"

keystore_error_t
keystore_error_set(keystore_errors_t *errors, keystore_error_t error, int error_sys, const char *fmt, ...) {
    va_list ap;

    errors->error = error;
    errors->error_sys = error_sys;

    va_start(ap, fmt);
    vsnprintf(errors->error_str, sizeof(errors->error_str), fmt, ap);
    va_end(ap);

    return error;
}

keystore_error_t
keystore_error_ok(keystore_errors_t *errors) {
    errors->error = KEYSTORE_ERROR_OK;
    errors->error_sys = 0;
    errors->error_str[0] = '\0';

    return KEYSTORE_ERROR_OK;
}
