#pragma once

#include "error_internal.h"

#define CRYPT_BCRYPT_SALT_SIZE    22
#define CRYPT_BCRYPT_SETTING_SIZE (7 + CRYPT_BCRYPT_SALT_SIZE)
#define CRYPT_BCRYPT_SIZE         (CRYPT_BCRYPT_SETTING_SIZE + 31)

keystore_error_t crypt_bcrypt(keystore_errors_t *errors, const char *salt, const char *password, char *hash);
keystore_error_t crypt_bcrypt_matches(keystore_errors_t *errors, const char *password, const char *hash);

