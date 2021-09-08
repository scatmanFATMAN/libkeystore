#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#if defined(_WIN32)
#else
# include <sys/random.h>
#endif
#include "../crypt_blowfish-1.3/ow-crypt.h"
#include "crypt.h"

keystore_error_t
crypt_bcrypt(keystore_errors_t *errors, const char *salt, const char *password, char *hash) {
    keystore_error_t error = KEYSTORE_ERROR_OK;
    char *setting = NULL, salt_in[CRYPT_BCRYPT_SALT_SIZE], *pw;
    void *data = NULL;
    int data_size = 0;

    //both `data` and `data_size` must be initialized to NULL and 0. crypt_ra() will re-use this structure if not NULL and possibly call realloc() on it.
    //for our case, we'll always input a new structure. nothing will be cached but it's just easier

    //get random data for the salt if not provided
    if (salt != NULL) {
        setting = malloc(CRYPT_BCRYPT_SETTING_SIZE);
        strcpy(setting, "$2b$12$");
        memcpy(setting + 7, salt, CRYPT_BCRYPT_SALT_SIZE);
    }
    else {
#if defined(_WIN32)
#else
        if (getrandom(salt_in, sizeof(salt_in), 0) == -1) {
            error = keystore_error_set(errors, KEYSTORE_ERROR_PW_SALT_DATA, errno, "Failed to generate random data for salt");
            goto done;
        }

        setting = crypt_gensalt_ra("$2b$", 12, salt_in, sizeof(salt_in));
        if (setting == NULL) {
            error = keystore_error_set(errors, KEYSTORE_ERROR_PW_SALT, errno, "Failed to generate salt");
            goto done;
        }
#endif
    }

    pw = crypt_ra(password, setting, &data, &data_size);
    if (pw == NULL) {
        error = keystore_error_set(errors, KEYSTORE_ERROR_PW, errno, "Failed to generate password hash");
        goto done;
    }

    strcpy(hash, pw);

done:
    if (setting != NULL) {
        free(setting);
    }

    if (data != NULL) {
        free(data);
    }

    //we don't need to free(pw) because it's allocated as part of the opaque `data` structure

    return error;
}

keystore_error_t
crypt_bcrypt_matches(keystore_errors_t *errors, const char *password, const char *hash) {
    char salt[CRYPT_BCRYPT_SALT_SIZE], password_hash[CRYPT_BCRYPT_SIZE + 1];
    bool matches = true;
    keystore_error_t error;
    int i;

    memcpy(salt, hash + 7, sizeof(salt));

    error = crypt_bcrypt(errors, salt, password, password_hash);
    if (error != KEYSTORE_ERROR_OK) {
        return error;
    }

    for (i = 0; i < CRYPT_BCRYPT_SIZE; i++) {
        if (hash[i] != password_hash[i]) {
            matches = false;
        }
    }

    if (!matches) {
       return keystore_error_set(errors, KEYSTORE_ERROR_PW_INVALID, 0, "Password is invalid");
    }

    return keystore_error_ok(errors);
}
