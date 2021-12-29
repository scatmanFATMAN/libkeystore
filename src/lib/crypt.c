#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#if defined(_WIN32)
#else
# include <sys/random.h>
#endif
#include "../crypt_blowfish-1.3/ow-crypt.h"
#include "util.h"
#include "crypt.h"

void
crypt_init() {
#if OPENSSL_API_COMPAT < 0x10100000L
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
#endif
}

void
crypt_free() {
#if OPENSSL_API_COMPAT < 0x10100000L
    ERR_free_strings();
    EVP_cleanup();
#endif
}

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
       return keystore_error_set(errors, KEYSTORE_ERROR_INVALID, 0, "Password is invalid");
    }

    return keystore_error_ok(errors);
}

keystore_error_t
crypt_aes256_iv(keystore_errors_t *errors, unsigned char *iv) {
    if (!RAND_bytes(iv, CRYPT_AES256_IV_SIZE)) {
        return keystore_error_set(errors, KEYSTORE_ERROR_MEM, 0, "Out of memory");
    }

    return keystore_error_ok(errors);
}

keystore_error_t
crypt_aes256_encrypt(keystore_errors_t *errors, const char *plain, const char *key, unsigned char *iv, unsigned char **encrypted, int *encrypted_len) {
    keystore_error_t error = KEYSTORE_ERROR_OK;
    EVP_CIPHER_CTX *ctx;
    int plain_len, len;

    //get random bytes fro the IV
    if (!RAND_bytes(iv, CRYPT_AES256_IV_SIZE)) {
        return keystore_error_set(errors, KEYSTORE_ERROR_MEM, 0, "Out of memory");
    }

    plain_len = strlen(plain);

    //allocate a buffer big enough to fit the cipher. that is the length of the plain text + any padding to make the size divisible by the block size
    *encrypted = malloc((plain_len / CRYPT_AES256_BLOCK_SIZE + 1) * CRYPT_AES256_BLOCK_SIZE);
    if (encrypted == NULL) {
        return keystore_error_set(errors, KEYSTORE_ERROR_MEM, 0, "Out of memory");
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        error = keystore_error_set(errors, KEYSTORE_ERROR_MEM, 0, "Out of memory");
        goto done;
    }

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char *)key, iv)) {
        error = keystore_error_set(errors, KEYSTORE_ERROR_INIT, 0, "Init: %s", ERR_reason_error_string(ERR_get_error()));
        goto done;
    }

    if (!EVP_EncryptUpdate(ctx, *encrypted, &len, (unsigned char *)plain, plain_len)) {
        error = keystore_error_set(errors, KEYSTORE_ERROR_WRITE, 0, "Update: %s", ERR_reason_error_string(ERR_get_error()));
        goto done;
    }

    *encrypted_len = len;

    if (!EVP_EncryptFinal_ex(ctx, *encrypted + *encrypted_len, &len)) {
        error = keystore_error_set(errors, KEYSTORE_ERROR_WRITE, 0, "Final: %s", ERR_reason_error_string(ERR_get_error()));
        goto done;
    }

    *encrypted_len += len;

done:
    if (ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx);
    }

    if (error != KEYSTORE_ERROR_OK) {
        free(*encrypted);
        return error;
    }

    return keystore_error_ok(errors);
}

keystore_error_t
crypt_aes256_decrypt(keystore_errors_t *errors, const unsigned char *encrypted, int encrypted_len, const char *key, const unsigned char *iv, char **plain) {
    keystore_error_t error = KEYSTORE_ERROR_OK;
    EVP_CIPHER_CTX *ctx;
    int plain_len, len;

    //the plain text cannot be longer than the cipher size
    *plain = malloc(encrypted_len + 1);
    if (plain == NULL) {
        return keystore_error_set(errors, KEYSTORE_ERROR_MEM, 0, "Out of memory");
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        error = keystore_error_set(errors, KEYSTORE_ERROR_MEM, 0, "Out of memory");
        goto done;
    }

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char *)key, iv)) {
        error = keystore_error_set(errors, KEYSTORE_ERROR_INIT, 0, "Init: %s", ERR_reason_error_string(ERR_get_error()));
        goto done;
    }

    if (!EVP_DecryptUpdate(ctx, *(unsigned char **)plain, &len, encrypted, encrypted_len)) {
        error = keystore_error_set(errors, KEYSTORE_ERROR_WRITE, 0, "Update: %s", ERR_reason_error_string(ERR_get_error()));
        goto done;
    }

    plain_len = len;

    if (!EVP_DecryptFinal_ex(ctx, *(unsigned char **)plain + len, &len)) {
        error = keystore_error_set(errors, KEYSTORE_ERROR_WRITE, 0, "Final: %s", ERR_reason_error_string(ERR_get_error()));
        goto done;
    }

    plain_len += len;
    (*plain)[plain_len] = '\0';

done:
    if (ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx);
    }

    if (error != KEYSTORE_ERROR_OK) {
        free(*plain);
        return error;
    }

    return keystore_error_ok(errors);
}

keystore_error_t
crypt_aes256_file_encrypt_open(keystore_errors_t *errors, crypt_file_t *file, const char *path, const char *key) {
    keystore_error_t error = KEYSTORE_ERROR_OK;

    file->f = fopen(path, "w");
    if (file->f == NULL) {
        return keystore_error_set(errors, KEYSTORE_ERROR_OPEN, errno, "Open: %s", strerror(errno));
    }

    //get random bytes fro the IV
    if (!RAND_bytes(file->iv, CRYPT_AES256_IV_SIZE)) {
        error = keystore_error_set(errors, KEYSTORE_ERROR_MEM, 0, "Out of memory");
        goto done;
    }

    file->ctx = EVP_CIPHER_CTX_new();
    if (file->ctx == NULL) {
        error = keystore_error_set(errors, KEYSTORE_ERROR_MEM, 0, "Out of memory");
        goto done;
    }

    if (!EVP_EncryptInit_ex(file->ctx, EVP_aes_256_cbc(), NULL, (unsigned char *)key, file->iv)) {
        error = keystore_error_set(errors, KEYSTORE_ERROR_INIT, 0, "Init: %s", ERR_reason_error_string(ERR_get_error()));
        goto done;
    }

done:

    if (error != KEYSTORE_ERROR_OK) {
        if (file->f != NULL) {
            fclose(file->f);
        }

        if (file->ctx != NULL) {
            EVP_CIPHER_CTX_free(file->ctx);
        }

        //zero out memory for the IV
        util_memzero(file, sizeof(*file));

        return error;
    }

    return keystore_error_ok(errors);
}

keystore_error_t
crypt_aes256_file_encrypt_write(keystore_errors_t *errors, crypt_file_t *file, const char *plain, int plain_len) {
    unsigned char encrypted[CRYPT_AES256_BLOCK_SIZE];
    int len, plain_len_chunk;
    keystore_error_t error;

    //write in aes256 block size chunks so the file gets encrypted and written in a stream like manner so
    //we don't need to put the entire file into memory

    do {
        if (plain_len >= CRYPT_AES256_BLOCK_SIZE) {
            plain_len_chunk = CRYPT_AES256_BLOCK_SIZE;
        }
        else {
            plain_len_chunk = CRYPT_AES256_BLOCK_SIZE - plain_len;
        }
        plain_len -= plain_len_chunk;

        if (!EVP_EncryptUpdate(file->ctx, encrypted, &len, (unsigned char *)plain, plain_len_chunk)) {
            error = keystore_error_set(errors, KEYSTORE_ERROR_WRITE, 0, "Update: %s", ERR_reason_error_string(ERR_get_error()));
            goto done;
        }

        if (fwrite(encrypted, sizeof(unsigned char), len, file->f) != len) {
            return keystore_error_set(errors, KEYSTORE_ERROR_WRITE, errno, "Write: %s", strerror(errno));
        }
    }
    while (plain_len > 0);

done:
    return error;
}

keystore_error_t
crypt_aes256_file_encrypt_close(keystore_errors_t *errors, crypt_file_t *file) {
    unsigned char encrypted[CRYPT_AES256_BLOCK_SIZE];
    int len;

    if (!EVP_EncryptFinal_ex(file->ctx, encrypted, &len)) {
        return keystore_error_set(errors, KEYSTORE_ERROR_WRITE, 0, "Final: %s", ERR_reason_error_string(ERR_get_error()));
    }

    if (len > 0) {
        if (fwrite(encrypted, sizeof(unsigned char), len, file->f) != len) {
            return keystore_error_set(errors, KEYSTORE_ERROR_WRITE, errno, "Write: %s", strerror(errno));
        }
    }

    EVP_CIPHER_CTX_free(file->ctx);
    fclose(file->f);

    return keystore_error_ok(errors);
}

