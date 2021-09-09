#pragma once

#include "error_internal.h"

#define CRYPT_BCRYPT_SALT_SIZE    22
#define CRYPT_BCRYPT_SETTING_SIZE (7 + CRYPT_BCRYPT_SALT_SIZE)
#define CRYPT_BCRYPT_SIZE         (CRYPT_BCRYPT_SETTING_SIZE + 31)

//128 bit (16 bytes) block and IV 
#define CRYPT_AES256_BLOCK_SIZE (128 / 8)
#define CRYPT_AES256_IV_SIZE    (128 / 8)

void crypt_init();
void crypt_free();

/**
 * Hashes a password using the supplied salt.
 *
 * @param[out] errors The error object to write errors to.
 * @param[in] salt The salt for bcrypt. Must be CRYPT_BCRYPT_SALT_SIZE characters.
 * @param[in] password The data to hash.
 * @param[out] The resulting hash. Must be a buffer CRYPT_BCRYPT_SIZE + 1 big.
 * @return KEYSTORE_ERROR_OK on success, otherwise another error.
 */
keystore_error_t crypt_bcrypt(keystore_errors_t *errors, const char *salt, const char *password, char *hash);

/**
 * Compares a hash and a password to see if it's the correct password. Uses time-safe comparison.
 *
 * @param[out] errors The error object to write errors to.
 * @param[in] password The data to compare the hash to.
 * @param[in] hash The hash to compare against.
 * @return KEYSTORE_ERROR_OK on success, otherwise another error.
 */
keystore_error_t crypt_bcrypt_matches(keystore_errors_t *errors, const char *password, const char *hash);

/**
 * Encrypts a string using AES256 CBC.
 *
 * @param[out] errors The error object to write errors to.
 * @param[in] plain The plain text to encrypt.
 * @param[in] key The key to use for encryption.
 * @param[out] iv The IV used for encryption. The buffer must be CRYPT_AES256_IV_SIZE big.
 * @param[out] encrypted The resulting encrypted cipher. Memory is allocated by the function and should be free'd by the caller.
 * @param[out] encrypted_len The length of the encrypted cipher.
 * @return KEYSTORE_ERROR_OK on success, otherwise another error.
 */
keystore_error_t crypt_aes256_encrypt(keystore_errors_t *errors, const char *plain, const char *key, unsigned char *iv, unsigned char **encrypted, int *encrypted_len);

/**
 * Decrypts a string using AES256 CBC.
 *
 * @param[out] errors The error object to write errors to.
 * @param[in] encrypted The encrypted cipher to decrypt.
 * @param[in] encrypted_len The encrypted cipher's length.
 * @param[in] key The key to use for decryption.
 * @param[in] iv The IV to use for decryption.
 * @param[out] plain The resulting decrypted plain text. Memory is allocated by the function, is NULL terminated, and should be free'd by the caller.
 * @return KEYSTORE_ERROR_OK on success, otherwise another error.
 */
keystore_error_t crypt_aes256_decrypt(keystore_errors_t *errors, const unsigned char *encrypted, int encrypted_len, const char *key, const unsigned char *iv, char **plain);
