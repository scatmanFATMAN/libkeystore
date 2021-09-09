#pragma once

#include <stdint.h>
#include "error.h"

#define KEYSTORE_ENTRY_NAME_MAX 255

typedef struct keystore_t keystore_t;
typedef struct keystore_entry_t keystore_entry_t;

typedef enum {
    KEYSTORE_ENTRY_TYPE_NOTE,
    KEYSTORE_ENTRY_TYPE_FOLDER
} keystore_entry_type_t;

/**
 * Initializes a new KeyStore entry. Once created, the type of the entry cannot be changed.
 *
 * @param[in] keystore The KeyStore context.
 * @param[in] type The entry's type.
 * @param[in] name The entry's name.
 * @return A reference to a new entry or NULL if not enough memory was available.
 */
keystore_entry_t * keystore_entry_init(keystore_t *keystore, keystore_entry_type_t type, const char *name);

/**
 * Frees a KeyStore entry.
 *
 * @param[in] entry The KeyStore entry.
 */
void keystore_entry_free(keystore_entry_t *entry);

/**
 * Gets the KeyStore entry's type.
 *
 * @param[in] entry The KeyStore entry.
 * @return The KeyStore entry's type.
 */
keystore_entry_type_t keystore_entry_type(keystore_entry_t *entry);

/**
 * Gets the KeyStore entry's name.
 *
 * @param[in] entry The KeyStore entry.
 * @return The KeyStore entry's name.
 */
const char * keystore_entry_name(keystore_entry_t *entry);

/**
 * Sets the KeyStore entry's name.
 *
 * @param[in] keystore The KeyStore context.
 * @param[in] entry The KeyStore entry.
 * @param[in] name The new name of the KeyStore entry.
 * @return KEYSTORE_ERROR_OK on success, otherwise another error.
 */
keystore_error_t keystore_entry_set_name(keystore_t *keystore, keystore_entry_t *entry, const char *name);

/**
 * Gets the KeyStore entry's value. The entry must be a note type entry. This function can be used to retrieve both
 * the entry's value and length, or one of the two by passing NULL for the variable you don't care about. Passing NULL
 * for both value and len is pointless, but harmless.
 * When retrieving the value, take into considerination that it's a pointer to the value of the entry. If the entry's value
 * is set to something else or the entry is deleted, the pointer will not be valid anymore. If the value is NULL, then that
 * mean's the entry's value is blank.
 *
 * @param[in] keystore The KeyStore context.
 * @param[in] entry The KeyStore entry.
 * @param[out] value The KeyStore entry's value. Pass NULL if you do not care about this value.
 * @param[out] len The KeyStore entry's value's length. Pass NULL if you do not care about this value.
 * @return KEYSTORE_ERROR_OK on success, otherwise another error. If an error occurs, both value and len are not set.
 */
keystore_error_t keystore_entry_value(keystore_t *keystore, keystore_entry_t *entry, const char **value, uint32_t *len);

/**
 * Sets the Keystore entry's value. This entry must be a note type entry. If value is NULL, then the KeyStore entry's
 * value will be cleared.
 *
 * @param[in] keystore The KeyStore context.
 * @param[in] entry The KeyStore entry.
 * @param[in] value The KeyStore entry's new value.
 * @return KEYSTORE_ERROR_OK on success, otherwise another error.
 */
keystore_error_t keystore_entry_set_value(keystore_t *keystore, keystore_entry_t *entry, const char *value);

/**
 * Sets the Keystore entry's value. This entry must be a note type entry. If value is NULL or len is 0, then the KeyStore's
 * entry will be cleared.
 *
 * @param[in] keystore The KeyStore context.
 * @param[in] entry The KeyStore entry.
 * @param[in] value The KeyStore entry's new value.
 * @param[in] len The new value's length.
 * @return KEYSTORE_ERROR_OK on success, otherwise another error.
 */
keystore_error_t keystore_entry_set_valuen(keystore_t *keystore, keystore_entry_t *entry, const char *value, uint32_t len);
