#pragma once

#include <stdbool.h>
#include "error.h"
#include "entry.h"

typedef struct keystore_t keystore_t;

/**
 * Initializes the KeyStore context. The pointer returned is dynamically allocated and must be free'd
 * by calling keystore_free().
 *
 * @return The KeyStore context or NULL if not enough memory was available.
 */
keystore_t * keystore_init();

/**
 * Frees a KeyStore context and closes the KeyStore if one is open.
 *
 * @param[in] keystore The KeyStore context.
 */
void keystore_free(keystore_t *keystore);

/**
 * Opens a KeyStore. The KeyStore context must not already have an open KeyStore.
 *
 * @param[in] keystore The KeyStore context.
 * @param[in] path The file path of the KeyStore.
 * @param[in] password The password required for opening the KeyStore.
 * @return KEYSTORE_ERROR_OK on success, otherwise another error.
 */
keystore_error_t keystore_open(keystore_t *keystore, const char *path, const char *password);

/**
 * Closes a KeyStore that's open.
 *
 * @param[in] keystore The KeyStore context.
 * @return KEYSTORE_ERROR_OK on success, otherwise another error.
 */
keystore_error_t keystore_close(keystore_t *keystore);

/**
 * Gets the major version of the KeyStore.
 *
 * @param[in] keystore The KeyStore context.
 * @return The major version of the KeyStore or -1 if a KeyStore isn't open.
 */
int keystore_version_major(keystore_t *keystore);

/**
 * Gets the minor version of the KeyStore.
 *
 * @param[in] keystore The KeyStore context.
 * @return The minor version of the KeyStore or -1 if a KeyStore isn't open.
 */
int keystore_version_minor(keystore_t *keystore);

/**
 * Gets the patch version of the KeyStore.
 *
 * @param[in] keystore The KeyStore context.
 * @return The patch version of the KeyStore or -1 if a KeyStore isn't open.
 */
int keystore_version_patch(keystore_t *keystore);

/**
 * Gets the currently stored error message of the KeyStore. This error message gets populated
 * after another API call fails.
 *
 * @param[in] keystore The KeyStore context.
 * @return The error message or a blank string if no error occurred.
 */
const char * keystore_error(keystore_t *keystore);

/**
 * Determines if the KeyStore context has a KeyStore open.
 *
 * @param[in] keystore The KeyStore context.
 * @return true if a KeyStore is open, otherwise false.
 */
bool keystore_is_open(keystore_t *keystore);

/**
 * Creates a new KeyStore.
 *
 * @param[in] keystore The KeyStore context.
 * @param[in] path The file path of the KeyStore.
 * @param[in] password The password required for opening the KeyStore.
 * @return KEYSTORE_ERROR_OK on success, otherwise another error.
 */
keystore_error_t keystore_create(keystore_t *keystore, const char *path, const char *password);

/**
 * Saves a KeyStore.
 *
 * @param[in] keystore The KeyStore context.
 * @return KEYSTORE_ERROR_OK on success, otherwise another error.
 */
keystore_error_t keystore_save(keystore_t *keystore);

/**
 * Adds a KeyStore entry to the KeyStore context. If parent is NULL, the entry will be added to the KeyStore context's
 * root folder, otherwise it'll be added to the entry as a child.
 *
 * @param[in] keystore The KeyStore context.
 * @param[in] parent The KeyStore entry to add the new entry to. If NULL, the entry will be added to the KeyStore context's root folder.
 * @param[in] entry The KeyStore entry to add.
 * @return KEYSTORE_ERROR_OK on success, otherwise another error.
 */
keystore_error_t keystore_add_entry(keystore_t *keystore, keystore_entry_t *parent, keystore_entry_t *entry);
