#pragma once

#include <stdint.h>
#include <time.h>
#include "error.h"
#include "entry_iterator.h"

#define KEYSTORE_ENTRY_NAME_MAX 255

#define KEYSTORE_ENTRY_DELETE_FLAG_RECURSIVE (1 << 1)  //<! Informs keystore_entry_delete_entry() to recursively delete child entries if it's a folder

typedef struct keystore_t keystore_t;
typedef struct keystore_entry_t keystore_entry_t;
typedef struct keystore_entry_iterator_t keystore_entry_iterator_t;

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
 *
 * Get the Keystore entry's parent.
 *
 * @param[in] entry The KeyStore entry.
 * @return The KeyStore entry's parent.
 */
keystore_entry_t * keystore_entry_parent(keystore_entry_t *entry);

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

/**
 * Gets the KeyStore entry's created timestamp.
 *
 * @param[in] entry The KeyStore entry.
 * @return The created timestamp of the KeyStore entry.
 */
time_t keystore_entry_created(keystore_entry_t *entry);

/**
 * Gets the KeyStore entry's modified timestamp.
 *
 * @param[in] entry The KeyStore entry.
 * @return The modified timestamp of the KeyStore entry.
 */
time_t keystore_entry_modified(keystore_entry_t *entry);

/**
 * Gets the KeyStore entry's folder size. The entry must be a KEYSTORE_ENTRY_TYPE_FOLDER type.
 *
 * @param[in] keystore The KeyStore context.
 * @param[in] entry The KeyStore entry to get the folder size of.
 * @param[out] size The memory location to store the size of the folder.
 * @return KEYSTORE_ERROR_OK on success, otherwise another error.
 */
keystore_error_t keystore_entry_folder_size(keystore_t *keystore, keystore_entry_t *entry, unsigned int *size);

/**
 * Adds a KeyStore entry parent entry. The parent entry must be a KEYSTORE_ENTRY_TYPE_FOLDER type.
 *
 * @param[in] keystore The KeyStore context.
 * @param[in] parent The KeyStore entry to add the new entry to.
 * @param[in] entry The KeyStore entry to add.
 * @return KEYSTORE_ERROR_OK on success, otherwise another error.
 */
keystore_error_t keystore_entry_add_entry(keystore_t *keystore, keystore_entry_t *parent, keystore_entry_t *entry);

/**
 * Gets a KeyStore entry from the parent entry which must be a KEYSTORE_ENTRY_TYPE_FOLDER type.
 *
 * @param[in] keystore The KeyStore context.
 * @param[in] parent The KeyStore entry to look in.
 * @param[in] name The name of the KeyStore entry to look for.
 * @param[out] entry If found, the entry will be stored in this pointer.
 * @return KEYSTORE_ERROR_OK if found, otherwise another error.
 */
keystore_error_t keystore_entry_get_entry(keystore_t *keystore, keystore_entry_t *parent, const char *name, keystore_entry_t **entry);

/**
 * Gets an iterator of entries for this KeyStore entry. The iterator must be free'd with
 * keystore_entry_iterator_free() once it's done being used.
 *
 * @param[in] keystore The KeyStore context.
 * @param[in] parent The KeyStore entry to look in.
 * @param[out] iterator The iterator of entries in the parent entry.
 * @return KEYSTORE_ERROR_OK on success, otherwise another error.
 */
keystore_error_t keystore_entry_get_entries(keystore_t *keystore, keystore_entry_t *parent, keystore_entry_iterator_t **iterator);

/**
 * Deletes a KeyStore entry. By default, this function does not let you delete
 * folders that are not empty. In order to delete folders that are not empty,
 * use the KEYSTORE_ENTRY_DELETE_FLAG_RECURSIVE flag.
 *
 * @param[in] keystore The KeyStore context.
 * @param[in] entry The KeyStore entry to delete.
 * @param[in] flags Flags that control how to delete.
 * @return KEYSTORE_ERROR_OK on success, otherwise another error.
 *    KEYSTORE_ENTRY_DELETE_FLAG_RECURSIVE
 */
keystore_error_t keystore_entry_delete_entry(keystore_t *keystore, keystore_entry_t *entry, int flags);

/**
 * Reads a KeyStore entry from the KeyStore file.
 *
 * @param[in] keystore The KeyStore context.
 * @param[in] entry The entry to return.
 * @return KEYSTORE_ERROR_OK if found, otherwise another error.
 */
//SUGGEST REMOVING FROM PUBLIC API. FORWARD DECLARE IN keystore.c
//keystore_error_t keystore_entry_read(keystore_t *keystore, keystore_entry_t **entry);

/**
 * Writes a KeyStorey entry to the KeyStore file.
 *
 * @param[in] keystore The KeyStore context.
 * @param[in] entry The entry to write.
 * @return KEYSTORE_ERROR_OK on success, otherwise another error.
 */
//SUGGEST REMOVING FROM PUBLIC API. FORWARD DECLARE IN keystore.c
//keystore_error_t keystore_entry_write(keystore_t *keystore, keystore_entry_t *entry);

/**
 * Returns a string describing the entry type.
 *
 * @param[in] type The KeyStore entry type.
 * @return A string literal.
 */
const char * keystore_entry_type_str(keystore_entry_type_t type);
