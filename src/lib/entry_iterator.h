#pragma once

#include <stdbool.h>

typedef struct keystore_entry_iterator_t keystore_entry_iterator_t;
typedef struct keystore_entry_t keystore_entry_t;

/**
 * Frees all memory associated with the iterator.
 *
 * @param[in] iterator The iterator.
 */
void keystore_entry_iterator_free(keystore_entry_iterator_t *iterator);

/**
 * Gets the number of entries in the iterator.
 *
 * @param[in] iterator The iterator.
 */
unsigned int keystore_entry_iterator_size(keystore_entry_iterator_t *iterator);

/**
 * Determines whether or not there are any more entries in the iterator.
 *
 * @param[in] iterator The iterator.
 * @return <tt>true</tt> if there are more entries, otherwise <tt>false</tt>.
 */
bool keystore_entry_iterator_has_next(keystore_entry_iterator_t *iterator);

/**
 * Advances the iterator and returns the next entry.
 *
 * @param[in] iterator The iterator.
 * @return The next entry in the iterator or NULL if no more entries exist.
 */
keystore_entry_t * keystore_entry_iterator_next(keystore_entry_iterator_t *iterator);

/**
 * Rewinds the iterator to the first entry.
 *
 * @param[in] iterator The iterator.
 */
void keystore_entry_iterator_rewind(keystore_entry_iterator_t *iterator);
