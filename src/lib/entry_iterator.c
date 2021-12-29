#include <stdlib.h>
#include "keystore_internal.h"
#include "entry_iterator.h"

void
keystore_entry_iterator_free(keystore_entry_iterator_t *iterator) {
    if (iterator != NULL) {
        free(iterator);
    }
}

unsigned int
keystore_entry_iterator_size(keystore_entry_iterator_t *iterator) {
    return iterator->size;
}

bool
keystore_entry_iterator_has_next(keystore_entry_iterator_t *iterator) {
    return iterator->entry != NULL;
}

keystore_entry_t *
keystore_entry_iterator_next(keystore_entry_iterator_t *iterator) {
    keystore_entry_t *entry;

    entry = iterator->entry;

    if (iterator->entry != NULL) {
        iterator->entry = iterator->entry->next;
    }

    return entry;
}

void
keystore_entry_iterator_rewind(keystore_entry_iterator_t *iterator) {
    iterator->entry = iterator->entry_orig;
}
