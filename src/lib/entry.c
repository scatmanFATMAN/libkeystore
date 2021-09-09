#include <stdlib.h>
#include <string.h>
#include "keystore_internal.h"
#include "error_internal.h"
#include "entry.h"

static keystore_entry_note_t *
keystore_entry_note_init() {
    keystore_entry_note_t *note;

    note = calloc(1, sizeof(*note));

    return note;
}

static void
keystore_entry_note_free(keystore_entry_note_t *note) {
    if (note != NULL) {
        if (note->value != NULL) {
            //certain things in this structure might be sensitive like:
            //  - value
            memset(note->value, 0, note->value_len);

            free(note->value);
        }

        free(note);
    }
}

static keystore_entry_folder_t *
keystore_entry_folder_init() {
    keystore_entry_folder_t *folder;

    folder = calloc(1, sizeof(*folder));

    return folder;
}

static void
keystore_entry_folder_free(keystore_entry_folder_t *folder) {
    if (folder != NULL) {
        free(folder);
    }
}

keystore_entry_t *
keystore_entry_init(keystore_t *keystore, keystore_entry_type_t type, const char *name) {
    keystore_entry_t *entry;

    if (strlen(name) > KEYSTORE_ENTRY_NAME_MAX) {
        keystore_error_set(&keystore->error, KEYSTORE_ERROR_LEN, 0, "Name is too long");
        return NULL;
    }

    entry = calloc(1, sizeof(*entry));
    if (entry == NULL) {
        keystore_error_set(&keystore->error, KEYSTORE_ERROR_MEM, 0, "Out of memory");
        return NULL;
    }

    switch (type) {
        case KEYSTORE_ENTRY_TYPE_NOTE:
            entry->data = keystore_entry_note_init();
            break;
        case KEYSTORE_ENTRY_TYPE_FOLDER:
            entry->data = keystore_entry_folder_init();
            break;
    }

    if (entry->data == NULL) {
        free(entry);
        keystore_error_set(&keystore->error, KEYSTORE_ERROR_MEM, 0, "Out of memory");
        return NULL;
    }

    entry->type = type;
    strcpy(entry->name, name);

    return entry;
}

void
keystore_entry_free(keystore_entry_t *entry) {
    if (entry != NULL) {
        switch (entry->type) {
            case KEYSTORE_ENTRY_TYPE_NOTE:
                keystore_entry_note_free((keystore_entry_note_t *)entry->data);
                break;
            case KEYSTORE_ENTRY_TYPE_FOLDER:
                keystore_entry_folder_free((keystore_entry_folder_t *)entry->data);
                break;
        }

        //certain things in this structure might be sensitive like:
        //  - name
        memset(entry, 0, sizeof(*entry));

        free(entry);
    }
}

keystore_entry_type_t
keystore_entry_type(keystore_entry_t *entry) {
    return entry->type;
}

const char *
keystore_entry_name(keystore_entry_t *entry) {
    return entry->name;
}

keystore_error_t
keystore_entry_set_name(keystore_t *keystore, keystore_entry_t *entry, const char *name) {
    if (strlen(name) > KEYSTORE_ENTRY_NAME_MAX) {
        return keystore_error_set(&keystore->error, KEYSTORE_ERROR_LEN, 0, "Name is too long");
    }

    strcpy(entry->name, name);
    return keystore_error_ok(&keystore->error);
}

keystore_error_t
keystore_entry_value(keystore_t *keystore, keystore_entry_t *entry, const char **value, uint32_t *len) {
    keystore_entry_note_t *note;

    if (entry->type != KEYSTORE_ENTRY_TYPE_NOTE) {
        return keystore_error_set(&keystore->error, KEYSTORE_ERROR_TYPE, 0, "Must be a note");
    }

    note = (keystore_entry_note_t *)entry->data;

    if (value != NULL) {
        *value = note->value;
    }
    if (len != NULL) {
        *len = note->value_len;
    }

    return keystore_error_ok(&keystore->error);
}

keystore_error_t
keystore_entry_set_value(keystore_t *keystore, keystore_entry_t *entry, const char *value) {
    return keystore_entry_set_valuen(keystore, entry, value, value == NULL ? 0 : strlen(value));
}

keystore_error_t
keystore_entry_set_valuen(keystore_t *keystore, keystore_entry_t *entry, const char *value, uint32_t len) {
    keystore_entry_note_t *note;
    char *tmp;

    if (entry->type != KEYSTORE_ENTRY_TYPE_NOTE) {
        return keystore_error_set(&keystore->error, KEYSTORE_ERROR_TYPE, 0, "Must be a note");
    }

    note = (keystore_entry_note_t *)entry->data;

    if (value == NULL || len == 0) {
        note->value_len = 0;

        if (note->value != NULL) {
            free(note->value);
            note->value = NULL;
        }
    }
    else {
        //make sure we can allocate memory for this string first. if we can't, we don't want to lose the old value
        tmp = strdup(value);
        if (tmp == NULL) {
            return keystore_error_set(&keystore->error, KEYSTORE_ERROR_MEM, 0, "Out of memory");
        }

        //free the old value and swap pointers
        if (note->value != NULL) {
            free(note->value);
        }

        note->value_len = len;
        note->value = tmp;
    }

    return keystore_error_ok(&keystore->error);
}
