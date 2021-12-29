#include <stdlib.h>
#include <string.h>
#include "keystore_internal.h"
#include "error_internal.h"
#include "util.h"
#include "io.h"
#include "entry.h"

keystore_error_t keystore_entry_read(keystore_t *keystore, keystore_entry_t *parent, keystore_entry_t **entry);
keystore_error_t keystore_entry_write(keystore_t *keystore, keystore_entry_t *entry);

static keystore_entry_note_t *
keystore_entry_init_note() {
    keystore_entry_note_t *note;

    note = calloc(1, sizeof(*note));

    return note;
}

static void
keystore_entry_free_note(keystore_entry_note_t *note) {
    if (note != NULL) {
        if (note->value != NULL) {
            //certain things in this structure might be sensitive like:
            //  - value
            util_memzero(note->value, note->value_len);

            free(note->value);
        }

        free(note);
    }
}

static keystore_entry_folder_t *
keystore_entry_init_folder() {
    keystore_entry_folder_t *folder;

    folder = calloc(1, sizeof(*folder));

    return folder;
}

static void
keystore_entry_free_folder(keystore_entry_folder_t *folder) {
    keystore_entry_t *entry, *entry_del;

    if (folder != NULL) {
        entry = folder->head;
        while (entry != NULL) {
            entry_del = entry;
            entry = entry->next;

            keystore_entry_free(entry_del);
        }

        free(folder);
    }
}

keystore_entry_t *
keystore_entry_init(keystore_t *keystore, keystore_entry_type_t type, const char *name) {
    keystore_entry_t *entry = NULL;
    bool success = false;
    size_t name_len;

    name_len = strlen(name);

    if (name_len > KEYSTORE_ENTRY_NAME_MAX) {
        keystore_error_set(&keystore->error, KEYSTORE_ERROR_LEN, 0, "Name is too long");
        goto done;
    }

    entry = calloc(1, sizeof(*entry));
    if (entry == NULL) {
        keystore_error_set(&keystore->error, KEYSTORE_ERROR_MEM, 0, "Out of memory");
        goto done;
    }

    entry->name_len = name_len;
    entry->name = malloc(entry->name_len + 1);
    if (entry->name == NULL) {
        keystore_error_set(&keystore->error, KEYSTORE_ERROR_MEM, 0, "Out of memory");
        goto done;
    }

    switch (type) {
        case KEYSTORE_ENTRY_TYPE_NOTE:
            entry->data = keystore_entry_init_note();
            break;
        case KEYSTORE_ENTRY_TYPE_FOLDER:
            entry->data = keystore_entry_init_folder();
            break;
    }

    if (entry->data == NULL) {
        keystore_error_set(&keystore->error, KEYSTORE_ERROR_MEM, 0, "Out of memory");
        return NULL;
    }

    entry->type = type;
    strcpy(entry->name, name);
    entry->created = time(NULL);
    entry->modified = entry->created;

    success = true;

done:
    if (!success) {
        if (entry != NULL) {
            keystore_entry_free(entry);
            entry = NULL;
        }
    }

    return entry;
}

void
keystore_entry_free(keystore_entry_t *entry) {
    if (entry != NULL) {
        if (entry->name != NULL) {
            util_memzero(entry->name, entry->name_len);
            free(entry->name);
        }

        switch (entry->type) {
            case KEYSTORE_ENTRY_TYPE_NOTE:
                keystore_entry_free_note((keystore_entry_note_t *)entry->data);
                break;
            case KEYSTORE_ENTRY_TYPE_FOLDER:
                keystore_entry_free_folder((keystore_entry_folder_t *)entry->data);
                break;
        }

        util_memzero(entry, sizeof(*entry));
        free(entry);
    }
}

keystore_entry_type_t
keystore_entry_type(keystore_entry_t *entry) {
    return entry->type;
}

keystore_entry_t *
keystore_entry_parent(keystore_entry_t *entry) {
    return entry->parent;
}

const char *
keystore_entry_name(keystore_entry_t *entry) {
    return entry->name;
}

keystore_error_t
keystore_entry_set_name(keystore_t *keystore, keystore_entry_t *entry, const char *name) {
    size_t name_len = 0;
    char *name_dupe;

    if (name != NULL) {
        name_len = strlen(name);
    }

    if (name_len == 0) {
        return keystore_error_set(&keystore->error, KEYSTORE_ERROR_EMPTY, 0, "Name cannot be empty");
    }

    if (name_len > KEYSTORE_ENTRY_NAME_MAX) {
        return keystore_error_set(&keystore->error, KEYSTORE_ERROR_LEN, 0, "Name is too long");
    }

    name_dupe = strdup(name);
    if (name_dupe == NULL) {
        return keystore_error_set(&keystore->error, KEYSTORE_ERROR_MEM, 0, "Out of memory");
    }

    if (entry->name != NULL) {
        free(entry->name);
    }

    entry->name_len = name_len;
    entry->name = name_dupe;
    entry->modified = time(NULL);

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

    entry->modified = time(NULL);

    return keystore_error_ok(&keystore->error);
}

time_t
keystore_entry_created(keystore_entry_t *entry) {
    return entry->created;
}

time_t
keystore_entry_modified(keystore_entry_t *entry) {
    return entry->modified;
}

keystore_error_t
keystore_entry_folder_size(keystore_t *keystore, keystore_entry_t *entry, unsigned int *size) {
    keystore_entry_folder_t *folder;

    if (entry->type != KEYSTORE_ENTRY_TYPE_FOLDER) {
        return keystore_error_set(&keystore->error, KEYSTORE_ERROR_TYPE, 0, "Not a folder");
    }

    folder = (keystore_entry_folder_t *)entry->data;
    *size = folder->size;

    return keystore_error_ok(&keystore->error);
}

keystore_error_t
keystore_entry_add_entry(keystore_t *keystore, keystore_entry_t *parent, keystore_entry_t *entry) {
    keystore_entry_folder_t *folder;

    if (parent->type != KEYSTORE_ENTRY_TYPE_FOLDER) {
        return keystore_error_set(&keystore->error, KEYSTORE_ERROR_TYPE, 0, "Parent is not a folder");
    }

    folder = (keystore_entry_folder_t *)parent->data;
    if (folder->head == NULL) {
        folder->head = entry;
        folder->tail = entry;
    }
    else {
        folder->tail->next = entry;
        folder->tail = entry;
    }

    entry->parent = parent;

    ++folder->size;
    parent->modified = time(NULL);
    entry->modified = time(NULL);

    return keystore_error_ok(&keystore->error);
}

keystore_error_t
keystore_entry_get_entry(keystore_t *keystore, keystore_entry_t *parent, const char *name, keystore_entry_t **entry) {
    keystore_entry_folder_t *folder;
    keystore_entry_t *itr;

    if (parent->type != KEYSTORE_ENTRY_TYPE_FOLDER) {
        return keystore_error_set(&keystore->error, KEYSTORE_ERROR_TYPE, 0, "Parent is not a folder");
    }

    folder = (keystore_entry_folder_t *)parent->data;
    itr = folder->head;
    while (itr != NULL) {
        if (strcmp(itr->name, name) == 0) {
            *entry = itr;
            return keystore_error_ok(&keystore->error);
        }

        itr = itr->next;
    }

    return keystore_error_set(&keystore->error, KEYSTORE_ERROR_NOT_FOUND, 0, "Entry not found");
}

keystore_error_t
keystore_entry_get_entries(keystore_t *keystore, keystore_entry_t *parent, keystore_entry_iterator_t **iterator) {
    keystore_entry_folder_t *folder;

    if (parent->type != KEYSTORE_ENTRY_TYPE_FOLDER) {
        return keystore_error_set(&keystore->error, KEYSTORE_ERROR_TYPE, 0, "Parent is not a folder");
    }

    *iterator = calloc(1, sizeof(**iterator));
    if (*iterator == NULL) {
        return keystore_error_set(&keystore->error, KEYSTORE_ERROR_MEM, 0, "Out of memory");
    }

    folder = (keystore_entry_folder_t *)parent->data;

    (*iterator)->entry_orig = folder->head;
    (*iterator)->entry = folder->head;
    (*iterator)->size = folder->size;

    return keystore_error_ok(&keystore->error);
}

keystore_error_t
keystore_entry_move_entry(keystore_t *keystore, keystore_entry_t *entry, keystore_entry_t *dst) {
    keystore_error_t error;
    keystore_entry_folder_t *folder;
    keystore_entry_t *parent, *prev;

    if (entry->parent == NULL) {
        return keystore_error_set(&keystore->error, KEYSTORE_ERROR_INVALID, 0, "Cannot move the root folder");
    }
    if (entry->parent->type != KEYSTORE_ENTRY_TYPE_FOLDER) {
        return keystore_error_set(&keystore->error, KEYSTORE_ERROR_TYPE, 0, "Parent is not a folder");
    }
    if (keystore_entry_type(dst) != KEYSTORE_ENTRY_TYPE_FOLDER) {
        return keystore_error_set(&keystore->error, KEYSTORE_ERROR_TYPE, 0, "Destination entry is not a folder");
    }

    parent = entry->parent;
    folder = (keystore_entry_folder_t *)parent->data;

    error = keystore_entry_add_entry(keystore, dst, entry);
    if (error != KEYSTORE_ERROR_OK) {
        return error;
    }

    if (folder->head == entry) {
        folder->head = entry->next;
    }
    else {
        prev = folder->head;
        while (prev->next != entry) {
            prev = prev->next;
        }

        prev->next = entry->next;

        if (folder->tail == entry) {
            folder->tail = prev;
        }
    }

    parent->modified = time(NULL);
    --folder->size;

    return keystore_error_ok(&keystore->error);
}

keystore_error_t
keystore_entry_delete_entry(keystore_t *keystore, keystore_entry_t *entry, int flags) {
    keystore_entry_folder_t *folder;
    keystore_entry_t *parent, *prev;

    if (entry->parent == NULL) {
        return keystore_error_set(&keystore->error, KEYSTORE_ERROR_INVALID, 0, "Cannot delete the root folder");
    }

    if (entry->parent->type != KEYSTORE_ENTRY_TYPE_FOLDER) {
        return keystore_error_set(&keystore->error, KEYSTORE_ERROR_TYPE, 0, "Parent is not a folder");
    }

    if (entry->type == KEYSTORE_ENTRY_TYPE_FOLDER) {
        folder = (keystore_entry_folder_t *)entry->data;
        if (folder->size > 0 && !(flags & KEYSTORE_ENTRY_DELETE_FLAG_RECURSIVE)) {
            return keystore_error_set(&keystore->error, KEYSTORE_ERROR_INVALID, 0, "Cannot delete non-empty folder");
        }
    }

    parent = entry->parent;
    folder = (keystore_entry_folder_t *)parent->data;

    if (folder->head == entry) {
        folder->head = entry->next;
    }
    else {
        prev = folder->head;
        while (prev->next != entry) {
            prev = prev->next;
        }

        prev->next = entry->next;

        if (folder->tail == entry) {
            folder->tail = prev;
        }
    }

    parent->modified = time(NULL);
    --folder->size;

    keystore_entry_free(entry);

    return keystore_error_ok(&keystore->error);
}

//keystore_entry_read will free memory if this fails
static keystore_error_t
keystore_entry_read_note(keystore_t *keystore, keystore_entry_note_t *note) {
    keystore_error_t error;

    error = keystore_read_uint32(keystore, &note->value_len);
    if (error != KEYSTORE_ERROR_OK) {
        goto done;
    }

    note->value = malloc(note->value_len + 1);
    if (note->value == NULL) {
        error = keystore_error_set(&keystore->error, KEYSTORE_ERROR_MEM, 0, "Out of memory");
        goto done;
    }

    error = keystore_read_strn(keystore, note->value, note->value_len);
    if (error != KEYSTORE_ERROR_OK) {
        goto done;
    }

done:
    return error;
}

static keystore_error_t
keystore_entry_read_folder(keystore_t *keystore, keystore_entry_t *entry, keystore_entry_folder_t *folder) {
    keystore_entry_t *entry_item;
    keystore_error_t error;
    uint32_t i;

    error = keystore_read_uint32(keystore, &folder->size);
    if (error != KEYSTORE_ERROR_OK) {
        goto done;
    }

    for (i = 0; i < folder->size; i++) {
        error = keystore_entry_read(keystore, entry, &entry_item);
        if (error != KEYSTORE_ERROR_OK) {
            break;
        }

        //No nodes: H -> <- T
        //1 node:   H -> O -> <- T
        //2 nodes:  H -> O -> O -> <- T

        if (i == 0) {
            folder->head = entry_item;
            folder->tail = entry_item;
        }
        else {
            folder->tail->next = entry_item;
            folder->tail = entry_item;
        }
    }

done:
    return error;
}

keystore_error_t
keystore_entry_read(keystore_t *keystore, keystore_entry_t *parent, keystore_entry_t **entry) {
    keystore_entry_t *entry_new = NULL;
    keystore_error_t error;
    uint8_t type;

    error = keystore_read_uint8(keystore, &type);
    if (error != KEYSTORE_ERROR_OK) {
        goto done;
    }

    switch (type) {
        case KEYSTORE_ENTRY_TYPE_NOTE:
        case KEYSTORE_ENTRY_TYPE_FOLDER:
            break;
        default:
            error = keystore_error_set(&keystore->error, KEYSTORE_ERROR_TYPE, 0, "Invalid type");
            break;
    }

    if (error != KEYSTORE_ERROR_OK) {
        goto done;
    }

    entry_new = calloc(1, sizeof(*entry_new));
    if (entry_new == NULL) {
        error = keystore_error_set(&keystore->error, KEYSTORE_ERROR_MEM, 0, "Out of memory");
        goto done;
    }

    entry_new->type = type;

    error = keystore_read_uint16(keystore, &entry_new->name_len);
    if (error != KEYSTORE_ERROR_OK) {
        goto done;
    }

    entry_new->name = calloc(1, entry_new->name_len + 1);
    if (entry_new->name == NULL) {
        error = keystore_error_set(&keystore->error, KEYSTORE_ERROR_MEM, 0, "Out of memory");
        goto done;
    }

    error = keystore_read_strn(keystore, entry_new->name, entry_new->name_len);
    if (error != KEYSTORE_ERROR_OK) {
        goto done;
    }

    error = keystore_read_int64(keystore, &entry_new->created);
    if (error != KEYSTORE_ERROR_OK) {
        goto done;
    }

    error = keystore_read_int64(keystore, &entry_new->modified);
    if (error != KEYSTORE_ERROR_OK) {
        goto done;
    }

    switch (type) {
        case KEYSTORE_ENTRY_TYPE_NOTE:
            entry_new->data = keystore_entry_init_note();
            if (entry_new->data == NULL) {
                error = keystore_error_set(&keystore->error, KEYSTORE_ERROR_MEM, 0, "Out of memory");
            }
            else {
                error = keystore_entry_read_note(keystore, (keystore_entry_note_t *)entry_new->data);
            }

            break;
        case KEYSTORE_ENTRY_TYPE_FOLDER:
            entry_new->data = keystore_entry_init_folder();
            if (entry_new->data == NULL) {
                error = keystore_error_set(&keystore->error, KEYSTORE_ERROR_MEM, 0, "Out of memory");
            }
            else {
                error = keystore_entry_read_folder(keystore, entry_new, (keystore_entry_folder_t *)entry_new->data);
            }

            break;
    }

    if (error != KEYSTORE_ERROR_OK) {
        goto done;
    }

    entry_new->parent = parent;
    *entry = entry_new;
    error = keystore_error_ok(&keystore->error);

done:
    if (error != KEYSTORE_ERROR_OK) {
        if (entry_new != NULL) {
            keystore_entry_free(entry_new);
        }
    }

    return error;
}

static keystore_error_t
keystore_entry_write_note(keystore_t *keystore, keystore_entry_note_t *note) {
    keystore_error_t error;

    error = keystore_write_uint32(keystore, note->value_len);
    if (error != KEYSTORE_ERROR_OK) {
        goto done;
    }

    error = keystore_write_strn(keystore, note->value, note->value_len);
    if (error != KEYSTORE_ERROR_OK) {
        goto done;
    }

done:
    return error;
}

static keystore_error_t
keystore_entry_write_folder(keystore_t *keystore, keystore_entry_folder_t *folder) {
    keystore_entry_t *entry;
    keystore_error_t error;

    error = keystore_write_uint32(keystore, folder->size);
    if (error != KEYSTORE_ERROR_OK) {
        goto done;
    }

    entry = folder->head;
    while (entry != NULL) {
        error = keystore_entry_write(keystore, entry);
        if (error != KEYSTORE_ERROR_OK) {
            goto done;
        }

        entry = entry->next;
    }

done:
    return error;
}

keystore_error_t
keystore_entry_write(keystore_t *keystore, keystore_entry_t *entry) {
    keystore_error_t error;

    error = keystore_write_uint8(keystore, entry->type);
    if (error != KEYSTORE_ERROR_OK) {
        goto done;
    }

    error = keystore_write_uint16(keystore, entry->name_len);
    if (error != KEYSTORE_ERROR_OK) {
        goto done;
    }

    error = keystore_write_strn(keystore, entry->name, entry->name_len);
    if (error != KEYSTORE_ERROR_OK) {
        goto done;
    }

    error = keystore_write_int64(keystore, entry->created);
    if (error != KEYSTORE_ERROR_OK) {
        goto done;
    }

    error = keystore_write_int64(keystore, entry->modified);
    if (error != KEYSTORE_ERROR_OK) {
        goto done;
    }

    switch (entry->type) {
        case KEYSTORE_ENTRY_TYPE_NOTE:
            error = keystore_entry_write_note(keystore, (keystore_entry_note_t *)entry->data);
            break;
        case KEYSTORE_ENTRY_TYPE_FOLDER:
            error = keystore_entry_write_folder(keystore, (keystore_entry_folder_t *)entry->data);
            break;
    }

done:

    return error;
}

const char *
keystore_entry_type_str(keystore_entry_type_t type) {
    switch (type) {
        case KEYSTORE_ENTRY_TYPE_NOTE:
            return "Note";
        case KEYSTORE_ENTRY_TYPE_FOLDER:
            return "Folder";
    }

    return "Unknown";
}
