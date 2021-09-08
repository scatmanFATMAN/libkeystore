#pragma once

#include <stdbool.h>
#include "error.h"

#define KEYSTORE_ENTRY_NAME_MAX 255

typedef struct keystore_t keystore_t;
typedef struct keystore_entry_t keystore_entry_t;

typedef enum {
    KEYSTORE_ENTRY_TYPE_INVALID,
    KEYSTORE_ENTRY_TYPE_ENTRY,
    KEYSTORE_ENTRY_TYPE_FOLDER
} keystore_entry_type_t;

keystore_t * keystore_init();
void keystore_free(keystore_t *keystore);

keystore_error_t keystore_open(keystore_t *keystore, const char *path, const char *password);
keystore_error_t keystore_close(keystore_t *keystore);

int keystore_version_major(keystore_t *keystore);
int keystore_version_minor(keystore_t *keystore);
int keystore_version_patch(keystore_t *keystore);

const char * keystore_error(keystore_t *keystore);

bool keystore_is_open(keystore_t *keystore);

keystore_error_t keystore_create(keystore_t *keystore, const char *path, const char *password);
keystore_error_t keystore_save(keystore_t *keystore);

keystore_error_t keystore_add_entry(keystore_t *keystore, keystore_entry_t *entry);

keystore_entry_t * keystore_entry_init(keystore_t *keystore, keystore_entry_type_t type, const char *name);
void keystore_entry_free(keystore_entry_t *entry);

keystore_entry_type_t keystore_entry_type(keystore_entry_t *entry);
const char * keystore_entry_name(keystore_entry_t *entry);
