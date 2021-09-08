#pragma once

#include <stdio.h>
#include <stdint.h>
#include "keystore.h"
#include "crypt.h"
#include "error_internal.h"

typedef struct {
    char magic[4];
    uint8_t version[3];
    char password[CRYPT_BCRYPT_SIZE + 1];
} keystore_header_t;

struct keystore_entry_t {
    keystore_entry_type_t type;
    char name[KEYSTORE_ENTRY_NAME_MAX + 1];
};

struct keystore_t {
    FILE *f;
    keystore_errors_t error;
    keystore_header_t header;
    struct keystore_entry_t *entry;
};
