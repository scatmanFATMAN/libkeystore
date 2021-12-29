#pragma once

#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include "keystore.h"
#include "crypt.h"
#include "error_internal.h"

typedef struct {
    char magic[4];                              //!< Defines a KeyStore file.
    uint8_t version[3];                         //!< The version of the KeyStore; 0=major, 1=minor, 2=patch
    unsigned char iv[CRYPT_AES256_IV_SIZE];     //!< The IV for AES256 CBC encryption of the KeyStore when saved.
    char password[CRYPT_BCRYPT_SIZE + 1];       //!< The bcrypt'd password to decrypt the KeyStore.
} keystore_header_t;

struct keystore_entry_t {
    keystore_entry_type_t type;
    uint16_t name_len;
    char *name;
    time_t created;
    time_t modified;
    void *data;
    struct keystore_entry_t *parent;
    struct keystore_entry_t *next;
};

typedef struct {
    uint32_t value_len;
    char *value;
} keystore_entry_note_t;

typedef struct {
    uint32_t size;
    struct keystore_entry_t *head;
    struct keystore_entry_t *tail;
} keystore_entry_folder_t;

struct keystore_entry_iterator_t {
    keystore_entry_t *entry_orig;
    keystore_entry_t *entry;
    unsigned int size;
};

struct keystore_t {
    FILE *f;
    keystore_errors_t error;
    keystore_header_t header;
    struct keystore_entry_t *root;
};
