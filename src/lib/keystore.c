#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include "error_internal.h"
#include "keystore_internal.h"
#include "version.h"
#include "util.h"
#include "fs.h"
#include "io.h"
#include "crypt.h"
#include "keystore.h"

#define KEYSTORE_FILE_PREFIX     "KSSN"
#define KEYSTORE_FILE_PREFIX_LEN 4

static int initialized = 0;

//forward declarations for things that shouldn't be public
keystore_error_t keystore_entry_read(keystore_t *keystore, keystore_entry_t *parent, keystore_entry_t **entry);
keystore_error_t keystore_entry_write(keystore_t *keystore, keystore_entry_t *entry);

keystore_t *
keystore_init() {
    keystore_t *keystore;

    if (initialized++ == 0) {
        crypt_init();
    }

    keystore = calloc(1, sizeof(*keystore));

    return keystore;
}

void
keystore_free(keystore_t *keystore) {
    if (--initialized == 0) {
        crypt_free();

        //protect against people calling keystore_free() too many times
        if (initialized < 0) {
            initialized = 0;
        }
    }

    if (keystore != NULL) {
        keystore_close(keystore);
        free(keystore);
    }
}


//TODO: only keep ->error?
static void
keystore_close_no_reset(keystore_t *keystore) {
    if (keystore != NULL) {
        if (keystore->f != NULL) {
            fclose(keystore->f);
            keystore->f = NULL;
        }

        if (keystore->root != NULL) {
            keystore_entry_free(keystore->root);
        }
    }
}

keystore_error_t
keystore_open(keystore_t *keystore, const char *path, const char *password) {
    keystore_error_t error = KEYSTORE_ERROR_OK;

    keystore->f = fopen(path, "rb+");
    if (keystore->f == NULL) {
        error = keystore_error_set(&keystore->error, KEYSTORE_ERROR_OPEN, errno, "%s", strerror(errno));
        goto done;
    }

    //reader the header: magic
    error = keystore_read(keystore, (unsigned char *)keystore->header.magic, 4);
    if (error != KEYSTORE_ERROR_OK) {
        goto done;
    }

    if (strncmp(keystore->header.magic, KEYSTORE_FILE_PREFIX, KEYSTORE_FILE_PREFIX_LEN) != 0) {
        error = keystore_error_set(&keystore->error, KEYSTORE_ERROR_INVALID, 0, "Not a keystore file");
        goto done;
    }

    //read the header: version
    error = keystore_read(keystore, keystore->header.version, 3);
    if (error != KEYSTORE_ERROR_OK) {
        goto done;
    }

    if (keystore->header.version[0] > VERSION_MAJOR) {
        error = keystore_error_set(&keystore->error, KEYSTORE_ERROR_VERSION, 0, "Invalid major version");
        goto done;
    }

    //read the header: IV
    error = keystore_read(keystore, keystore->header.iv, sizeof(keystore->header.iv));
    if (error != KEYSTORE_ERROR_OK) {
        goto done;
    }

    //read the header: password
    error = keystore_read(keystore, (unsigned char *)keystore->header.password, sizeof(keystore->header.password) - 1);
    if (error != KEYSTORE_ERROR_OK) {
        goto done;
    }

    keystore->header.password[sizeof(keystore->header.password) - 1] = '\0';

    error = crypt_bcrypt_matches(&keystore->error, password, keystore->header.password);
    if (error != KEYSTORE_ERROR_OK) {
        goto done;
    }

    error = keystore_entry_read(keystore, NULL, &keystore->root);

done:
    if (error != KEYSTORE_ERROR_OK) {
        keystore_close_no_reset(keystore);
        //keystore_close(keystore);
    }

    return error;
}

keystore_error_t
keystore_close(keystore_t *keystore) {
    if (keystore != NULL) {
        keystore_close_no_reset(keystore);
        util_memzero(keystore, sizeof(*keystore));
    }

    return keystore_error_ok(&keystore->error);
}

int
keystore_version_major(keystore_t *keystore) {
    return keystore == NULL ? -1 : keystore->header.version[0];
}

int
keystore_version_minor(keystore_t *keystore) {
    return keystore == NULL ? -1 : keystore->header.version[1];
}

int
keystore_version_patch(keystore_t *keystore) {
    return keystore == NULL ? -1 : keystore->header.version[2];
}

const char *
keystore_error(keystore_t *keystore) {
    return keystore == NULL ? NULL : keystore->error.error_str;
}

keystore_entry_t *
keystore_root(keystore_t *keystore) {
    if (keystore_is_open(keystore)) {
        return keystore->root;
    }

    return NULL;
}

bool
keystore_is_open(keystore_t *keystore) {
    return keystore != NULL && keystore->f != NULL;
}

keystore_error_t
keystore_create(keystore_t *keystore, const char *path, const char *password) {
    keystore_error_t error = KEYSTORE_ERROR_OK;

    if (fs_file_exists(path)) {
        error = keystore_error_set(&keystore->error, KEYSTORE_ERROR_FILE_EXISTS, 0, "File exists");
        return error;
    }

    keystore->f = fopen(path, "wb+");
    if (keystore->f == NULL) {
        error = keystore_error_set(&keystore->error, KEYSTORE_ERROR_OPEN, errno, "%s", strerror(errno));
        return error;
    }

    memcpy(keystore->header.magic, KEYSTORE_FILE_PREFIX, KEYSTORE_FILE_PREFIX_LEN);
    keystore->header.version[0] = VERSION_MAJOR;
    keystore->header.version[1] = VERSION_MINOR;
    keystore->header.version[2] = VERSION_PATCH;

    error = crypt_bcrypt(&keystore->error, NULL, password, keystore->header.password);
    if (error != KEYSTORE_ERROR_OK) {
        goto done;
    }

    keystore->root = keystore_entry_init(keystore, KEYSTORE_ENTRY_TYPE_FOLDER, "root");

    keystore_save(keystore);

done:
    keystore_close_no_reset(keystore);
    //keystore_close(keystore);

    return error;
}

//#error TODO: change keystore_write and keystore_read functions to take the keystore_errors struct

keystore_error_t
keystore_save(keystore_t *keystore) {
    keystore_error_t error;

    rewind(keystore->f);

    //generate an IV used to encrypt the file
    //everytime the file is saved, we'll generate a new IV
    error = crypt_aes256_iv(&keystore->error, keystore->header.iv);
    if (error != KEYSTORE_ERROR_OK) {
        return error;
    }

    error = keystore_write(keystore, (unsigned char *)keystore->header.magic, 4);
    if (error == KEYSTORE_ERROR_OK) {
        error = keystore_write(keystore, keystore->header.version, 3);
    }

    if (error == KEYSTORE_ERROR_OK) {
        error = keystore_write(keystore, keystore->header.iv, sizeof(keystore->header.iv));
    }

    if (error == KEYSTORE_ERROR_OK) {
        error = keystore_write(keystore, (unsigned char *)keystore->header.password, sizeof(keystore->header.password) - 1);
        
    }

    //write the root and recursively write all entries
    error = keystore_entry_write(keystore, keystore->root);

    if (error == KEYSTORE_ERROR_OK ) {
        fflush(keystore->f);
    }

    return error;
}
