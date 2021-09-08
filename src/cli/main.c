#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <keystore/keystore.h>
#include "version.h"
#include "sep.h"

#define FLAG_REQUIRE_NOT_OPEN (1 << 0)
#define FLAG_REQUIRE_OPEN     (1 << 1)

typedef struct {
    const char *cmd;
    int flags;
    bool (*func)(keystore_t *, sep_t *);
    const char *short_desc;
} handler_t;

static bool handle_close(keystore_t *keystore, sep_t *sep);
static bool handle_create(keystore_t *keystore, sep_t *sep);
static bool handle_help(keystore_t *keystore, sep_t *sep);
static bool handle_open(keystore_t *keystore, sep_t *sep);
static bool handle_quit(keystore_t *keystore, sep_t *sep);
static bool handle_version(keystore_t *keystore, sep_t *sep);

static handler_t handlers[] = {
    {"close",        FLAG_REQUIRE_OPEN,     handle_close,   "Closes a KeyStore."},
    {"create",       FLAG_REQUIRE_NOT_OPEN, handle_create,  "Creates a KeyStore."},
    {"help",         0,                     handle_help,    "Displays this."},
    {"open",         FLAG_REQUIRE_NOT_OPEN, handle_open,    "Opens a KeyStore."},
    {"quit|exit",    0,                     handle_quit,    "Quits the application."},
    {"version",      FLAG_REQUIRE_OPEN,     handle_version, "Displays the version of the KeyStore."},
    {NULL, false, NULL, NULL}
};

bool
handle_close(keystore_t *keystore, sep_t *sep) {
    keystore_close(keystore);

    printf("KeyStore closed.\n");

    return true;
}

bool
handle_create(keystore_t *keystore, sep_t *sep) {
    if (sep_size(sep) < 3) {
        printf("Usage: create <file> <password>.\n");
        return true;
    }

    if (keystore_create(keystore, sep_get(sep, 1), sep_get(sep, 2)) != KEYSTORE_ERROR_OK) {
        printf("%s\n", keystore_error(keystore));
        return true;
    }

    printf("Keystore created.\n");
    return true;
}

bool
handle_help(keystore_t *keystore, sep_t *sep) {
    int i;

    for (i = 0; handlers[i].func != NULL; i++) {
        printf("%s - %s\n", handlers[i].cmd, handlers[i].short_desc);
    }

    return true;
}

bool
handle_open(keystore_t *keystore, sep_t *sep) {
    if (sep_size(sep) < 3) {
        printf("Usage: open <file> <password>.\n");
        return true;
    }

    if (keystore_open(keystore, sep_get(sep, 1), sep_get(sep, 2)) != KEYSTORE_ERROR_OK) {
        printf("%s\n", keystore_error(keystore));
        return true;
    }

    printf("Keystore opened.\n");
    return true;
}

bool
handle_quit(keystore_t *keystore, sep_t *sep) {
    printf("Good bye.\n");
    return false;
}

bool
handle_version(keystore_t *keystore, sep_t *sep) {
    printf("Version %d.%d.%d\n", keystore_version_major(keystore), keystore_version_minor(keystore), keystore_version_patch(keystore));
    return true;
}

static handler_t *
find_handler(keystore_t *keystore, const char *cmd) {
    handler_t *handler = NULL;
    char *cmd_dupe, *cmd_ptr;
    bool found = false;
    int i;

    for (i = 0; !found && handlers[i].func != NULL; i++) {
        cmd_dupe = strdup(handlers[i].cmd);
        cmd_ptr = strtok(cmd_dupe, "|");

        while (cmd_ptr != NULL) {
            if (strcmp(cmd_ptr, cmd) == 0) {
                found = true;

                if (handlers[i].flags & FLAG_REQUIRE_NOT_OPEN && keystore_is_open(keystore)) {
                    printf("You must not have a KeyStore open.\n");
                }
                else if (handlers[i].flags & FLAG_REQUIRE_OPEN && !keystore_is_open(keystore)) {
                    printf("You must first open a KeyStore.\n");
                }
                else {
                    handler = &handlers[i];
                }

                break;
            }

            cmd_ptr = strtok(NULL, "|");
        }

        free(cmd_dupe);
    }

    if (!found) {
        printf("Command '%s' not found\n", cmd);
    }

    return handler;
}

int
main(int argc, char **argv) {
    const char *cmd;
    char line[2048];
    bool running;
    sep_t sep;
    handler_t *handler;
    keystore_t *keystore;

    printf("%s %d.%d.%d\n", VERSION_NAME, VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH);

    keystore = keystore_init();
    if (keystore == NULL) {
        fprintf(stderr, "Out of memory");
        return 1;
    }

    printf("\nType `help` for help.\n");

    running = true;

    while (running) {
        if (!keystore_is_open(keystore)) {
            printf("\n[Not logged in]> ");
        }
        else {
            printf("\n[ll]> ");
        }

        if (fgets(line, sizeof(line), stdin) == NULL) {
            fprintf(stderr, "Error getting input\n");
            break;
        }

        sep_init(&sep);
        sep_parse(&sep, line);
        cmd = sep_get(&sep, 0);

        handler = find_handler(keystore, cmd);
        if (handler != NULL) {
            running = handler->func(keystore, &sep);
        }

        sep_free(&sep);
    }

    if (keystore_is_open(keystore)) {
        keystore_close(keystore);
    }
    keystore_free(keystore);

    return 0;
}
