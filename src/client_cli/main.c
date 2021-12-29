#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <keystore/keystore.h>
#if defined(_WIN32)
# include <Windows.h>
# define PATH_MAX MAX_PATH
#else
# include <linux/limits.h>
#endif
#include "../common/os.h"
#include "version.h"
#include "color.h"
#include "sep.h"

#define FLAG_REQUIRE_NOT_OPEN (1 << 0)
#define FLAG_REQUIRE_OPEN     (1 << 1)

typedef struct {
    char file[256];
    keystore_entry_t *entry;
    int path_len;
    char path[PATH_MAX];
    bool dirty;
} state_t;

typedef struct {
    const char *cmd;
    int flags;
    bool (*func)(keystore_t *, sep_t *, state_t *);
    const char *short_desc;
} handler_t;

typedef struct {
    char path[PATH_MAX];
    int path_len;
    keystore_entry_t *entry;
    char error[256];
} path_info_t;

static bool handle_add(keystore_t *keystore, sep_t *sep, state_t *state);
static bool handle_cd(keystore_t *keystore, sep_t *sep, state_t *state);
static bool handle_close(keystore_t *keystore, sep_t *sep, state_t *state);
static bool handle_create(keystore_t *keystore, sep_t *sep, state_t *state);
static bool handle_date(keystore_t *keystore, sep_t *sep, state_t *state);
static bool handle_help(keystore_t *keystore, sep_t *sep, state_t *state);
static bool handle_ls(keystore_t *keystore, sep_t *sep, state_t *state);
static bool handle_mkdir(keystore_t *keystore, sep_t *sep, state_t *state);
static bool handle_mv(keystore_t *keystore, sep_t *sep, state_t *state);
static bool handle_open(keystore_t *keystore, sep_t *sep, state_t *state);
static bool handle_quit(keystore_t *keystore, sep_t *sep, state_t *state);
static bool handle_rename(keystore_t *keystore, sep_t *sep, state_t *state);
static bool handle_rm(keystore_t *keystore, sep_t *sep, state_t *state);
static bool handle_rmdir(keystore_t *keystore, sep_t *sep, state_t *state);
static bool handle_save(keystore_t *keystore, sep_t *sep, state_t *state);
static bool handle_version(keystore_t *keystore, sep_t *sep, state_t *state);

static handler_t handlers[] = {
    {"add",          FLAG_REQUIRE_OPEN,     handle_add,     "Adds an entry to the KeyStore."},
    {"cd",           FLAG_REQUIRE_OPEN,     handle_cd,      "Changes the current folder."},
    {"close",        FLAG_REQUIRE_OPEN,     handle_close,   "Closes a KeyStore."},
    {"create",       FLAG_REQUIRE_NOT_OPEN, handle_create,  "Creates a KeyStore."},
    {"date",         0,                     handle_date,    "Displays the current date."},
    {"help",         0,                     handle_help,    "Displays this."},
    {"ls",           FLAG_REQUIRE_OPEN,     handle_ls,      "Displays all entries in the current folder."},
    {"mkdir",        FLAG_REQUIRE_OPEN,     handle_mkdir,   "Add a folder to the KeyStore."},
    {"mv",           FLAG_REQUIRE_OPEN,     handle_mv,      "Moves a KeyStore entry to another folder."},
    {"open",         FLAG_REQUIRE_NOT_OPEN, handle_open,    "Opens a KeyStore."},
    {"quit|exit",    0,                     handle_quit,    "Quits the application."},
    {"rename",       FLAG_REQUIRE_OPEN,     handle_rename,  "Renames an entry."},
    {"rm",           FLAG_REQUIRE_OPEN,     handle_rm,      "Removes an entry from the current folder."},
    {"rmdir",        FLAG_REQUIRE_OPEN,     handle_rmdir,   "Removes a folder from the current folder."},
    {"save",         FLAG_REQUIRE_OPEN,     handle_save,    "Saves the KeyStore."},
    {"version",      0,                     handle_version, "Displays the version of the KeyStore client and library if open."},
    {NULL, false, NULL, NULL}
};

static void
handle_signal(int sig) {
    printf("Please use the 'quit' or 'exit' command to quit.\n");
}

static bool
get_path_info(keystore_t *keystore, state_t *state, const char *path, path_info_t *info) {
    char *path_dupe[2], *ptr, *save;
    bool success = true;

    memset(info, 0, sizeof(*info));

    //0 needs to remain at the beginning so free() knows what to do
    //1 can be incremented
    path_dupe[0] = strdup(path);
    path_dupe[1] = path_dupe[0];

    if (path_dupe[1][0] == '/') {
        info->entry = keystore_root(keystore);
        info->path_len = snprintf(info->path, sizeof(info->path), "%s", "/");
        ++path_dupe[1];
    }
    else {
        info->entry = state->entry;
        info->path_len = state->path_len;
        strcpy(info->path, state->path);
    }

    ptr = strtok_r(path_dupe[1], "/", &save);
    while (ptr != NULL) {
        if (strcmp(ptr, ".") != 0) {
            if (strcmp(ptr, "..") == 0) {
                if (keystore_entry_parent(info->entry) != NULL) {
                    info->entry = keystore_entry_parent(info->entry);

                    while (info->path_len >= 0 && info->path[info->path_len - 1] != '/') {
                        info->path[info->path_len - 1] = '\0';
                        --info->path_len;
                    }

                    //remove the last slash if we're not root
                    if (info->path_len > 1) {
                        info->path[info->path_len - 1] = '\0';
                        --info->path_len;
                    }
                }
            }
            else {
                if (keystore_entry_get_entry(keystore, info->entry, ptr, &info->entry) != KEYSTORE_ERROR_OK) {
                    strcpy(info->error, keystore_error(keystore));
                    success = false;
                    break;
                }

                if (strcmp(info->path, "/") == 0) {
                    //we're in the root directory, so just replace the entire path with /<entry name>
                    info->path_len = snprintf(info->path, sizeof(info->path), "/%s", keystore_entry_name(info->entry));
                }
                else {
                    //we're not in the root path, so we need to append the entry's name with a /
                    info->path_len += snprintf(info->path + info->path_len, sizeof(info->path) - info->path_len, "/%s", keystore_entry_name(info->entry));
                }
            }

//            if (keystore_entry_type(info->entry) != KEYSTORE_ENTRY_TYPE_FOLDER) {
//                strcpy(info->error, "Not a folder.\n");
//                success = false;
//                break;
//            }
        }

        ptr = strtok_r(NULL, "/", &save);
    }

    free(path_dupe[0]);

    return success;
}

bool
handle_add(keystore_t *keystore, sep_t *sep, state_t *state) {
    const char *name, *value = NULL;
    keystore_entry_t *entry;

    if (sep_size(sep) < 2) {
        printf("Usage: add <name> [value]\n");
        return true;
    }

    name = sep_get(sep, 1);
    if (sep_size(sep) >= 3) {
        value = sep_get(sep, 2);
    }

    entry = keystore_entry_init(keystore, KEYSTORE_ENTRY_TYPE_NOTE, name);
    keystore_entry_set_value(keystore, entry, value);
    keystore_entry_add_entry(keystore, state->entry, entry);
    state->dirty = true;

    printf("Note added.\n");

    return true;
}

bool
handle_cd(keystore_t *keystore, sep_t *sep, state_t *state) {
    path_info_t info;
    const char *path;
    bool success = true;

    if (sep_size(sep) < 2) {
        printf("Usage: cd <path>\n");
        return true;
    }

    path = sep_get(sep, 1);

    success = get_path_info(keystore, state, path, &info);
    if (!success) {
        printf("%s\n", info.error);
        return true;
    }

    state->entry = info.entry;
    state->path_len = info.path_len;
    strcpy(state->path, info.path);

    return true;
}

bool
handle_close(keystore_t *keystore, sep_t *sep, state_t *state) {
    char answer[32], *ptr;
    int decision = -1;

    if (state->dirty) {
        while (decision == -1) {
            printf("The KeyStore has unsaved changes. Would you like to save before closing [yes|no|cancel]? ");
            fgets(answer, sizeof(answer), stdin);

            ptr = strchr(answer, '\n');
            if (ptr != NULL) {
                *ptr = '\0';
            }

            if (strcasecmp(answer, "yes") == 0) {
                decision = 0;
            }
            else if (strcasecmp(answer, "no") == 0) {
                decision = 1;
            }
            else if (strcasecmp(answer, "cancel") == 0) {
                decision = 2;
            }
        }

        if (decision == 0) {
            if (keystore_save(keystore) == KEYSTORE_ERROR_OK) {
                printf("KeyStore saved.\n");
            }
            else {
                printf("%s\n", keystore_error(keystore));
                return true;
            }
        }
        else if (decision == 2) {
            return true;
        }
    }

    keystore_close(keystore);
    printf("KeyStore closed.\n");

    return true;
}

bool
handle_create(keystore_t *keystore, sep_t *sep, state_t *state) {
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
handle_date(keystore_t *keystore, sep_t *sep, state_t *state) {
    time_t now;
    struct tm tm;

    memset(&tm, 0, sizeof(tm));

    now = time(NULL);
    localtime_r(&now, &tm);

    printf("%d-%02d-%02d %02d:%02d:%02d\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
    return true;
}

bool
handle_help(keystore_t *keystore, sep_t *sep, state_t *state) {
    int i;

    for (i = 0; handlers[i].func != NULL; i++) {
        color_printf(COLOR_GREEN, "%s", handlers[i].cmd);
        printf(" - %s\n", handlers[i].short_desc);
    }

    return true;
}

static void
handle_ls_print_entry(keystore_entry_t *entry, bool l) {
    keystore_entry_type_t type;
    time_t created, modified;
    struct tm tm_created, tm_modified;

    type = keystore_entry_type(entry);

    printf("  ");
    switch (type) {
        case KEYSTORE_ENTRY_TYPE_NOTE:
            printf(" ");
            break;
        case KEYSTORE_ENTRY_TYPE_FOLDER:
            color_set(COLOR_BLUE);
            printf("f");
            break;
    }

    printf(" %s\n", keystore_entry_name(entry));
    color_reset();

    if (l) {
        created = keystore_entry_created(entry);
        modified = keystore_entry_modified(entry);

        localtime_r(&created, &tm_created);
        localtime_r(&modified, &tm_modified);

        printf("      Created: %d-%02d-%02d %02d:%02d:%02d | Modified: %d-%02d-%02d %02d:%02d:%02d\n",
            tm_created.tm_year + 1900, tm_created.tm_mon + 1, tm_created.tm_mday, tm_created.tm_hour, tm_created.tm_min, tm_created.tm_sec,
            tm_modified.tm_year + 1900, tm_modified.tm_mon + 1, tm_modified.tm_mday, tm_modified.tm_hour, tm_modified.tm_min, tm_modified.tm_sec);
    }
}

bool
handle_ls(keystore_t *keystore, sep_t *sep, state_t *state) {
    keystore_entry_iterator_t *itr;
    keystore_entry_t *entry;
    path_info_t info;
    const char *path;
    bool l = false;

    if (sep_size(sep) >= 3) {
        if (sep_equals(sep, 1, "-l")) {
            printf("Usage: ls -l <path>\n");
        }

        l = true;
        path = sep_get(sep, 2);
    }
    else if (sep_size(sep) == 2) {
        if (sep_equals(sep, 1, "-l")) {
            l = true;
            path = ".";
        }
        else {
            path = sep_get(sep, 1);
        }
    }
    else {
        path = ".";
    }

    if (!get_path_info(keystore, state, path, &info)) {
        printf("%s\n", info.error);
        return true;
    }

    if (keystore_entry_type(info.entry) == KEYSTORE_ENTRY_TYPE_NOTE) {
        handle_ls_print_entry(info.entry, l);
    }
    else if (keystore_entry_type(info.entry) == KEYSTORE_ENTRY_TYPE_FOLDER) {
        keystore_entry_get_entries(keystore, info.entry, &itr);
        while (keystore_entry_iterator_has_next(itr)) {
            entry = keystore_entry_iterator_next(itr);
            handle_ls_print_entry(entry, l);
        }
        printf("%u entries.\n", keystore_entry_iterator_size(itr));

        keystore_entry_iterator_free(itr);
    }

    return true;
}

bool
handle_mkdir(keystore_t *keystore, sep_t *sep, state_t *state) {
    const char *path;
    char name[KEYSTORE_ENTRY_NAME_MAX + 1], dir[PATH_MAX];
    keystore_entry_t *entry;
    path_info_t info;

    if (sep_size(sep) < 1) {
        printf("Usage: mkdir <path>\n");
        return true;
    }

    path = sep_get(sep, 1);
    os_dirname(path, dir, sizeof(dir));
    os_basename(path, name, sizeof(name));

    if (!get_path_info(keystore, state, dir, &info)) {
        printf("%s\n", keystore_error(keystore));
        return true;
    }

    if (keystore_entry_type(info.entry) != KEYSTORE_ENTRY_TYPE_FOLDER) {
        printf("Desination is not a folder.\n");
        return true;
    }

    entry = keystore_entry_init(keystore, KEYSTORE_ENTRY_TYPE_FOLDER, name);
    if (keystore_entry_add_entry(keystore, info.entry, entry) != KEYSTORE_ERROR_OK) {
        printf("%s\n", info.error);
        return true;
    }

    state->dirty = true;
    printf("Folder added.\n");

    return true;
}

bool
handle_mv(keystore_t *keystore, sep_t *sep, state_t *state) {
    const char *path[2];
    path_info_t info[2];

    if (sep_size(sep) < 3) {
        printf("Usage: mv <path from> <path to>.\n");
        return false;
    }

    path[0] = sep_get(sep, 1);
    path[1] = sep_get(sep, 2);

    if (!get_path_info(keystore, state, path[0], &info[0])) {
        printf("%s\n", info[0].error);
        return 1;
    }

    if (!get_path_info(keystore, state, path[1], &info[1])) {
        printf("%s\n", info[1].error);
        return 1;
    }

    if (keystore_entry_move_entry(keystore, info[0].entry, info[1].entry) != KEYSTORE_ERROR_OK) {
        printf("%s\n", keystore_error(keystore));
        return true;
    }

    state->dirty = true;
    printf("Entry moved.\n");

    return true;
}

bool
handle_open(keystore_t *keystore, sep_t *sep, state_t *state) {
    const char *path, *password;

    if (sep_size(sep) < 3) {
        printf("Usage: open <file> <password>.\n");
        return true;
    }

    path = sep_get(sep, 1);
    password = sep_get(sep, 2);

    if (keystore_open(keystore, path, password) != KEYSTORE_ERROR_OK) {
        printf("%s\n", keystore_error(keystore));
        return true;
    }

    printf("Keystore opened.\n");

    memset(state, 0, sizeof(*state));

    os_basename(path, state->file, sizeof(state->file));
    state->entry = keystore_root(keystore);
    state->path_len = snprintf(state->path, sizeof(state->path), "%s", "/");

    return true;
}

bool
handle_quit(keystore_t *keystore, sep_t *sep, state_t *state) {
    char answer[32], *ptr;
    int decision = -1;

    if (keystore_is_open(keystore)) {
        if (state->dirty) {
            while (decision == -1) {
                printf("The KeyStore has unsaved changes. Would you like to save before closing [yes|no|cancel]? ");
                fgets(answer, sizeof(answer), stdin);

                ptr = strchr(answer, '\n');
                if (ptr != NULL) {
                    *ptr = '\0';
                }

                if (strcasecmp(answer, "yes") == 0) {
                    decision = 0;
                }
                else if (strcasecmp(answer, "no") == 0) {
                    decision = 1;
                }
                else if (strcasecmp(answer, "cancel") == 0) {
                    decision = 2;
                }
            }

            if (decision == 0) {
                if (keystore_save(keystore) == KEYSTORE_ERROR_OK) {
                    printf("KeyStore saved.\n");
                }
                else {
                    printf("%s\n", keystore_error(keystore));
                    return true;
                }
            }
            else if (decision == 2) {
                //abort the quit+save
                return true;
            }
        }
    }

    printf("Good bye.\n");
    return false;
}

bool
handle_rename(keystore_t *keystore, sep_t *sep, state_t *state) {
    const char *path, *name;
    path_info_t info;
    

    if (sep_size(sep) < 3) {
        printf("Usage: rename <path> <name>\n");
        return true;
    }

    path = sep_get(sep, 1);
    name = sep_get(sep, 2);

    if (!get_path_info(keystore, state, path, &info)) {
        printf("%s\n", info.error);
        return true;
    }

    if (keystore_entry_set_name(keystore, info.entry, name) != KEYSTORE_ERROR_OK) {
        printf("%s\n", keystore_error(keystore));
        return true;
    }

    state->dirty = true;
    printf("Entry renamed.\n");

    return true;
}

bool
handle_rm(keystore_t *keystore, sep_t *sep, state_t *state) {
    const char *path;
    keystore_entry_t *entry;

    if (sep_size(sep) < 2) {
        printf("Usage: rm <path>\n");
        return true;
    }

    path = sep_get(sep, 1);

    if (keystore_entry_get_entry(keystore, state->entry, path, &entry) != KEYSTORE_ERROR_OK) {
        printf("%s\n", keystore_error(keystore));
        return true;
    }

    if (keystore_entry_type(entry) == KEYSTORE_ENTRY_TYPE_FOLDER) {
        printf("Folders cannot be deleted with 'rm'. Use `rmdir` to delete folders.\n");
        return true;
    }

    if (keystore_entry_delete_entry(keystore, entry, 0) != KEYSTORE_ERROR_OK) {
        printf("%s\n", keystore_error(keystore));
    }

    state->dirty = true;

    return true;
}

bool
handle_rmdir(keystore_t *keystore, sep_t *sep, state_t *state) {
    char answer[32], *ptr;
    const char *path;
    unsigned int size;
    int decision = -1;
    keystore_entry_t *entry;

    if (sep_size(sep) < 2) {
        printf("Usage: rmdir <path>\n");
        return true;
    }

    path = sep_get(sep, 1);

    if (keystore_entry_get_entry(keystore, state->entry, path, &entry) != KEYSTORE_ERROR_OK) {
        printf("%s\n", keystore_error(keystore));
        return true;
    }

    if (keystore_entry_type(entry) == KEYSTORE_ENTRY_TYPE_NOTE) {
        printf("Notes cannot be deleted with 'rmdir'. Use `rm` to delete notes.\n");
        return true;
    }

    if (keystore_entry_folder_size(keystore, entry, &size) != KEYSTORE_ERROR_OK) {
        printf("%s\n", keystore_error(keystore));
        return false;
    }

    if (size == 0) {
        decision = 0;
    }
    else {
        while (decision == -1) {
            printf("This folder has %u entries in it. Would you like to delete all entries in the folder too [yes|no]? ", size);
            fgets(answer, sizeof(answer), stdin);

            ptr = strchr(answer, '\n');
            if (ptr != NULL) {
                *ptr = '\0';
            }

            if (strcasecmp(answer, "yes") == 0) {
                decision = 0;
            }
            else if (strcasecmp(answer, "no") == 0) {
                decision = 1;
            }
        }
    }

    if (decision == 1) {
        return true;
    }

    if (keystore_entry_delete_entry(keystore, entry, KEYSTORE_ENTRY_DELETE_FLAG_RECURSIVE) != KEYSTORE_ERROR_OK) {
        printf("%s\n", keystore_error(keystore));
    }
    else {
        state->dirty = true;
    }

    return true;
}

bool
handle_save(keystore_t *keystore, sep_t *sep, state_t *state) {
    if (keystore_save(keystore) != KEYSTORE_ERROR_OK) {
        printf("%s\n", keystore_error(keystore));
        return true;
    }

    state->dirty = false;
    printf("Saved.\n");

    return true;
}

bool
handle_version(keystore_t *keystore, sep_t *sep, state_t *state) {
    printf("Client Version %d.%d.%d\n", VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH);

    if (keystore_is_open(keystore)) {
        printf("Library Version %d.%d.%d\n", keystore_version_major(keystore), keystore_version_minor(keystore), keystore_version_patch(keystore));
    }
    return true;
}

static handler_t *
find_handler(keystore_t *keystore, const char *cmd) {
    handler_t *handler = NULL;
    char *cmd_dupe, *cmd_ptr, *save;
    bool found = false;
    int i;

    for (i = 0; !found && handlers[i].func != NULL; i++) {
        cmd_dupe = strdup(handlers[i].cmd);
        cmd_ptr = strtok_r(cmd_dupe, "|", &save);

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

            cmd_ptr = strtok_r(NULL, "|", &save);
        }

        free(cmd_dupe);
    }

    if (!found) {
        printf("Command '%s' not found.\n", cmd);
    }

    return handler;
}

int
main(int argc, char **argv) {
    const char *cmd;
    char line[2048];
    bool running;
    sep_t sep;
    state_t state;
    handler_t *handler;
    keystore_t *keystore;

    printf("%s %d.%d.%d\n", VERSION_NAME, VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH);

    signal(SIGINT, handle_signal);

    keystore = keystore_init();
    if (keystore == NULL) {
        fprintf(stderr, "Out of memory");
        return 1;
    }

    printf("\nType `");
    color_printf(COLOR_GREEN, "help");
    printf("` for help.\n");

    running = true;

    while (running) {
        printf("\n[");
        if (!keystore_is_open(keystore)) {
            color_printf(COLOR_YELLOW, "Not open");
        }
        else {
            color_printf(COLOR_YELLOW, "%s", state.file);
            printf(": ");
            color_printf(COLOR_YELLOW, "%s", state.path);
            if (state.dirty) {
                color_printf(COLOR_RED, " *");
            }
        }
        printf("]> ");

        if (fgets(line, sizeof(line), stdin) == NULL) {
            fprintf(stderr, "Error getting input\n");
            break;
        }

        sep_init(&sep);
        sep_parse(&sep, line);

        if (sep_size(&sep) > 0) {
            cmd = sep_get(&sep, 0);

            handler = find_handler(keystore, cmd);
            if (handler != NULL) {
                running = handler->func(keystore, &sep, &state);
            }
        }

        sep_free(&sep);
    }

    if (keystore_is_open(keystore)) {
        keystore_close(keystore);
    }
    keystore_free(keystore);

    return 0;
}
