#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "sep.h"

void
sep_init(sep_t *sep) {
    memset(sep, 0, sizeof(*sep));
}

void
sep_free(sep_t *sep) {
    unsigned int i;

    if (sep->args != NULL) {
        for (i = 0; i < sep->size; i++) {
            free(sep->args[i]);
        }

        free(sep->args);
    }
}

const char *
sep_error(sep_t *sep) {
    return sep->error;
}

static bool
sep_grow(sep_t *sep) {
    char **new_args;
    unsigned int new_capacity;

    new_capacity = sep->capacity == 0 ? 25 : sep->capacity * 2;
    new_args = realloc(sep->args, new_capacity * sizeof(char *));
    if (new_args == NULL) {
        strcpy(sep->error, "Out of memory");
        return false;
    }

    sep->args = new_args;
    sep->capacity = new_capacity;

    return true;
}

static bool
sep_add_arg(sep_t *sep, const char *arg, unsigned int len) {
    unsigned int i, pos;

    if (sep->args == NULL || sep->size == sep->capacity) {
        if (!sep_grow(sep)) {
            return false;
        }
    }

    sep->args[sep->size] = malloc(len + 1);
    if (sep->args[sep->size] == NULL) {
        strcpy(sep->error, "Out of memory");
        return false;
    }

    pos = 0;
    for (i = 0; i < len; i++) {
        if (arg[i] == '\\' && arg[i + 1] == '"') {
            continue;
        }

        sep->args[sep->size][pos++] = arg[i];
    }

    //if we skipped any back slashes, pad the rest of the string with nulls
    //also make sure the extra byte allocated for the null terminator gets set
    for (i = pos; i < len + 1; i++) {
        sep->args[sep->size][i] = '\0';
    }

    ++sep->size;

    return true;
}

bool
sep_parse(sep_t *sep, const char *str) {
    const char *ptr = str, *start;
    bool on_quote;

    while (true) {
        on_quote = false;

        //skip front whitespace
        while (isspace(*ptr)) {
            ++ptr;
        }

        if (*ptr == '\0') {
            break;
        }

        if (*ptr == '"') {
            on_quote = true;
            ++ptr;
        }

        //we are at the beginning of the arg, traverse to the end of the arg then
        //copy the arg into the struct
        start = ptr;
        if (on_quote) {
            while (true) {
                if (*ptr == '"' && *(ptr - 1) != '\\') {
                    break;
                }
                if (*ptr == '\0') {
                    break;
                }

                ++ptr;
            }
        }
        else {
            while (!isspace(*ptr) && *ptr != '\0') {
                ++ptr;
            }
        }

        if (!sep_add_arg(sep, start, ptr - start)) {
            return false;
        }

        //if this is a quoted arg, skip the ending quote
        if (on_quote) {
            ++ptr;
        }

        //skip end whitespace
        while (isspace(*ptr)) {
            ++ptr;
        }
    }

    return true;
}

unsigned int
sep_size(sep_t *sep) {
    return sep->size;
}

const char *
sep_get(sep_t *sep, unsigned int index) {
    return sep->args[index];
}
