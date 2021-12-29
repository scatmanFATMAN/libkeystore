#pragma once

#include <stdbool.h>

typedef struct {
    char **args;
    unsigned int size;
    unsigned int capacity;
    char error[256];
} sep_t;

void sep_init(sep_t *sep);
void sep_free(sep_t *sep);

const char * sep_error(sep_t *sep);

bool sep_parse(sep_t *sep, const char *str);

unsigned int sep_size(sep_t *sep);
const char * sep_get(sep_t *sep, unsigned int index);
char * sep_dupe(sep_t *sep, unsigned int index);
bool sep_equals(sep_t *sep, unsigned int index, const char *str);
