#pragma once

typedef enum {
    COLOR_RED,
    COLOR_GREEN,
    COLOR_BLUE,
    COLOR_YELLOW,
    COLOR_CYAN,
    COLOR_MAGENTA
} color_t;

void color_set(color_t color);
void color_reset();

void color_printf(color_t color, const char *fmt, ...);
