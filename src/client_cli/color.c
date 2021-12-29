#include <stdio.h>
#include <stdarg.h>
#include "color.h"

void
color_set(color_t color) {
    int num = 37;

    switch (color) {
        case COLOR_RED:
            num = 91;
            break;
        case COLOR_GREEN:
            num = 92;
            break;
        case COLOR_BLUE:
            num = 94;
            break;
        case COLOR_YELLOW:
            num = 93;
            break;
        case COLOR_CYAN:
            num = 96;
            break;
        case COLOR_MAGENTA:
            num = 35;
            break;
    }

    printf("\033[%dm", num);
}

void
color_reset() {
    printf("\033[%dm", 37);
}

void
color_printf(color_t color, const char *fmt, ...) {
    va_list ap;

    color_set(color);

    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);

    color_reset();
}
