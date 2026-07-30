/*
 * enums.c -- debug-info fixture that carries enum types.
 *
 * Compiled with `-g` so IDA imports the DWARF enums (Color, Status) into the
 * IDB's local types, giving the type suite a source-built fixture with named
 * enum members and values. Without debug info a plain Mach-O carries no enum
 * types, so the enum-value read/write tests would otherwise only exercise
 * external (e.g. drop-in) IDBs.
 *
 * The enums are referenced from code so they survive into the debug info.
 */
#include <stdio.h>

enum Color {
    COLOR_RED = 1,
    COLOR_GREEN = 2,
    COLOR_BLUE = 4,
};

enum Status {
    STATUS_OK = 0,
    STATUS_WARN = 10,
    STATUS_ERR = 20,
};

typedef struct {
    enum Color color;
    enum Status status;
    int id;
} widget_t;

int color_weight(enum Color c) {
    switch (c) {
        case COLOR_RED:
            return 1;
        case COLOR_GREEN:
            return 2;
        case COLOR_BLUE:
            return 3;
    }
    return 0;
}

const char *status_name(enum Status s) {
    switch (s) {
        case STATUS_OK:
            return "ok";
        case STATUS_WARN:
            return "warn";
        case STATUS_ERR:
            return "err";
    }
    return "?";
}

int classify(const widget_t *w) {
    if (w->status == STATUS_ERR) {
        return -1;
    }
    if (w->color == COLOR_BLUE) {
        return 2;
    }
    return w->id;
}

int widget_score(const widget_t *w) {
    return color_weight(w->color) + classify(w) + w->id;
}

void describe(const widget_t *w) {
    printf("widget id=%d status=%s score=%d\n", w->id, status_name(w->status), widget_score(w));
}

int main(void) {
    widget_t w = {COLOR_BLUE, STATUS_OK, 7};
    describe(&w);
    printf("classify=%d\n", classify(&w));
    return 0;
}
