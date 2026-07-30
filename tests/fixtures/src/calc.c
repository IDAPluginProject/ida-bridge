/*
 * calc.c -- small C fixture for e2e tests.
 *
 * Provides a stable, recognizable shape: a handful of external functions, a
 * static helper (so a stripped build loses a name), a global, a struct, and a
 * couple of string literals. Imports printf from libSystem.
 *
 * Built into several variants by build.py (arch / opt level / stripped).
 */
#include <stdio.h>

static const char greeting[] = "hello from ida-bridge test binary";
static const char farewell[] = "goodbye from ida-bridge test binary";

int g_call_count = 0;

typedef struct {
    int x;
    int y;
} point_t;

int add(int a, int b) { return a + b; }
int multiply(int a, int b) { return a * b; }
const char *get_greeting(void) { return greeting; }

static int square(int x) {
    g_call_count++;
    return multiply(x, x);
}

int point_sum(const point_t *p) {
    return p->x + p->y;
}

int compute(int x, int y) {
    int sum = add(x, y);
    point_t p = {sum, square(multiply(x, y))};
    return point_sum(&p);
}

int main(int argc, char **argv) {
    printf("%s\n", get_greeting());
    printf("compute(3, 4) = %d\n", compute(3, 4));
    if (argc > 1) {
        printf("%s\n", farewell);
    }
    return 0;
}
