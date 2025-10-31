#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "../shared.h"

#include "log.h"

#define ENABLE_RED() if (COLOR) { fprintf(stderr, "\033[1;31m"); }
#define ENABLE_YELLOW() if (COLOR) { fprintf(stderr, "\033[1;33m"); }
#define ENABLE_CYAN() if (COLOR) { fprintf(stderr, "\033[1;36m"); }
#define DISABLE_COLOR() if (COLOR) { fprintf(stderr, "\033[0m"); }

bool DEBUG = false;
bool COLOR = false;

void log_info(const char *msg, ...) {
    va_list args;
    va_start(args, msg);
    vfprintf(stdout, msg, args);
    va_end(args);

    fprintf(stdout, "\n");
}

void log_error(const char *msg, ...) {
    ENABLE_RED()
    va_list args;
    va_start(args, msg);
    vfprintf(stderr, msg, args);
    va_end(args);

    fprintf(stderr, "\n");
    DISABLE_COLOR()
}

void log_errno(const char *label) {
    ENABLE_RED()
    fprintf(stderr, "(%s) %s\n", label, strerror(errno));
    DISABLE_COLOR()
}

void dbg(const char *msg, ...) {
    if (!DEBUG) { return; }

    ENABLE_CYAN()
    va_list args;
    va_start(args, msg);
    vfprintf(stderr, msg, args);
    va_end(args);
    fprintf(stderr, "\n");
    DISABLE_COLOR()
}

void dbg_errno(const char *label) {
    if (!DEBUG) { return; }

    ENABLE_CYAN()
    fprintf(stderr, "(%s) %s\n", label, strerror(errno));
    DISABLE_COLOR()
}

bool check_ptr(const char *f_name, const char *ptr_name, const void *ptr) {
    if (!ptr) {
        log_error("NULL pointer detected in %s: `%s`!!!", f_name, ptr_name);
        return false;
    }
    return true;
}
