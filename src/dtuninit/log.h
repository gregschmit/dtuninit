#ifndef LOG_H
#define LOG_H

#include <stdbool.h>

extern bool DEBUG;
extern bool COLOR;

void log_info(const char *msg, ...);
void log_error(const char *msg, ...);
void log_errno(const char *label);
void dbg(const char *msg, ...);
void dbg_errno(const char *label);

bool check_ptr(const char *f_name, const char *ptr_name, const void *ptr);

#endif  // LOG_H
