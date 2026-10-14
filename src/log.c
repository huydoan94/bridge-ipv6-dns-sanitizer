#include "log.h"

#include <stdarg.h>
#include <stdio.h>

static void log_line(FILE *stream, const char *format, va_list arguments)
{
    vfprintf(stream, format, arguments);
    fputc('\n', stream);
    fflush(stream);
}

void log_info(const char *format, ...)
{
    va_list arguments;

    va_start(arguments, format);
    log_line(stdout, format, arguments);
    va_end(arguments);
}

void log_error(const char *format, ...)
{
    va_list arguments;

    va_start(arguments, format);
    log_line(stderr, format, arguments);
    va_end(arguments);
}
