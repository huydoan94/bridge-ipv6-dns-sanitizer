#ifndef L2DNS6RW_LOG_H
#define L2DNS6RW_LOG_H

/* procd collects stdout and stderr into the system log. */
__attribute__((format(printf, 1, 2))) void log_info(const char *format, ...);
__attribute__((format(printf, 1, 2))) void log_error(const char *format, ...);

#endif
