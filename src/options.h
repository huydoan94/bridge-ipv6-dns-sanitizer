#ifndef L2DNS6RW_OPTIONS_H
#define L2DNS6RW_OPTIONS_H

#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>

#include "l2dns6rw-bpf.h"

#define OPTIONS_MAX_DEVICES 16
#define DEFAULT_OBJECT_PATH "/lib/bpf/l2dns6rw.o"
#define DEFAULT_PIN_PATH "/sys/fs/bpf/l2dns6rw"

struct options {
    const char *devices[OPTIONS_MAX_DEVICES];
    unsigned int device_count;
    struct in6_addr dns[L2DNS6RW_MAX_DNS_SERVERS];
    unsigned int dns_count; /* 0: each device's own ULA */
    bool verbose;
    bool detach; /* detach everything and exit */
    const char *object_path;
    const char *pin_path;
};

enum options_result {
    OPTIONS_RUN,
    OPTIONS_HELP,
    OPTIONS_INVALID,
};

/* Parses argv into options; on OPTIONS_INVALID, error holds the reason. */
enum options_result options_parse(
    struct options *options,
    int argc,
    char **argv,
    char *error,
    size_t error_size
);
void options_usage(const char *program);

#endif
