#include "options.h"

#include <arpa/inet.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void options_usage(const char *program)
{
    printf(
        "Usage: %s -i DEVICE [-i DEVICE]... [-d DNS_SERVER]... [-v] [-o OBJECT] [-p PIN_DIR]\n"
        "       %s -D [-p PIN_DIR]\n",
        program,
        program
    );
}

enum options_result options_parse(
    struct options *options,
    int argc,
    char **argv,
    char *error,
    size_t error_size
)
{
    int option;

    memset(options, 0, sizeof(*options));
    options->object_path = DEFAULT_OBJECT_PATH;
    options->pin_path = DEFAULT_PIN_PATH;
    optind = 1;
    opterr = 0;
    while ((option = getopt(argc, argv, "i:d:vo:p:Dh")) != -1) {
        switch (option) {
        case 'i':
            if (options->device_count == OPTIONS_MAX_DEVICES) {
                snprintf(error, error_size, "too many devices; maximum is %d", OPTIONS_MAX_DEVICES);
                return OPTIONS_INVALID;
            }
            if (optarg[0] == '\0' || strlen(optarg) >= IF_NAMESIZE || strchr(optarg, '/') != NULL) {
                snprintf(error, error_size, "invalid device name '%s'", optarg);
                return OPTIONS_INVALID;
            }
            options->devices[options->device_count++] = optarg;
            break;
        case 'd':
            if (options->dns_count == L2DNS6RW_MAX_DNS_SERVERS) {
                snprintf(error, error_size, "too many DNS servers; maximum is %d", L2DNS6RW_MAX_DNS_SERVERS);
                return OPTIONS_INVALID;
            }
            if (inet_pton(AF_INET6, optarg, &options->dns[options->dns_count]) != 1) {
                snprintf(error, error_size, "invalid IPv6 DNS server '%s'", optarg);
                return OPTIONS_INVALID;
            }
            options->dns_count++;
            break;
        case 'v':
            options->verbose = true;
            break;
        case 'o':
            options->object_path = optarg;
            break;
        case 'p':
            options->pin_path = optarg;
            break;
        case 'D':
            options->detach = true;
            break;
        case 'h':
            return OPTIONS_HELP;
        default:
            snprintf(error, error_size, "unknown option or missing value: -%c", optopt);
            return OPTIONS_INVALID;
        }
    }
    if (optind != argc) {
        snprintf(error, error_size, "unexpected argument '%s'", argv[optind]);
        return OPTIONS_INVALID;
    }
    if (!options->detach && options->device_count == 0) {
        snprintf(error, error_size, "at least one device (-i) is required");
        return OPTIONS_INVALID;
    }
    return OPTIONS_RUN;
}
