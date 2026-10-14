/*
 * runner: runs the l2dns6rw BPF program on test frames with BPF_PROG_TEST_RUN
 * (needs root) and prints what it did, for tests/bpf/cases.py to check.
 *
 * Usage: runner OBJECT CASES
 *
 * Each CASES line is "NAME DNS HEX": DNS is "-" (no DNS entry for the device)
 * or comma-separated IPv6 addresses; HEX is the Ethernet frame. Each output
 * line is "NAME RETVAL OUTPUT_HEX VERDICT REASON", where VERDICT and REASON
 * come from the event the program reported, or are "-" when it reported none.
 * The program runs with verbose events on, as if attached to the loopback
 * device (ifindex 1), whose dns entry holds DNS.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "l2dns6rw-bpf.h"

#define LOOPBACK_IFINDEX 1
#define MAX_FRAME 4096
#define MAX_LINE (2 * MAX_FRAME + 1024)

struct last_event {
    int seen;
    unsigned int verdict;
    unsigned int reason;
};

static int record_event(void *context, void *data, size_t size)
{
    struct last_event *last = context;
    const struct l2dns6rw_event *event = data;

    if (size >= sizeof(*event)) {
        last->seen = 1;
        last->verdict = event->verdict;
        last->reason = event->reason;
    }
    return 0;
}

static int parse_hex(const char *text, unsigned char *bytes, size_t capacity, size_t *length)
{
    size_t digits = strlen(text);

    if (digits % 2 != 0 || digits / 2 > capacity)
        return -1;
    for (size_t i = 0; i < digits / 2; i++) {
        unsigned int value;

        if (sscanf(text + 2 * i, "%2x", &value) != 1)
            return -1;
        bytes[i] = (unsigned char)value;
    }
    *length = digits / 2;
    return 0;
}

static int set_dns(int map, char *servers)
{
    struct l2dns6rw_dns value;
    const __u32 key = LOOPBACK_IFINDEX;
    char *save = NULL;

    if (strcmp(servers, "-") == 0) {
        bpf_map_delete_elem(map, &key);
        return 0;
    }
    memset(&value, 0, sizeof(value));
    for (char *server = strtok_r(servers, ",", &save); server != NULL; server = strtok_r(NULL, ",", &save)) {
        if (value.count == L2DNS6RW_MAX_DNS_SERVERS || inet_pton(AF_INET6, server, value.servers[value.count]) != 1)
            return -1;
        value.count++;
    }
    return bpf_map_update_elem(map, &key, &value, BPF_ANY);
}

int main(int argc, char **argv)
{
    static char line[MAX_LINE];
    static unsigned char frame[MAX_FRAME], output[MAX_FRAME];
    const struct l2dns6rw_settings settings = {.verbose = 1};
    struct last_event last = {0};
    struct bpf_object *object;
    struct bpf_program *program;
    struct ring_buffer *events;
    struct bpf_map *map;
    const __u32 zero = 0;
    FILE *cases;
    int dns_map;

    if (argc != 3) {
        fprintf(stderr, "usage: %s OBJECT CASES\n", argv[0]);
        return 2;
    }
    object = bpf_object__open_file(argv[1], NULL);
    if (object == NULL) {
        fprintf(stderr, "open %s: %s\n", argv[1], strerror(errno));
        return 1;
    }
    /* The test runs must not touch the maps a running daemon pinned. */
    bpf_object__for_each_map(map, object)
        bpf_map__set_pin_path(map, NULL);
    if (bpf_object__load(object) < 0) {
        fprintf(stderr, "load %s: %s\n", argv[1], strerror(errno));
        return 1;
    }
    program = bpf_object__find_program_by_name(object, "l2dns6rw_ingress");
    dns_map = bpf_object__find_map_fd_by_name(object, "dns");
    bpf_map_update_elem(bpf_object__find_map_fd_by_name(object, "settings"), &zero, &settings, BPF_ANY);
    events = ring_buffer__new(bpf_object__find_map_fd_by_name(object, "events"), record_event, &last, NULL);
    cases = fopen(argv[2], "r");
    if (program == NULL || events == NULL || cases == NULL) {
        fprintf(stderr, "set up: %s\n", strerror(errno));
        return 1;
    }

    while (fgets(line, sizeof(line), cases) != NULL) {
        char *name = strtok(line, " \n"), *dns = strtok(NULL, " \n"), *hex = strtok(NULL, " \n");
        struct __sk_buff context;
        size_t frame_length;
        LIBBPF_OPTS(bpf_test_run_opts, run);

        if (name == NULL || dns == NULL || hex == NULL || parse_hex(hex, frame, sizeof(frame), &frame_length) < 0 ||
            set_dns(dns_map, dns) < 0) {
            fprintf(stderr, "bad case line: %s\n", name ? name : "");
            return 1;
        }
        memset(&context, 0, sizeof(context));
        context.ifindex = LOOPBACK_IFINDEX;
        run.data_in = frame;
        run.data_size_in = (__u32)frame_length;
        run.data_out = output;
        run.data_size_out = sizeof(output);
        run.ctx_in = &context;
        run.ctx_size_in = sizeof(context);
        ring_buffer__consume(events);
        last.seen = 0;
        if (bpf_prog_test_run_opts(bpf_program__fd(program), &run) < 0) {
            fprintf(stderr, "%s: test run: %s\n", name, strerror(errno));
            return 1;
        }
        ring_buffer__consume(events);
        printf("%s %u ", name, run.retval);
        for (__u32 i = 0; i < run.data_size_out; i++)
            printf("%02x", output[i]);
        if (last.seen)
            printf(" %u %u\n", last.verdict, last.reason);
        else
            printf(" - -\n");
    }
    fclose(cases);
    ring_buffer__free(events);
    bpf_object__close(object);
    return 0;
}
