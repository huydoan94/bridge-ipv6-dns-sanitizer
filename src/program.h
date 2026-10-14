#ifndef L2DNS6RW_PROGRAM_H
#define L2DNS6RW_PROGRAM_H

#include <netinet/in.h>
#include <stdbool.h>

#include "l2dns6rw-bpf.h"

struct bpf_object;
struct bpf_link;
struct ring_buffer;

typedef void (*program_event_fn)(const struct l2dns6rw_event *event, void *context);

/*
 * The loaded BPF program. Its maps and per-device tcx links are pinned under
 * pin_path, so the program keeps running when the daemon exits or restarts;
 * a restarted daemon reuses the maps and moves the links to its program.
 */
struct program {
    struct bpf_object *object;
    struct ring_buffer *events;
    program_event_fn on_event;
    void *context;
    const char *pin_path;
    int dns_fd;
    int counters_fd;
};

int program_open(
    struct program *program,
    const char *object_path,
    const char *pin_path,
    bool verbose,
    program_event_fn on_event,
    void *context
);

/* Attaches to device (ifindex) at tcx ingress, reusing its pinned link. */
int program_attach(struct program *program, const char *device, unsigned int ifindex);

/* Detaches pinned links of devices not in devices[]. */
void program_release_others(const struct program *program, const char *const *devices, unsigned int count);

int program_set_dns(
    const struct program *program,
    unsigned int ifindex,
    const struct in6_addr *servers,
    unsigned int count
);
bool program_has_dns(const struct program *program, unsigned int ifindex);

/* Removes DNS entries whose ifindex is not in ifindexes[]. */
void program_prune_dns(const struct program *program, const unsigned int *ifindexes, unsigned int count);

int program_events_fd(const struct program *program);
void program_consume_events(const struct program *program);

/* Sum of one counter over all CPUs. */
unsigned long long program_counter(const struct program *program, unsigned int counter);

/* Closes the daemon's handles; the pinned program keeps running. */
void program_close(struct program *program);

/* Detaches every device and removes all pins under pin_path. */
int program_detach_all(const char *pin_path);

#endif
