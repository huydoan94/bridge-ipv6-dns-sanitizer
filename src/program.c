#include "program.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "log.h"

#define PROGRAM_NAME "l2dns6rw_ingress"
#define LINK_PREFIX "link-"

/* The daemon's handles on the links it attached, by device. */
static struct {
    char device[IF_NAMESIZE];
    struct bpf_link *link;
} attached[L2DNS6RW_MAX_DEVICES];

static int handle_event(void *context, void *data, size_t size)
{
    const struct program *program = context;

    if (size >= sizeof(struct l2dns6rw_event))
        program->on_event(data, program->context);
    return 0;
}

static int map_fd(const struct program *program, const char *name)
{
    return bpf_object__find_map_fd_by_name(program->object, name);
}

/* Removes the pinned maps, so the next load creates them with this object's layout. */
static void unpin_maps(const char *pin_path)
{
    static const char *const names[] = {"dns", "settings", "counters", "events"};
    char path[PATH_MAX];

    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        snprintf(path, sizeof(path), "%s/%s", pin_path, names[i]);
        unlink(path);
    }
}

static struct bpf_object *load(const char *object_path, const char *pin_path)
{
    LIBBPF_OPTS(bpf_object_open_opts, options, .pin_root_path = pin_path);
    struct bpf_object *object = bpf_object__open_file(object_path, &options);

    if (object == NULL) {
        log_error("open %s: %s", object_path, strerror(errno));
        return NULL;
    }
    if (bpf_object__load(object) == 0)
        return object;
    bpf_object__close(object);
    return NULL;
}

int program_open(
    struct program *program,
    const char *object_path,
    const char *pin_path,
    bool verbose,
    program_event_fn on_event,
    void *context
)
{
    const struct l2dns6rw_settings settings = {.verbose = verbose};
    const __u32 key = 0;

    memset(program, 0, sizeof(*program));
    program->pin_path = pin_path;
    if (mkdir(pin_path, 0700) < 0 && errno != EEXIST) {
        log_error("create %s: %s", pin_path, strerror(errno));
        return -1;
    }
    program->object = load(object_path, pin_path);
    if (program->object == NULL) {
        /* Maps pinned by an older version can have another layout. */
        log_info("could not reuse the pinned maps; recreating them");
        unpin_maps(pin_path);
        program->object = load(object_path, pin_path);
    }
    if (program->object == NULL) {
        log_error("load %s: %s", object_path, strerror(errno));
        return -1;
    }
    program->dns_fd = map_fd(program, "dns");
    program->counters_fd = map_fd(program, "counters");
    if (bpf_map_update_elem(map_fd(program, "settings"), &key, &settings, BPF_ANY) < 0) {
        log_error("write settings: %s", strerror(errno));
        return -1;
    }
    program->on_event = on_event;
    program->context = context;
    program->events = ring_buffer__new(map_fd(program, "events"), handle_event, program, NULL);
    if (program->events == NULL) {
        log_error("open event buffer: %s", strerror(errno));
        return -1;
    }
    return 0;
}

/* The slot holding device's link, else a free one; -1 when all are taken. */
static int device_slot(const char *device)
{
    int free_slot = -1;

    for (int i = 0; i < L2DNS6RW_MAX_DEVICES; i++) {
        if (attached[i].link != NULL && strcmp(attached[i].device, device) == 0)
            return i;
        if (attached[i].link == NULL && free_slot < 0)
            free_slot = i;
    }
    return free_slot;
}

/* True when link is a tcx ingress attachment on ifindex. */
static bool link_attached_to(const struct bpf_link *link, unsigned int ifindex)
{
    struct bpf_link_info info;
    __u32 length = sizeof(info);

    memset(&info, 0, sizeof(info));
    return bpf_link_get_info_by_fd(bpf_link__fd(link), &info, &length) == 0 &&
        info.type == BPF_LINK_TYPE_TCX && info.tcx.ifindex == ifindex;
}

int program_attach(struct program *program, const char *device, unsigned int ifindex)
{
    struct bpf_program *ingress = bpf_object__find_program_by_name(program->object, PROGRAM_NAME);
    const int slot = device_slot(device);
    char path[PATH_MAX];
    struct bpf_link *link;

    if (ingress == NULL || slot < 0) {
        log_error("cannot attach to %s: %s", device, ingress == NULL ? "no program" : "too many devices");
        return -1;
    }
    snprintf(path, sizeof(path), "%s/" LINK_PREFIX "%s", program->pin_path, device);
    bpf_link__destroy(attached[slot].link);
    attached[slot].link = NULL;
    snprintf(attached[slot].device, sizeof(attached[slot].device), "%s", device);

    /* A link pinned by an earlier run keeps working while it is replaced. */
    link = access(path, F_OK) == 0 ? bpf_link__open(path) : NULL;
    if (link != NULL) {
        if (link_attached_to(link, ifindex) && bpf_link__update_program(link, ingress) == 0) {
            attached[slot].link = link;
            return 0;
        }
        /* The device was recreated or the link is unusable: start over. */
        bpf_link__unpin(link);
        bpf_link__destroy(link);
    }
    unlink(path);
    link = bpf_program__attach_tcx(ingress, (int)ifindex, NULL);
    if (link == NULL) {
        log_error("attach to %s: %s", device, strerror(errno));
        return -1;
    }
    if (bpf_link__pin(link, path) < 0) {
        log_error("pin %s: %s", path, strerror(errno));
        bpf_link__destroy(link);
        return -1;
    }
    attached[slot].link = link;
    return 0;
}

static bool listed(const char *name, const char *const *devices, unsigned int count)
{
    for (unsigned int i = 0; i < count; i++) {
        if (strcmp(name, devices[i]) == 0)
            return true;
    }
    return false;
}

/* Unpins and closes the link pinned at path, which detaches it once unused. */
static void release_link(const char *path)
{
    struct bpf_link *link = bpf_link__open(path);

    if (link != NULL) {
        bpf_link__unpin(link);
        bpf_link__destroy(link);
    } else {
        unlink(path);
    }
}

void program_release_others(const struct program *program, const char *const *devices, unsigned int count)
{
    DIR *directory = opendir(program->pin_path);
    struct dirent *entry;
    char path[PATH_MAX];

    if (directory == NULL)
        return;
    while ((entry = readdir(directory)) != NULL) {
        const char *device = entry->d_name + strlen(LINK_PREFIX);

        if (strncmp(entry->d_name, LINK_PREFIX, strlen(LINK_PREFIX)) != 0 || listed(device, devices, count))
            continue;
        snprintf(path, sizeof(path), "%s/%s", program->pin_path, entry->d_name);
        release_link(path);
        log_info("detached from %s, which is no longer configured", device);
    }
    closedir(directory);
}

int program_set_dns(
    const struct program *program,
    unsigned int ifindex,
    const struct in6_addr *servers,
    unsigned int count
)
{
    struct l2dns6rw_dns value;
    const __u32 key = ifindex;

    if (count == 0 || count > L2DNS6RW_MAX_DNS_SERVERS)
        return -1;
    memset(&value, 0, sizeof(value));
    value.count = count;
    for (unsigned int i = 0; i < count; i++)
        memcpy(value.servers[i], &servers[i], sizeof(value.servers[i]));
    return bpf_map_update_elem(program->dns_fd, &key, &value, BPF_ANY);
}

bool program_has_dns(const struct program *program, unsigned int ifindex)
{
    struct l2dns6rw_dns value;
    const __u32 key = ifindex;

    return bpf_map_lookup_elem(program->dns_fd, &key, &value) == 0;
}

void program_prune_dns(const struct program *program, const unsigned int *ifindexes, unsigned int count)
{
    __u32 key, next, stale[L2DNS6RW_MAX_DEVICES];
    unsigned int stale_count = 0;
    __u32 *previous = NULL;

    while (bpf_map_get_next_key(program->dns_fd, previous, &next) == 0) {
        bool keep = false;

        for (unsigned int i = 0; i < count; i++)
            keep = keep || ifindexes[i] == next;
        if (!keep && stale_count < L2DNS6RW_MAX_DEVICES)
            stale[stale_count++] = next;
        key = next;
        previous = &key;
    }
    for (unsigned int i = 0; i < stale_count; i++)
        bpf_map_delete_elem(program->dns_fd, &stale[i]);
}

int program_events_fd(const struct program *program)
{
    return ring_buffer__epoll_fd(program->events);
}

void program_consume_events(const struct program *program)
{
    ring_buffer__consume(program->events);
}

unsigned long long program_counter(const struct program *program, unsigned int counter)
{
    const int cpus = libbpf_num_possible_cpus();
    unsigned long long total = 0;
    __u64 *values;

    if (cpus <= 0)
        return 0;
    values = calloc((size_t)cpus, sizeof(*values));
    if (values != NULL && bpf_map_lookup_elem(program->counters_fd, &counter, values) == 0) {
        for (int cpu = 0; cpu < cpus; cpu++)
            total += values[cpu];
    }
    free(values);
    return total;
}

void program_close(struct program *program)
{
    for (int i = 0; i < L2DNS6RW_MAX_DEVICES; i++) {
        /* Closing a pinned link's handle leaves it attached. */
        bpf_link__destroy(attached[i].link);
        attached[i].link = NULL;
    }
    ring_buffer__free(program->events);
    bpf_object__close(program->object);
    memset(program, 0, sizeof(*program));
}

int program_detach_all(const char *pin_path)
{
    DIR *directory = opendir(pin_path);
    struct dirent *entry;
    char path[PATH_MAX];

    if (directory == NULL)
        return errno == ENOENT ? 0 : -1;
    while ((entry = readdir(directory)) != NULL) {
        if (entry->d_name[0] == '.')
            continue;
        snprintf(path, sizeof(path), "%s/%s", pin_path, entry->d_name);
        if (strncmp(entry->d_name, LINK_PREFIX, strlen(LINK_PREFIX)) == 0) {
            release_link(path);
            log_info("detached from %s", entry->d_name + strlen(LINK_PREFIX));
        } else {
            unlink(path);
        }
    }
    closedir(directory);
    return rmdir(pin_path) < 0 && errno != ENOENT ? -1 : 0;
}
