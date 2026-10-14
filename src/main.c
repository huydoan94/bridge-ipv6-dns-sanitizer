/*
 * l2dns6rw daemon: attaches the BPF sanitizer (l2dns6rw.bpf.c) to the
 * configured devices at tcx ingress and keeps its per-device DNS list current.
 *
 * Everything is event-driven: the daemon sleeps in poll() until the kernel
 * reports a link or IPv6 address change (devices recreated, ULAs added or
 * removed) or the program reports a packet. The program and its maps are
 * pinned, so sanitizing continues while the daemon is stopped or restarting.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dns.h"
#include "events.h"
#include "log.h"
#include "netlink.h"
#include "options.h"
#include "program.h"

#ifndef PROGRAM_VERSION
#define PROGRAM_VERSION "unknown"
#endif

#define EVENT_LINE_BYTES 256

/* What the daemon last applied for one configured device. */
struct device_state {
    unsigned int ifindex;      /* attached ifindex; 0 when the device is missing */
    struct in6_addr automatic; /* automatic mode: the address in the dns map */
    bool has_automatic;
    bool reported_missing;
    bool reported_no_ula;
};

struct daemon {
    struct options options;
    struct program program;
    struct device_state devices[OPTIONS_MAX_DEVICES];
};

static volatile sig_atomic_t running = 1;

static void handle_signal(int signal_number)
{
    (void)signal_number;
    running = 0;
}

static int install_signal_handlers(void)
{
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    action.sa_handler = handle_signal;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL) < 0 || sigaction(SIGTERM, &action, NULL) < 0)
        return -1;
    return 0;
}

static void log_event(const struct l2dns6rw_event *event, void *context)
{
    char device[IF_NAMESIZE], line[EVENT_LINE_BYTES];

    (void)context;
    if (if_indextoname(event->ifindex, device) == NULL)
        snprintf(device, sizeof(device), "%u", event->ifindex);
    events_format(event, device, line, sizeof(line));
    if (event->verdict == L2DNS6RW_VERDICT_CHANGED)
        log_info("%s", line);
    else
        log_error("%s", line);
}

/* Automatic mode: points device's dns entry at its own or its bridge's ULA. */
static void update_automatic_dns(
    struct daemon *daemon,
    const char *name,
    struct device_state *device,
    const struct dns_snapshot *snapshot
)
{
    char master[IF_NAMESIZE] = "";
    char text[INET6_ADDRSTRLEN];
    struct in6_addr address;
    const char *source;

    dns_bridge_master(name, master);
    if (!dns_select(snapshot, name, master, &address, &source)) {
        /* Keep the last address: a ULA can briefly disappear during a reload. */
        if (!program_has_dns(&daemon->program, device->ifindex) && !device->reported_no_ula)
            log_error("%s: no ULA on it or its bridge; its RA and DHCPv6 replies are dropped until one appears", name);
        device->reported_no_ula = true;
        return;
    }
    device->reported_no_ula = false;
    if (device->has_automatic && memcmp(&device->automatic, &address, sizeof(address)) == 0 &&
        program_has_dns(&daemon->program, device->ifindex))
        return;
    if (program_set_dns(&daemon->program, device->ifindex, &address, 1) < 0) {
        log_error("%s: could not store its DNS address: %s", name, strerror(errno));
        return;
    }
    device->automatic = address;
    device->has_automatic = true;
    inet_ntop(AF_INET6, &address, text, sizeof(text));
    log_info("%s: DNS %s(%s)", name, text, source);
}

/* Attaches to every present device and refreshes the dns map. */
static void synchronize(struct daemon *daemon)
{
    const struct options *options = &daemon->options;
    unsigned int ifindexes[OPTIONS_MAX_DEVICES];
    unsigned int present = 0;
    struct dns_snapshot snapshot;
    bool have_snapshot = false;

    if (options->dns_count == 0) {
        have_snapshot = dns_snapshot_take(&snapshot) == 0;
        if (!have_snapshot)
            log_error("could not read interface addresses: %s; keeping the current DNS", strerror(errno));
    }
    for (unsigned int i = 0; i < options->device_count; i++) {
        const char *name = options->devices[i];
        struct device_state *device = &daemon->devices[i];
        const unsigned int ifindex = if_nametoindex(name);

        if (ifindex == 0) {
            if (!device->reported_missing)
                log_error("%s: device not present; it is attached when it appears", name);
            device->reported_missing = true;
            device->ifindex = 0;
            continue;
        }
        device->reported_missing = false;
        if (device->ifindex != ifindex) {
            if (program_attach(&daemon->program, name, ifindex) < 0)
                continue;
            log_info("%s: sanitizing RA and DHCPv6 at ingress", name);
            device->ifindex = ifindex;
            device->has_automatic = false;
            if (options->dns_count > 0 &&
                program_set_dns(&daemon->program, ifindex, options->dns, options->dns_count) < 0)
                log_error("%s: could not store its DNS servers: %s", name, strerror(errno));
        }
        ifindexes[present++] = ifindex;
        if (have_snapshot)
            update_automatic_dns(daemon, name, device, &snapshot);
    }
    program_prune_dns(&daemon->program, ifindexes, present);
}

static int run(struct daemon *daemon)
{
    struct pollfd fds[2];
    int netlink;

    netlink = netlink_open();
    if (netlink < 0) {
        log_error("open rtnetlink: %s", strerror(errno));
        return EXIT_FAILURE;
    }
    /* Subscribed before the first scan, so no change between them is missed. */
    program_release_others(&daemon->program, daemon->options.devices, daemon->options.device_count);
    synchronize(daemon);

    fds[0].fd = netlink;
    fds[0].events = POLLIN;
    fds[1].fd = program_events_fd(&daemon->program);
    fds[1].events = POLLIN;
    while (running) {
        /* No timeout: only a kernel notification or a signal wakes the daemon. */
        if (poll(fds, 2, -1) < 0) {
            if (errno == EINTR)
                continue;
            log_error("poll: %s", strerror(errno));
            close(netlink);
            return EXIT_FAILURE;
        }
        if (fds[1].revents & POLLIN)
            program_consume_events(&daemon->program);
        if (fds[0].revents & POLLIN) {
            const int changed = netlink_drain(netlink);

            if (changed < 0) {
                log_error("rtnetlink: %s", strerror(errno));
                close(netlink);
                return EXIT_FAILURE;
            }
            if (changed > 0)
                synchronize(daemon);
        }
    }
    close(netlink);
    return EXIT_SUCCESS;
}

static void log_counters(const struct program *program)
{
    log_info(
        "packets seen=%llu changed=%llu unchanged=%llu dropped=%llu malformed=%llu",
        program_counter(program, L2DNS6RW_COUNTER_SEEN),
        program_counter(program, L2DNS6RW_COUNTER_CHANGED),
        program_counter(program, L2DNS6RW_COUNTER_UNCHANGED),
        program_counter(program, L2DNS6RW_COUNTER_DROPPED),
        program_counter(program, L2DNS6RW_COUNTER_MALFORMED)
    );
}

int main(int argc, char **argv)
{
    static struct daemon daemon;
    char error[128];
    int status;

    switch (options_parse(&daemon.options, argc, argv, error, sizeof(error))) {
    case OPTIONS_HELP:
        options_usage(argv[0]);
        return EXIT_SUCCESS;
    case OPTIONS_INVALID:
        log_error("%s", error);
        options_usage(argv[0]);
        return EXIT_FAILURE;
    case OPTIONS_RUN:
        break;
    }
    if (daemon.options.detach) {
        if (program_detach_all(daemon.options.pin_path) < 0) {
            log_error("detach: %s", strerror(errno));
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
    }

    log_info("starting version %s", PROGRAM_VERSION);
    if (daemon.options.dns_count > 0)
        log_info("using %u configured DNS server(s)", daemon.options.dns_count);
    else
        log_info("using each device's own ULA, or its bridge's, as DNS server");
    if (install_signal_handlers() < 0) {
        log_error("install signal handlers: %s", strerror(errno));
        return EXIT_FAILURE;
    }
    if (program_open(
            &daemon.program,
            daemon.options.object_path,
            daemon.options.pin_path,
            daemon.options.verbose,
            log_event,
            NULL
        ) < 0)
        return EXIT_FAILURE;
    status = run(&daemon);
    log_counters(&daemon.program);
    log_info("stopping; the pinned program keeps sanitizing");
    program_close(&daemon.program);
    return status;
}
