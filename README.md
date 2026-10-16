# l2dns6rw

Small OpenWrt package that sanitizes IPv6 Router Advertisements and DHCPv6
server replies arriving on chosen devices, typically the VXLAN port of a
bridge, before they reach local clients. An eBPF program does the work at tcx
ingress of each device; a small daemon attaches it and keeps its DNS list
current.

## Packet flow

```text
Remote VXLAN peer
      |
      v
VXLAN port (list device)
      |
      v
tcx ingress: l2dns6rw.bpf.o
   /      |       \
  v       v        v
 RA     DHCPv6    other
 |        |         |
 v        v         |
rewrite  rewrite    |
or drop  or drop    |
   \      /         |
    v    v          |
     bridge <-------+
      |
      v
 Local bridge clients
```

## What it changes

Router Advertisements:

- Router Lifetime -> `0`
- the first RDNSS option -> the device's DNS list
- later RDNSS options -> removed
- DNSSL option 31 -> removed
- PvD option 21 -> removed

DHCPv6 Advertise/Reply packets (`547 -> 546`):

- the first DNS Recursive Name Server option 23 -> the device's DNS list
- later DNS options -> removed
- Domain Search List option 24 -> removed

A message without an RDNSS or DNS option gets none added. Other options are
kept in their order.

The DNS list is `dns_server` when configured. Without it, each device uses
its own first ULA (`fc00::/7`), else the first ULA of its bridge. The daemon
recomputes that whenever the kernel reports a link or IPv6 address change; it
has no timers. When a device briefly has no ULA, its last address stays in use.

## Packet handling

- Extension headers: up to 8 Hop-by-Hop, Destination Options, Routing, AH and
  atomic Fragment headers are walked. A longer chain is dropped, since it
  could hide a target.
- A target behind a Routing header with segments left is dropped: it is not
  for this hop.
- ESP and Mobility headers pass unchanged.
- A first fragment of a target is dropped; later fragments pass unchanged.
- Jumbograms, truncated targets (IPv6 or UDP length beyond the frame), and
  devices without a DNS list are dropped.
- A message is rewritten only up to 2048 bytes, and with up to 64 options.
  A longer one, or one whose rewrite would exceed 2048 bytes, is dropped.
- A valid incoming checksum stays valid; an invalid one stays deliberately
  invalid. A zero UDP checksum counts as invalid (RFC 8200 8.1).
- DHCPv6 Authentication option 11, SEND RSA Signature option 12 and an AH
  header are left untouched. If such a packet would need a rewrite, it is
  dropped; if it needs none, it passes unchanged.
- An RDNSS or DNS option whose addresses are empty or not a multiple of 16
  bytes is removed and the rest of the message kept; clients ignore just
  that option.
- Other malformed options, and messages too short for their header, are
  dropped; clients discard them anyway.
- Bytes after the UDP message inside the IPv6 payload are removed when a
  DHCPv6 message is rewritten.

## Attachment and restarts

The program, its maps and each device's tcx link are pinned under
`/sys/fs/bpf/l2dns6rw/`. The program keeps sanitizing while the daemon is
stopped, restarting or crashed, using the last DNS list. A restarted daemon
reuses the pinned maps and moves each link to its own program, so a restart
or upgrade never leaves a gap.

A device that disappears and reappears (for example when netifd recreates the
VXLAN port) is attached again as soon as the kernel reports it. A device
removed from the configuration is detached at the next start.

To detach everything:

```sh
/etc/init.d/l2dns6rw detach
```

Removing the package also detaches it.

## Performance

Measured on OpenWrt VMs (4 vCPUs on an i7-9750H host), with frames sent
from a veth port through a test bridge to a capturing veth port. Each
sanitizer is compared with the same VM without one, since the two VMs run
different OpenWrt versions: the NFQUEUE daemon of 1.6.12 on a 32-bit x86 VM
(25.12.5, kernel 6.12), and the eBPF program of 1.6.13 on an x86-64 VM
(snapshot, kernel 6.18, BPF JIT).

Transit time, median (p99):

| Packet | 32-bit, none | 32-bit, NFQUEUE | x86-64, none | x86-64, eBPF |
| --- | --- | --- | --- | --- |
| RA, rewritten | 6–9 µs | 317–352 µs (870–909) | 3.2–3.3 µs | 3.7–3.8 µs (13–28) |
| DHCPv6 Reply, rewritten | 4 µs | 333–345 µs (645–1284) | 2.2 µs | 2.5 µs (6–20) |
| Other UDP | 6 µs | 6–8 µs | 3.2–3.4 µs | 3.3 µs |

The NFQUEUE round trip through a userspace daemon added about 330 µs to each
RA or DHCPv6 reply; the eBPF program adds about 0.3–0.5 µs.

Packets per second when flooding, each run against the same round without a
sanitizer:

| Flood | NFQUEUE, 32-bit | eBPF, x86-64 |
| --- | --- | --- |
| RAs | 34–36k of 121–124k (−71 to −72%) | 121–141k of 165–175k (−20 to −26%) |
| Other UDP | 105–111k of 122–123k (−10 to −14%) | 170–180k of 185–191k (−3 to −11%) |

The program alone (`BPF_PROG_TEST_RUN`, x86-64, JIT) takes 0.40 µs to rewrite
an RA, 0.31 µs for a DHCPv6 Reply and 0.035–0.05 µs to pass a packet that is
not a target. The daemon uses about 1.4 MiB of memory, against 2.6 MiB for
the NFQUEUE daemon, which also needed libtins and libstdc++ (about 2.1 MiB).

Limits: the NFQUEUE version was not measured on the x86-64 VM; most of its
cost is the trip to userspace, which a faster CPU shortens only in part. On
a 32-bit x86 VM the program is interpreted instead of JIT-compiled (about 65
times slower), so measure there only for correctness. Each drop reports an
event, which cost about 110 µs in these VMs; drops are rare in normal
traffic.

## Build

The package builds the program with OpenWrt's BPF toolchain (`bpf.mk`) and
the daemon against `libbpf`, its only runtime dependency. The kernel needs
tcx, which OpenWrt's 6.6 and newer kernels provide.

With the repository linked into an SDK as `package/l2dns6rw`:

```sh
sh tools/sdk-build.sh x86        # or filogic
```

It stages zlib, libelf and libbpf when the SDK lacks them, then runs
`make package/l2dns6rw/compile NO_DEPS=1`. Set `NO_DEPS=` to let make build
dependencies recursively instead.

## Tests

- `sh tools/host-test.sh`: the daemon's logic (option parsing, automatic DNS
  selection, log lines) and the init script, with the host compiler.
- `sh tests/bpf/run.sh [HOST]`: 55 packet cases run through the program in a
  kernel with `BPF_PROG_TEST_RUN`, natively with sudo or on a test VM.
- `sh tools/vm-test/run.sh [HOST]`: the installed package on an OpenWrt VM,
  through a real bridge: rewrites, restarts, device recreation, automatic
  DNS, detach and idle wakeups.

See `tests/README.md` for details.

## Install

Install the generated package, configure at least one device, then enable
and start the service:

```sh
uci add_list l2dns6rw.main.device='l2vl0'
uci commit l2dns6rw
/etc/init.d/l2dns6rw enable
/etc/init.d/l2dns6rw start
```

## Configuration

OpenWrt configuration file:

```text
/etc/config/l2dns6rw
```

Default:

```uci
config sanitizer 'main'
    # list device 'l2vl0'
    option verbose '0'
    # list dns_server 'fd00::53'
    # list dns_server '2001:db8::53'
```

`device` is required and repeatable: the devices whose incoming RAs and DHCPv6
replies are sanitized, at most 16. The service logs an error and does not
start without one. A device that does not exist yet is attached when it
appears.

`dns_server` is optional and repeatable, up to 8 IPv6 addresses. Without it,
each device's own or its bridge's ULA is used.

`verbose` also logs each rewritten packet. Drops are always logged.

Configure a DNS list and restart the service:

```sh
uci add_list l2dns6rw.main.dns_server='fd00::53'
uci add_list l2dns6rw.main.dns_server='2001:db8::53'
uci commit l2dns6rw
/etc/init.d/l2dns6rw restart
```

Delete the list to return to each device's own ULA:

```sh
uci -q delete l2dns6rw.main.dns_server
```

Releases before the eBPF version used `option queue_number` and nftables
NFQUEUE rules. Remove both: the option is ignored, and the rules would send
packets to a queue nobody reads.

## Logs

```sh
logread -f -e l2dns6rw
```

Examples:

```text
l2vl0: sanitizing RA and DHCPv6 at ingress
l2vl0: DNS fd00:abcd::1(br-lan)
dev=l2vl0 type=RA from=fe80::a rewritten router-lifetime=1800->0 rdnss-options=1 rdnss-addresses=1 removed=1 bytes=72->48
dev=l2vl0 type=RA from=fe80::a DROP: SEND-signed or authenticated message needs a rewrite
packets seen=6 changed=4 unchanged=0 dropped=2
```

## Formatting

Multiword filenames use lowercase hyphens. The included `.clang-format`
follows `CODING_STYLE.md`: four-space indentation, no tabs, Linux-style braces,
and one argument per line for substantial multi-line declarations and calls.

## Source layout

```text
src/
├── l2dns6rw.bpf.c   the BPF program: parsing, rewrite, drop policy
├── l2dns6rw-bpf.h   maps, counters and events shared with the daemon
├── bpf-include/     asm/byteorder.h for the program on any target (MIPS)
├── main.c           daemon: attach devices, follow kernel changes, log events
├── program.c/.h     loading, pinning and attaching the program (libbpf)
├── dns.c/.h         automatic DNS: a device's or its bridge's first ULA
├── netlink.c/.h     link and IPv6 address change notifications
├── events.c/.h      log lines for the program's events
├── options.c/.h     command-line options
├── log.c/.h         logging
└── Makefile         daemon and BPF object
```

## License

MIT
