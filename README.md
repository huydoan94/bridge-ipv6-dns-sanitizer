# l2dns6rw

Small OpenWrt daemon that sanitizes IPv6 Router Advertisements and DHCPv6
server replies received through VXLAN before they reach local clients.

## Packet flow

```text
Remote VXLAN peer
      |
      v
   VXLAN port
      |
      v
bridge prerouting
      |
      v
configured NFQUEUE
      |
      v
 libtins IPv6 parser
   /      |       \
  v       v        v
 RA     DHCPv6    other
 |        |         |
 v        v         |
sanitize sanitize   |
   \      /         |
    v    v          |
    verdict <--------+
      |
      v
 Local bridge clients
```

## What it changes

Router Advertisements:

- Router Lifetime -> `0`
- RDNSS -> configured DNS server list, or one automatically discovered local ULA
- duplicate RDNSS addresses/options -> removed
- DNSSL option 31 -> removed
- PvD option 21 -> removed

DHCPv6 Advertise/Reply packets (`547 -> 546`):

- DNS Recursive Name Server option 23 -> the same selected DNS server list
- duplicate DNS addresses/options -> removed
- Domain Search List option 24 -> removed

When no DNS list is configured, the automatic DNS address is the first ULA
(`fc00::/7`) found on the ingress interface or its bridge master.

Automatic discovery runs at startup and every five seconds in the event loop,
not in packet callbacks. Each refresh takes one OS interface/address snapshot
and resolves bridge membership. Packet processing uses only the in-memory
lookup. When discovery fails or an existing interface temporarily has no ULA,
its last successfully cached DNS remains in use and is retried on the next
refresh. Packets pass unchanged only if neither ingress interface has a cached
DNS. A newly resolved address replaces the old one. A successful snapshot still
removes deleted interfaces and prevents reuse of cached DNS when an interface
index belongs to a different interface name.

The daemon saves a human-readable snapshot (interface index and DNS source) in
an owner-only `/tmp/l2dns6rw-dns-XXXXXX` file and logs its actual path.
It writes only when the snapshot changes, retries failed writes on the next
refresh, and removes the file on normal shutdown. The file is diagnostic: it
is never read per packet or trusted across restarts. A write failure does not
disable the in-memory cache. Configured DNS lists bypass discovery entirely.

## Packet handling

- IPv6 extension-header traversal and transport discovery are delegated to libtins.
- Routing, AH, ESP, Mobility, jumbograms, and other unsupported layouts pass unchanged.
- Fragmented target RA/DHCPv6 packets are dropped.
- If the IPv6 declared length exceeds the bytes delivered by NFQUEUE, the
  packet is dropped.
- If IPv6 or UDP declares a shorter region than NFQUEUE captured, only the
  declared region is sanitized. Bytes after it are preserved unchanged.
- If UDP declares more bytes than are available, the packet is dropped.
- Packet and option buffers are reused. Outgoing netlink padding is explicitly
  zeroed, and oversized verdict payloads are rejected.
- Checksums are calculated only after validation confirms that a packet needs
  editing. Unchanged, malformed, and protected packets avoid that work.
- A valid incoming checksum remains valid after sanitization.
- An invalid incoming checksum remains deliberately invalid after sanitization.
- NFQUEUE checksum-not-ready packets receive a correct checksum after editing.
- DHCPv6 Authentication option 11 and SEND RSA Signature option 12 are left
  untouched. If a protected packet would require sanitization, it is dropped;
  if no change is needed, it passes unchanged.
- Other malformed or unsupported packets pass unchanged.

## Build

The daemon uses OpenWrt's `libtins` package for IPv6 protocol parsing, protocol
constants, formatting, and checksum helpers. Interface snapshots use the
platform's getifaddrs API. It only
needs libtins' core library; libpcap support can be disabled in libtins
configuration if it is not otherwise needed on the target. The package declares
`libnetfilter-queue` and `libtins` as explicit build dependencies so their
headers and libraries are built and staged before the daemon is compiled. They
also remain runtime dependencies of the installed daemon. The `nftables`
utility is used at service startup to inspect the active ruleset.

The package's direct dependencies are `kmod-nft-queue`, `libnetfilter-queue`,
`libtins`, and `nftables`. `kmod-nft-queue` selects `kmod-nfnetlink-queue`
transitively. The example rules do not use the bridge-specific meta, reject, or
conntrack extensions supplied by `kmod-nft-bridge`.

The source directory is still named `package/vxlan-ipv6-sanitize`, so the OpenWrt
build target retains that path.

Add the package to your OpenWrt source tree, then run:

```sh
make package/vxlan-ipv6-sanitize/compile V=s
```

## Tests

The host-side unit suite exercises protocol validation, RA and DHCPv6 rewrite
policy, checksums, logging, NFQUEUE verdict handling, and daemon failure paths.
See `tests/README.md` for normal and branch-coverage commands.

If an earlier build failed with missing `tins/*.h` headers, rebuild the libtins
staging files once before compiling this package again:

```sh
make package/feeds/packages/libtins/clean
make package/feeds/packages/libtins/compile V=s
make package/vxlan-ipv6-sanitize/clean
make package/vxlan-ipv6-sanitize/compile V=s
```

## Install

Install the generated `.ipk`, then enable and start the service:

```sh
/etc/init.d/l2dns6rw enable
/etc/init.d/l2dns6rw start
```

## nftables

The package does **not** install nftables rules. Configure NFQUEUE yourself.

When the service starts, it checks the active numeric nftables ruleset for the
configured queue number, including queue ranges. If no matching rule is found,
or if the ruleset cannot be inspected, it logs a warning and continues to run.
This check does not modify the ruleset.

An example is included at:

```text
examples/90-l2dns6rw.nft
```

Example rules:

```nft
table bridge bridge_ipv6_dns_sanitizer {
    chain vxlan_ingress {
        type filter hook prerouting priority filter; policy accept;

        meta iifkind "vxlan" icmpv6 type nd-router-advert \
            counter queue num 100 bypass

        meta iifkind "vxlan" udp sport 547 udp dport 546 \
            counter queue num 100 bypass
    }
}
```

The daemon accepts only bridge-family packets from the configured NFQUEUE. Linux
exposes the IPv6 packet through `NFQA_PAYLOAD`; bridge L2 metadata is kept
separately by the kernel.

## Configuration

OpenWrt configuration file:

```text
/etc/config/l2dns6rw
```

Default:

```uci
config sanitizer 'main'
    option queue_number '100'
    option verbose '0'
    # list dns_server 'fd00::53'
    # list dns_server '2001:db8::53'
```

`queue_number` is required and must be an integer from `0` through `65535`. The
service logs an error and does not start when the option is missing or invalid.
The nftables rules must use the same number.

`dns_server` is optional and repeatable. If one or more entries are present,
each must be an IPv6 address and the configured list replaces advertised RDNSS
and DHCPv6 DNS addresses. If it is absent, automatic local-ULA discovery remains
active. Up to 10 DNS servers may be configured.

Configure a DNS list and restart the service:

```sh
uci add_list l2dns6rw.main.dns_server='fd00::53'
uci add_list l2dns6rw.main.dns_server='2001:db8::53'
uci commit l2dns6rw
/etc/init.d/l2dns6rw restart
```

Delete the list to return to automatic local-ULA discovery:

```sh
uci -q delete l2dns6rw.main.dns_server
```

Enable verbose packet logging:

```sh
uci set l2dns6rw.main.verbose='1'
uci commit l2dns6rw
/etc/init.d/l2dns6rw restart
```

Change the queue number and restart the service after updating the corresponding
nftables rules:

```sh
uci set l2dns6rw.main.queue_number='200'
uci commit l2dns6rw
/etc/init.d/l2dns6rw restart
```

## Logs

```sh
logread -f -e l2dns6rw
```

At startup, the daemon reports its packaged version. The message text omits the
redundant `l2dns6rw:` prefix because procd already identifies
the process in the system log.

## Formatting

Multiword filenames use lowercase hyphens. C and C++ identifiers use underscores
where required by the language.

The included `.clang-format` follows `CODING_STYLE.md`: four-space indentation,
no tabs, Linux-style braces, and one argument per line for substantial
multi-line declarations and calls. `ColumnLimit: 0` avoids arbitrary wrapping;
long expressions should be split where doing so improves readability.

## Source layout

```text
.clang-format             project C++ formatting rules
src/
├── l2dns6rw.cpp daemon and packet sanitizers
├── constants.h                     shared application and protocol constants
├── network.cpp             interface and local-address discovery
├── network.h
├── packet.cpp              packet mutation and checksum mechanics
├── packet.h
├── packet-parser.cpp       libtins IPv6 transport parser
├── packet-parser.h         parser interface
├── logging.cpp             logging and log formatting
└── logging.h
```

## License

MIT
