# bridge-ipv6-dns-sanitizer

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
  NFQUEUE 100
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
- RDNSS -> one local ULA
- duplicate RDNSS addresses/options -> removed
- DNSSL option 31 -> removed
- PvD option 21 -> removed

DHCPv6 Advertise/Reply packets (`547 -> 546`):

- DNS Recursive Name Server option 23 -> one local ULA
- duplicate DNS addresses/options -> removed
- Domain Search List option 24 -> removed

The local DNS address is the first ULA (`fc00::/7`) found on the ingress
interface or its bridge master.

## Packet handling

- IPv6 extension-header traversal and transport discovery are delegated to libtins.
- Routing, AH, ESP, Mobility, jumbograms, and other unsupported layouts pass unchanged.
- Fragmented target RA/DHCPv6 packets are dropped.
- If the IPv6 declared length exceeds the bytes delivered by NFQUEUE, the
  packet is dropped.
- If IPv6 or UDP declares a shorter region than NFQUEUE captured, only the
  declared region is sanitized. Bytes after it are preserved unchanged.
- If UDP declares more bytes than are available, the packet is dropped.
- A valid incoming checksum remains valid after sanitization.
- An invalid incoming checksum remains deliberately invalid after sanitization.
- NFQUEUE checksum-not-ready packets receive a correct checksum after editing.
- DHCPv6 Authentication option 11 and SEND RSA Signature option 12 are left
  untouched. If a protected packet would require sanitization, it is dropped;
  if no change is needed, it passes unchanged.
- Other malformed or unsupported packets pass unchanged.

## Build

The daemon uses OpenWrt's `libtins` package for IPv6 protocol parsing, protocol
constants, interface/address access, formatting, and checksum helpers. It only
needs libtins' core library; libpcap support can be disabled in libtins
configuration if it is not otherwise needed on the target. The package declares
`libnetfilter-queue` and `libtins` as explicit build dependencies so their
headers and libraries are built and staged before the daemon is compiled. They
also remain runtime dependencies of the installed daemon.

The package's direct dependencies are `kmod-nft-queue`, `libnetfilter-queue`,
and `libtins`. `kmod-nft-queue` selects `kmod-nfnetlink-queue` transitively. The
example rules do not use the bridge-specific meta, reject, or conntrack
extensions supplied by `kmod-nft-bridge`.

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
/etc/init.d/bridge-ipv6-dns-sanitizer enable
/etc/init.d/bridge-ipv6-dns-sanitizer start
```

## nftables

The package does **not** install nftables rules. Configure NFQUEUE yourself.

An example is included at:

```text
examples/90-bridge-ipv6-dns-sanitizer.nft
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

The daemon accepts only bridge-family packets from NFQUEUE `100`. Linux exposes
the IPv6 packet through `NFQA_PAYLOAD`; bridge L2 metadata is kept separately by
the kernel.

## Configuration

OpenWrt configuration file:

```text
/etc/config/bridge-ipv6-dns-sanitizer
```

Default:

```uci
config sanitizer 'main'
    option verbose '0'
```

Enable verbose packet logging:

```sh
uci set bridge-ipv6-dns-sanitizer.main.verbose='1'
uci commit bridge-ipv6-dns-sanitizer
/etc/init.d/bridge-ipv6-dns-sanitizer restart
```

## Logs

```sh
logread -f -e bridge-ipv6-dns-sanitizer
```

At startup, the daemon reports its packaged version. The message text omits the
redundant `bridge-ipv6-dns-sanitizer:` prefix because procd already identifies
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
├── bridge-ipv6-dns-sanitizer.cpp daemon and packet sanitizers
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
