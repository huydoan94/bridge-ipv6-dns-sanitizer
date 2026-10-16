#!/usr/bin/env python3
"""cases.py: the BPF program's packet tests.

  cases.py write FILE        writes the test frames for tests/bpf/runner
  cases.py check RESULTS     checks the runner's output; exits 1 on a failure

Each case is a frame, the device's DNS list (or none) and what the program
must do: pass it untouched, drop it for a given reason, or rewrite it. A
rewrite is checked option by option: the first DNS option carries exactly
the device's list, removed options are gone, every other option is kept in
order, lengths match, and the checksum is valid (or still invalid when it
arrived invalid). Verdict and reason numbers come from src/l2dns6rw-bpf.h.
"""
import ipaddress
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "tools", "vm-test"))
from frames import checksum, dhcp_options, nd_option, nd_options  # noqa: E402

TCX_PASS = 0
TCX_DROP = 2

SRC_MAC = bytes.fromhex("02000000000a")
CLIENT_MAC = bytes.fromhex("02000000000b")
ALL_NODES_MAC = bytes.fromhex("333300000001")
ROUTER = ipaddress.IPv6Address("fe80::a").packed
CLIENT = ipaddress.IPv6Address("fe80::b").packed
ALL_NODES = ipaddress.IPv6Address("ff02::1").packed
REMOTE = ipaddress.IPv6Address("fd99::1").packed
DOMAIN = b"\x07example\x03com\x00"
CLIENT_DUID = struct.pack("!HH", 3, 1) + CLIENT_MAC
ONE = ["fd00::53"]
TWO = ["fd00::53", "fd00::54"]
EIGHT = [f"fd00::{i}" for i in range(1, 9)]


def header_enum(name):
    """Maps the names of enum NAME in src/l2dns6rw-bpf.h to their values."""
    with open(os.path.join(HERE, "..", "..", "src", "l2dns6rw-bpf.h")) as header:
        body = re.search(r"enum %s \{(.*?)\};" % name, header.read(), re.S).group(1)
    names = re.findall(r"L2DNS6RW_[A-Z0-9_]+", body)
    return {entry.split("_", 2)[2]: index for index, entry in enumerate(names)}


VERDICT = header_enum("l2dns6rw_verdict")
REASON = header_enum("l2dns6rw_reason")


def packed(addresses):
    return b"".join(ipaddress.IPv6Address(address).packed for address in addresses)


def pseudo_sum(src, dst, protocol, l4):
    return checksum(src + dst + struct.pack("!IxxxB", len(l4), protocol) + l4)


def with_checksum(l4, offset, src, dst, protocol, state):
    l4 = l4[:offset] + b"\0\0" + l4[offset + 2:]
    value = ~pseudo_sum(src, dst, protocol, l4) & 0xFFFF
    if protocol == 17 and value == 0:
        value = 0xFFFF
    if state == "invalid":
        value ^= 1
    if state == "zero":
        value = 0
    return l4[:offset] + struct.pack("!H", value) + l4[offset + 2:]


def extension(kind, next_header, **fields):
    if kind in ("hop", "dest"):
        return bytes([next_header, 0]) + b"\x01\x04\0\0\0\0"  # PadN to 8 bytes
    if kind == "routing":
        return bytes([next_header, 0, 4, fields.get("segments", 0)]) + b"\0" * 4
    if kind == "auth":
        return bytes([next_header, 2]) + b"\0\0" + struct.pack("!II", 0x100, 1) + b"\0" * 4  # 16 bytes
    if kind == "fragment":
        offset_flags = fields.get("offset", 0) << 3 | (1 if fields.get("more") else 0)
        return bytes([next_header, 0]) + struct.pack("!HI", offset_flags, 0x1234)
    raise ValueError(kind)


EXTENSION_NUMBER = {"hop": 0, "dest": 60, "routing": 43, "fragment": 44, "auth": 51}


def ipv6_frame(src, dst, protocol, l4, extensions=(), payload_len=None, dst_mac=ALL_NODES_MAC, trailing=b""):
    chain = b""
    next_headers = [EXTENSION_NUMBER[kind] for kind, _ in extensions] + [protocol]
    for (kind, fields), following in zip(extensions, next_headers[1:]):
        chain += extension(kind, following, **fields)
    payload = chain + l4 + trailing
    if payload_len is None:
        payload_len = len(payload)
    header = struct.pack("!IHBB", 6 << 28, payload_len, next_headers[0], 255) + src + dst
    return dst_mac + SRC_MAC + b"\x86\xdd" + header + payload


def ra(options, lifetime=1800, state="valid"):
    icmp = struct.pack("!BBHBBHII", 134, 0, 0, 64, 0, lifetime, 0, 0) + b"".join(options)
    return with_checksum(icmp, 2, ROUTER, ALL_NODES, 58, state)


def ra_frame(options, lifetime=1800, state="valid", **frame):
    return ipv6_frame(ROUTER, ALL_NODES, 58, ra(options, lifetime, state), **frame)


def rdnss(addresses):
    return nd_option(25, b"\0\0" + struct.pack("!I", 600) + packed(addresses))


SLLA = nd_option(1, SRC_MAC)
DNSSL = nd_option(31, b"\0\0" + struct.pack("!I", 600) + DOMAIN)
PVD = nd_option(21, b"\0" * 14)
SEND = nd_option(12, b"\0" * 6)
PREFIX = nd_option(3, bytes([64, 0xC0]) + struct.pack("!III", 86400, 14400, 0) + bytes(16))


def option(code, body):
    return struct.pack("!HH", code, len(body)) + body


def dhcp(options, message=7, sport=547, dport=546, state="valid", length_delta=0):
    body = bytes([message]) + b"\x12\x34\x56" + b"".join(options)
    udp = struct.pack("!HHHH", sport, dport, 8 + len(body) + length_delta, 0) + body
    return with_checksum(udp, 6, ROUTER, CLIENT, 17, state)


def dhcp_frame(options, trailing=b"", **fields):
    return ipv6_frame(ROUTER, CLIENT, 17, dhcp(options, **fields), dst_mac=CLIENT_MAC, trailing=trailing)


CLIENTID = option(1, CLIENT_DUID)
DNS = option(23, REMOTE)
DOMAINS = option(24, DOMAIN)
AUTH = option(11, b"\x03\x01\x00" + b"\0" * 8 + b"\0" * 8)


def case(name, frame, expect, dns=ONE, **details):
    return dict(name=name, frame=frame, expect=expect, dns=dns, **details)


def cases():
    malformed = ("drop", "MALFORMED_OPTION")
    many = [nd_option(1, SRC_MAC)] * 65
    long_option = nd_option(14, b"\0" * (2040 - 2))  # one nonce-like option of 2040 bytes
    return [
        # Router Advertisements
        case("ra-rewrite", ra_frame([SLLA, rdnss(["fd99::1"]), DNSSL, PREFIX]), "rewrite"),
        case("ra-two-servers", ra_frame([SLLA, rdnss(["fd99::1"]), DNSSL]), "rewrite", dns=TWO),
        case("ra-eight-servers", ra_frame([rdnss(["fd99::1"])]), "rewrite", dns=EIGHT),
        case("ra-compliant", ra_frame([SLLA, rdnss(ONE)], lifetime=0), "pass"),
        case("ra-lifetime-only", ra_frame([SLLA, PREFIX]), "rewrite"),
        case("ra-duplicate-rdnss", ra_frame([rdnss(["fd99::1"]), SLLA, rdnss(["fd99::2", "fd99::3"])]), "rewrite"),
        case("ra-same-servers-lifetime", ra_frame([rdnss(ONE)], lifetime=600), "rewrite"),
        case("ra-pvd", ra_frame([PVD, rdnss(ONE)], lifetime=0), "rewrite"),
        case("ra-dnssl-only", ra_frame([DNSSL], lifetime=0), "rewrite"),
        case("ra-send-needs-rewrite", ra_frame([rdnss(["fd99::1"]), SEND]), ("drop", "PROTECTED")),
        case("ra-send-compliant", ra_frame([rdnss(ONE), SEND], lifetime=0), "pass"),
        case("ra-bad-checksum", ra_frame([rdnss(["fd99::1"])], state="invalid"), "rewrite", invalid=True),
        case("ra-zero-length-option", ra_frame([rdnss(["fd99::1"]), b"\x01\x00" + b"\0" * 6]), malformed),
        case("ra-rdnss-bad-length", ra_frame([SLLA, nd_option(25, b"\0" * 14)]), "rewrite"),
        case("ra-rdnss-bad-length-then-good", ra_frame([nd_option(25, b"\0" * 14), SLLA, rdnss(["fd99::1"])]), "rewrite"),
        case("ra-option-overrun", ra_frame([b"\x01\x04" + b"\0" * 14]), malformed),
        case("ra-short", ipv6_frame(ROUTER, ALL_NODES, 58, b"\x86\0\0\0" + b"\0" * 8), ("drop", "MALFORMED_HEADER")),
        case("ra-no-dns", ra_frame([rdnss(["fd99::1"])]), ("drop", "NO_DNS"), dns=None),
        case("ra-hop-by-hop", ra_frame([rdnss(["fd99::1"]), DNSSL], extensions=[("hop", {})]), "rewrite"),
        case("ra-seven-headers", ra_frame([rdnss(["fd99::1"])], extensions=[("hop", {})] + [("dest", {})] * 6), "rewrite"),
        case("ra-nine-headers", ra_frame([rdnss(["fd99::1"])], extensions=[("hop", {})] + [("dest", {})] * 8),
             ("drop", "TOO_MANY_HEADERS")),
        case("ra-routing-header", ra_frame([rdnss(["fd99::1"])], extensions=[("routing", {})]), "rewrite"),
        case("ra-routing-segments-left", ra_frame([rdnss(["fd99::1"])], extensions=[("routing", {"segments": 1})]),
             ("drop", "ROUTED")),
        case("ra-ah-needs-rewrite", ra_frame([rdnss(["fd99::1"])], extensions=[("auth", {})]), ("drop", "PROTECTED")),
        case("ra-ah-compliant", ra_frame([rdnss(ONE)], lifetime=0, extensions=[("auth", {})]), "pass"),
        case("ra-first-fragment", ra_frame([rdnss(["fd99::1"])], extensions=[("fragment", {"more": True})]),
             ("drop", "FRAGMENT")),
        case("ra-atomic-fragment", ra_frame([rdnss(["fd99::1"])], extensions=[("fragment", {})]), "rewrite"),
        case("ra-later-fragment", ra_frame([rdnss(["fd99::1"])], extensions=[("fragment", {"offset": 1})]), "pass"),
        case("ra-jumbogram", ra_frame([rdnss(["fd99::1"])], extensions=[("hop", {})], payload_len=0),
             ("drop", "JUMBOGRAM")),
        case("ra-truncated", ra_frame([rdnss(["fd99::1"])], payload_len=200), ("drop", "TRUNCATED")),
        case("ra-too-many-options", ra_frame(many), ("drop", "TOO_MANY_OPTIONS")),
        case("ra-too-long", ra_frame([rdnss(["fd99::1"]), long_option]), ("drop", "TOO_LONG")),
        case("ra-growth-over-limit", ra_frame([rdnss(["fd99::1"]), nd_option(14, b"\0" * (2000 - 2))]),
             ("drop", "TOO_LONG"), dns=EIGHT),
        # Not targets
        case("icmpv6-neighbor-solicitation", ipv6_frame(ROUTER, ALL_NODES, 58, b"\x87\0\0\0" + b"\0" * 20), "pass"),
        case("ipv4", ALL_NODES_MAC + SRC_MAC + b"\x08\x00" + b"\x45" + b"\0" * 39, "pass"),
        case("udp-other-port", ipv6_frame(ROUTER, CLIENT, 17, dhcp([DNS], sport=53, dport=546)), "pass"),
        case("dhcpv6-request", dhcp_frame([CLIENTID, DNS], message=3, sport=546, dport=547), "pass"),
        # DHCPv6
        case("dhcpv6-reply-rewrite", dhcp_frame([CLIENTID, DNS, DOMAINS]), "rewrite"),
        case("dhcpv6-advertise-rewrite", dhcp_frame([CLIENTID, DNS, DOMAINS], message=2), "rewrite"),
        case("dhcpv6-two-servers", dhcp_frame([CLIENTID, DNS]), "rewrite", dns=TWO),
        case("dhcpv6-duplicate-dns", dhcp_frame([DNS, CLIENTID, option(23, packed(["fd99::2", "fd99::3"]))]), "rewrite"),
        case("dhcpv6-domain-list-only", dhcp_frame([CLIENTID, option(23, packed(ONE)), DOMAINS]), "rewrite"),
        case("dhcpv6-compliant", dhcp_frame([CLIENTID, option(23, packed(ONE))]), "pass"),
        case("dhcpv6-no-dns-option", dhcp_frame([CLIENTID]), "pass"),
        case("dhcpv6-auth-needs-rewrite", dhcp_frame([CLIENTID, DNS, AUTH]), ("drop", "PROTECTED")),
        case("dhcpv6-auth-compliant", dhcp_frame([CLIENTID, option(23, packed(ONE)), AUTH]), "pass"),
        case("dhcpv6-reconfigure", dhcp_frame([CLIENTID, DNS], message=10), "pass"),
        case("dhcpv6-zero-checksum", dhcp_frame([CLIENTID, DNS], state="zero"), "rewrite", invalid=True),
        case("dhcpv6-bad-checksum", dhcp_frame([CLIENTID, DNS], state="invalid"), "rewrite", invalid=True),
        case("dhcpv6-dns-bad-length", dhcp_frame([CLIENTID, option(23, b"\0" * 8)]), "rewrite"),
        case("dhcpv6-option-overrun", dhcp_frame([b"\x00\x01\x00\x40" + b"\0" * 4]), malformed),
        case("dhcpv6-udp-length-too-big", dhcp_frame([DNS], length_delta=8), ("drop", "TRUNCATED")),
        case("dhcpv6-udp-length-short", dhcp_frame([DNS], length_delta=-24), ("drop", "MALFORMED_HEADER")),
        case("dhcpv6-trailing-bytes", dhcp_frame([CLIENTID, DNS], trailing=b"\xaa" * 4), "rewrite"),
        case("dhcpv6-no-dns", dhcp_frame([CLIENTID, DNS]), ("drop", "NO_DNS"), dns=None),
    ]


def write(path):
    with open(path, "w") as output:
        for item in cases():
            dns = ",".join(item["dns"]) if item["dns"] else "-"
            output.write(f"{item['name']} {dns} {item['frame'].hex()}\n")


def split(frame):
    """Returns (ip header, extension headers, protocol, l4) of an IPv6 frame."""
    ip = frame[14:54]
    protocol, offset = ip[6], 54
    while protocol in (0, 60, 43, 44, 51):
        if protocol == 44:
            length = 8
        elif protocol == 51:
            length = (frame[offset + 1] + 2) * 4
        else:
            length = (frame[offset + 1] + 1) * 8
        protocol, offset = frame[offset], offset + length
    return ip, frame[54:offset], protocol, frame[offset:]


def check_rewrite(item, output, problems):
    original_ip, original_chain, protocol, original = split(item["frame"])
    ip, chain, _, l4 = split(output)
    expected_dns = packed(item["dns"])
    if struct.unpack("!H", ip[4:6])[0] != len(output) - 54:
        problems.append("IPv6 payload length does not match the frame")
    if ip[:4] + ip[6:] != original_ip[:4] + original_ip[6:] or chain != original_chain:
        problems.append("IPv6 header or extension headers changed")
    valid = pseudo_sum(ip[8:24], ip[24:40], protocol, l4) == 0xFFFF
    if valid == item.get("invalid", False):
        problems.append("checksum is %s, expected %s" % ("valid" if valid else "invalid", "invalid" if valid else "valid"))
    if protocol == 58:
        before, after = nd_options(original[16:]), nd_options(l4[16:])
        removed = {25, 31, 21}
        if struct.unpack("!H", l4[6:8])[0] != 0:
            problems.append("router lifetime is not 0")
        if l4[:2] + l4[4:6] + l4[8:16] != original[:2] + original[4:6] + original[8:16]:
            problems.append("RA header fields changed")
        dns = [body[6:] for kind, body in after if kind == 25]
        # An RDNSS of a bad length is removed, not rewritten.
        had_dns = any(kind == 25 and len(body) > 6 and (len(body) - 6) % 16 == 0 for kind, body in before)
    else:
        before = dhcp_options(original[12:struct.unpack("!H", original[4:6])[0]])
        after = dhcp_options(l4[12:])
        removed = {23, 24}
        if struct.unpack("!H", l4[4:6])[0] != len(l4):
            problems.append("UDP length does not match the message")
        if l4[:4] + l4[8:12] != original[:4] + original[8:12]:
            problems.append("ports, message type or transaction ID changed")
        dns = [body for code, body in after if code == 23]
        # A DNS option of a bad length is removed, not rewritten.
        had_dns = any(code == 23 and body and len(body) % 16 == 0 for code, body in before)
    if dns != ([expected_dns] if had_dns else []):
        problems.append(f"DNS options are {[d.hex() for d in dns]}, expected {[expected_dns.hex()] if had_dns else []}")
    if [o for o in after if o[0] not in removed] != [o for o in before if o[0] not in removed]:
        problems.append("other options were not kept in order")
    if any(o[0] in (31, 21, 24) for o in after):
        problems.append("a search-list or PvD option remains")


def check(path):
    expected = {item["name"]: item for item in cases()}
    failures = 0
    seen = set()
    with open(path) as results:
        for line in results:
            name, retval, output_hex, verdict, reason = line.split()
            item = expected[name]
            output = bytes.fromhex(output_hex)
            problems = []
            seen.add(name)
            mode = item["expect"] if isinstance(item["expect"], str) else item["expect"][0]
            wanted_reason = None if isinstance(item["expect"], str) else REASON[item["expect"][1]]
            if mode == "pass":
                if int(retval) != TCX_PASS or output != item["frame"]:
                    problems.append("not passed untouched")
                if verdict != "-":
                    problems.append(f"reported verdict {verdict}")
            elif mode == "drop":
                if int(retval) != TCX_DROP:
                    problems.append("not dropped")
                if (verdict, reason) != (str(VERDICT["DROPPED"]), str(wanted_reason)):
                    problems.append(f"reported {verdict}/{reason}, expected dropped/{wanted_reason}")
            else:
                if int(retval) != TCX_PASS:
                    problems.append("not passed")
                if verdict != str(VERDICT["CHANGED"]):
                    problems.append(f"reported verdict {verdict}, expected changed")
                check_rewrite(item, output, problems)
            print(("ok   " if not problems else "FAIL ") + name + ("" if not problems else ": " + "; ".join(problems)))
            failures += bool(problems)
    for name in sorted(set(expected) - seen):
        print(f"FAIL {name}: no result")
        failures += 1
    print(f"{len(expected)} cases, {failures} failures")
    return failures == 0


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "write":
        write(sys.argv[2])
        return 0
    if len(sys.argv) == 3 and sys.argv[1] == "check":
        return 0 if check(sys.argv[2]) else 1
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
