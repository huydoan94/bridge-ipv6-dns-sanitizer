#!/usr/bin/env python3
"""frames.py: builds the VM test frames and checks the frames captured after
the bridge, using only the standard library.

  frames.py write DIRECTORY           writes ra.bin, dhcp.bin and send.bin
  frames.py check MODE DNS PCAP       checks a capture; MODE is rewrite or
                                      bypass, DNS the expected servers,
                                      comma-separated

Each .bin file holds frames as a 2-byte big-endian length and the bytes, as
send-frames.c reads them. check prints one line per verdict and exits 1 when
any expectation fails.
"""
import ipaddress
import struct
import sys

SRC_MAC = bytes.fromhex("02000000000a")
DST_MAC = bytes.fromhex("02000000000b")
ALL_NODES_MAC = bytes.fromhex("333300000001")
ROUTER = ipaddress.IPv6Address("fe80::a").packed
CLIENT = ipaddress.IPv6Address("fe80::b").packed
ALL_NODES = ipaddress.IPv6Address("ff02::1").packed
REMOTE_DNS = ipaddress.IPv6Address("fd99::1").packed
DOMAIN = b"\x07example\x03com\x00"
XID = bytes.fromhex("123456")
CLIENT_DUID = struct.pack("!HH", 3, 1) + DST_MAC  # DUID-LL, Ethernet


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total


def upper_checksum(src, dst, protocol, payload):
    pseudo = src + dst + struct.pack("!IxxxB", len(payload), protocol)
    return ~checksum(pseudo + payload) & 0xFFFF


def ipv6_frame(dst_mac, src, dst, protocol, payload, hop_limit):
    header = struct.pack("!IHBB", 6 << 28, len(payload), protocol, hop_limit) + src + dst
    return dst_mac + SRC_MAC + b"\x86\xdd" + header + payload


def nd_option(kind, body):
    padded = body + b"\0" * (-(len(body) + 2) % 8)
    return struct.pack("!BB", kind, (len(padded) + 2) // 8) + padded


def router_advertisement(extra_options=b""):
    options = (
        nd_option(1, SRC_MAC)
        + nd_option(25, b"\0\0" + struct.pack("!I", 600) + REMOTE_DNS)
        + nd_option(31, b"\0\0" + struct.pack("!I", 600) + DOMAIN)
        + extra_options
    )
    icmp = struct.pack("!BBHBBHII", 134, 0, 0, 64, 0, 1800, 0, 0) + options
    icmp = icmp[:2] + struct.pack("!H", upper_checksum(ROUTER, ALL_NODES, 58, icmp)) + icmp[4:]
    return ipv6_frame(ALL_NODES_MAC, ROUTER, ALL_NODES, 58, icmp, 255)


def send_advertisement():
    # A SEND RSA Signature option (type 12); the RA still needs a rewrite.
    return router_advertisement(nd_option(12, b"\0" * 6))


def dhcp_option(code, body):
    return struct.pack("!HH", code, len(body)) + body


def dhcpv6_reply():
    message = (
        b"\x07"
        + XID
        + dhcp_option(1, CLIENT_DUID)
        + dhcp_option(23, REMOTE_DNS)
        + dhcp_option(24, DOMAIN)
    )
    udp = struct.pack("!HHHH", 547, 546, 8 + len(message), 0) + message
    udp = udp[:6] + struct.pack("!H", upper_checksum(ROUTER, CLIENT, 17, udp) or 0xFFFF) + udp[8:]
    return ipv6_frame(DST_MAC, ROUTER, CLIENT, 17, udp, 64)


def write_frames(path, frames):
    with open(path, "wb") as output:
        for frame in frames:
            output.write(struct.pack("!H", len(frame)) + frame)


def read_pcap(path):
    with open(path, "rb") as capture:
        data = capture.read()
    magic = struct.unpack("<I", data[:4])[0]
    order = "<" if magic in (0xA1B2C3D4, 0xA1B23C4D) else ">"
    link_type = struct.unpack(order + "I", data[20:24])[0]
    offset = 24
    frames = []
    while offset + 16 <= len(data):
        captured = struct.unpack(order + "IIII", data[offset:offset + 16])[2]
        frame = data[offset + 16:offset + 16 + captured]
        offset += 16 + captured
        if link_type == 113:  # Linux cooked capture: 16-byte header, no MACs.
            frame = b"\0" * 12 + frame[14:16] + frame[16:]
        frames.append(frame)
    return frames


def nd_options(data):
    options = []
    while data:
        kind, length = data[0], data[1] * 8
        options.append((kind, data[2:length]))
        data = data[length:]
    return options


def dhcp_options(data):
    options = []
    while data:
        code, length = struct.unpack("!HH", data[:4])
        options.append((code, data[4:4 + length]))
        data = data[4 + length:]
    return options


def check(mode, dns, path):
    expected_dns = b"".join(ipaddress.IPv6Address(server).packed for server in dns.split(",")) if mode == "rewrite" else None
    results = []

    def expect(condition, text):
        results.append(condition)
        print(("ok   " if condition else "FAIL ") + text)

    seen = {"ra": [], "dhcp": []}
    for frame in read_pcap(path):
        if frame[12:14] != b"\x86\xdd":
            continue
        ip = frame[14:]
        src, dst, protocol, payload = ip[8:24], ip[24:40], ip[6], ip[40:]
        if protocol == 58 and payload[0] == 134:
            seen["ra"].append((src, dst, payload, frame))
        elif protocol == 17 and struct.unpack("!HH", payload[:4]) == (547, 546):
            seen["dhcp"].append((src, dst, payload, frame))

    if mode == "bypass":
        expect([ra[3] for ra in seen["ra"]] == [router_advertisement(), send_advertisement()],
               "both RAs passed byte-for-byte unchanged with no listener")
        expect(len(seen["dhcp"]) == 1 and seen["dhcp"][0][3] == dhcpv6_reply(),
               "DHCPv6 Reply passed byte-for-byte unchanged with no listener")
        return all(results)

    expect(len(seen["ra"]) == 1, f"one RA received, the SEND-signed one dropped (got {len(seen['ra'])})")
    if seen["ra"]:
        src, dst, icmp, _ = seen["ra"][0]
        options = nd_options(icmp[16:])
        kinds = [kind for kind, _ in options]
        rdnss = [body[6:] for kind, body in options if kind == 25]
        expect(len(icmp) == 16 + sum(2 + len(body) for _, body in options), "RA options fill the ICMPv6 payload")
        expect(struct.unpack("!H", icmp[6:8])[0] == 0, "RA router lifetime is 0")
        expect(rdnss == [expected_dns], f"RA RDNSS is [{dns}]")
        expect(31 not in kinds, "RA DNSSL removed")
        expect(1 in kinds and 12 not in kinds, "RA source link-layer option kept, no SEND option")
        expect(checksum(src + dst + struct.pack("!IxxxB", len(icmp), 58) + icmp) == 0xFFFF,
               "RA ICMPv6 checksum valid")
    expect(len(seen["dhcp"]) == 1, f"one DHCPv6 Reply received (got {len(seen['dhcp'])})")
    if seen["dhcp"]:
        src, dst, udp, _ = seen["dhcp"][0]
        options = dhcp_options(udp[12:struct.unpack("!H", udp[4:6])[0]])
        codes = [code for code, _ in options]
        expect([body for code, body in options if code == 23] == [expected_dns],
               f"DHCPv6 DNS servers are [{dns}]")
        expect(24 not in codes, "DHCPv6 domain list removed")
        expect([body for code, body in options if code == 1] == [CLIENT_DUID], "DHCPv6 client ID kept")
        expect(udp[4:6] == struct.pack("!H", len(udp)), "UDP length matches the rewritten message")
        expect(checksum(src + dst + struct.pack("!IxxxB", len(udp), 17) + udp) == 0xFFFF,
               "UDP checksum valid")
    return all(results)


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "write":
        directory = sys.argv[2]
        write_frames(f"{directory}/ra.bin", [router_advertisement()])
        write_frames(f"{directory}/dhcp.bin", [dhcpv6_reply()])
        write_frames(f"{directory}/send.bin", [send_advertisement()])
        return 0
    if len(sys.argv) == 5 and sys.argv[1] == "check":
        return 0 if check(sys.argv[2], sys.argv[3], sys.argv[4]) else 1
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
