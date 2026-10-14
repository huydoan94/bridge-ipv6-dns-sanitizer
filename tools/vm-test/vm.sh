#!/bin/sh
# vm.sh: runs on the test VM, driven by tools/vm-test/run.sh.
#
#   vm.sh setup                 test bridge br-l2t with veth ports vA-br and
#                               vB-br; their peers vA (sender) and vB (capture)
#                               stay outside the bridge with IPv6 disabled;
#                               br-l2t holds fd00:abcd::1/64; a bridge nft
#                               table queues RA and DHCPv6 replies from vA-br
#   vm.sh case NAME [ARG...]    captures on vB while sending ra.bin, dhcp.bin
#                               and send.bin from vA; ARG... starts the daemon
#                               with those arguments, "auto" with none (the
#                               automatic DNS mode), "auto-no-ula" likewise
#                               with br-l2t's ULA removed, "none" runs none
#   vm.sh idle SECONDS ARG...   counts the daemon's context switches while idle
#   vm.sh teardown              removes everything setup created
#
# Files live in /tmp/l2t; br-lan, fw4 and other tables are never touched.
set -eu

dir=/tmp/l2t
mkdir -p "$dir"
setup() {
	ip link add br-l2t type bridge
	for side in A B; do
		ip link add "v$side-br" type veth peer name "v$side"
		ip link set "v$side-br" master br-l2t
		for device in "v$side" "v$side-br"; do
			echo 1 >"/proc/sys/net/ipv6/conf/$device/disable_ipv6"
			ip link set "$device" up
		done
	done
	ip link set vB address 02:00:00:00:00:0b
	ip link set br-l2t up
	ip -6 addr add fd00:abcd::1/64 dev br-l2t nodad
	nft -f - <<'RULES'
table bridge l2t {
	chain prerouting {
		type filter hook prerouting priority filter; policy accept;
		iifname "vA-br" icmpv6 type nd-router-advert counter queue num 100
		iifname "vA-br" udp sport 547 udp dport 546 counter queue num 100
	}
}
RULES
	echo "setup done"
}

start_daemon() { # NAME ARG...
	name=$1
	shift
	/usr/sbin/l2dns6rw -q 100 "$@" -v >"$dir/$name.log" 2>&1 &
	daemon=$!
	sleep 1
	kill -0 "$daemon" || { cat "$dir/$name.log"; echo "daemon exited" >&2; exit 1; }
}

run_case() { # NAME ARG...
	name=$1
	shift
	daemon=
	tcpdump -q -U -i vB -w "$dir/$name.pcap" ip6 2>"$dir/$name.tcpdump" &
	capture=$!
	sleep 1
	case $1 in
	none) : >"$dir/$name.log" ;;
	auto) start_daemon "$name" ;;
	auto-no-ula)
		ip -6 addr del fd00:abcd::1/64 dev br-l2t
		start_daemon "$name"
		;;
	*) start_daemon "$name" "$@" ;;
	esac
	for frames in ra dhcp send; do
		"$dir/send-frames" vA "$dir/$frames.bin"
	done
	sleep 1
	kill "$capture"
	wait "$capture" 2>/dev/null || true
	if [ -n "$daemon" ]; then
		kill "$daemon"
		wait "$daemon" 2>/dev/null || true
	fi
	[ "$1" != auto-no-ula ] || ip -6 addr add fd00:abcd::1/64 dev br-l2t nodad
	nft list chain bridge l2t prerouting | sed -n 's/.*counter \(packets [0-9]* bytes [0-9]*\).*/\1/p' |
		tr '\n' ';' | sed 's/^/nft counters: /; s/$/\n/'
	echo "--- daemon log ($name)"
	cat "$dir/$name.log"
}

idle() { # SECONDS ARG...
	seconds=$1
	shift
	start_daemon idle "$@"
	sleep 2
	before=$(sed -n 's/^voluntary_ctxt_switches:\t*//p' "/proc/$daemon/status")
	sleep "$seconds"
	after=$(sed -n 's/^voluntary_ctxt_switches:\t*//p' "/proc/$daemon/status")
	kill "$daemon"
	wait "$daemon" 2>/dev/null || true
	echo "idle $seconds s: voluntary context switches $before -> $after (+$((after - before)))"
}

teardown() {
	nft delete table bridge l2t 2>/dev/null || true
	ip link del br-l2t 2>/dev/null || true
	for side in A B; do
		ip link del "v$side-br" 2>/dev/null || true
	done
	echo "teardown done"
}

command=${1:-}
[ "$#" -eq 0 ] || shift
case $command in
setup) setup ;;
case) run_case "$@" ;;
idle) idle "$@" ;;
teardown) teardown ;;
*) sed -n '2,17p' "$0" >&2; exit 2 ;;
esac
