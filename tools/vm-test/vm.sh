#!/bin/sh
# vm.sh: runs on the test VM, driven by tools/vm-test/run.sh.
#
#   vm.sh setup                 test bridge br-l2t with veth ports vA-br and
#                               vB-br; their peers vA (sender) and vB (capture)
#                               stay outside the bridge with IPv6 disabled;
#                               br-l2t holds fd00:abcd::1/64
#   vm.sh start [ARG...]        starts the daemon on vA-br with ARG... (-d, -v)
#                               and waits until it has attached
#   vm.sh stop                  stops the daemon (the pinned program stays)
#   vm.sh detach                detaches the program (l2dns6rw -D)
#   vm.sh send NAME             captures on vB while sending ra.bin, dhcp.bin
#                               and send.bin from vA, into NAME.pcap
#   vm.sh recreate              deletes and recreates the vA-br port, then
#                               waits until the daemon has re-attached
#   vm.sh ula del|add           removes or restores br-l2t's ULA
#   vm.sh idle SECONDS          counts the daemon's context switches while idle,
#                               after 5 s for earlier changes to settle
#   vm.sh teardown              stops and detaches, removes everything setup made
#
# Files live in /tmp/l2t; br-lan, fw4 and other devices are never touched.
set -eu

dir=/tmp/l2t
log=$dir/daemon.log
pidfile=$dir/daemon.pid
mkdir -p "$dir"

add_port() { # SIDE
	ip link add "v$1-br" type veth peer name "v$1"
	ip link set "v$1-br" master br-l2t
	for device in "v$1" "v$1-br"; do
		echo 1 >"/proc/sys/net/ipv6/conf/$device/disable_ipv6"
		ip link set "$device" up
	done
}

# Waits up to 60 s for PATTERN to appear in the daemon log after line FROM.
wait_log() { # FROM PATTERN
	started=$(date +%s)
	until tail -n "+$(($1 + 1))" "$log" | grep -q "$2"; do
		if [ $(($(date +%s) - started)) -ge 60 ] || ! kill -0 "$(cat "$pidfile")" 2>/dev/null; then
			tail -n 20 "$log"
			echo "timed out waiting for: $2" >&2
			exit 1
		fi
		sleep 1
	done
}

case ${1:-} in
setup)
	ip link add br-l2t type bridge
	add_port A
	add_port B
	ip link set vB address 02:00:00:00:00:0b
	ip link set br-l2t up
	ip -6 addr add fd00:abcd::1/64 dev br-l2t nodad
	echo "setup done"
	;;
start)
	shift
	from=$(wc -l <"$log" 2>/dev/null || echo 0)
	/usr/sbin/l2dns6rw -i vA-br "$@" >>"$log" 2>&1 &
	echo $! >"$pidfile"
	wait_log "$from" 'vA-br: sanitizing'
	tail -n "+$((from + 1))" "$log"
	;;
stop)
	if [ -s "$pidfile" ]; then
		kill "$(cat "$pidfile")" 2>/dev/null || true
		while kill -0 "$(cat "$pidfile")" 2>/dev/null; do sleep 1; done
		rm -f "$pidfile"
	fi
	;;
detach)
	/usr/sbin/l2dns6rw -D
	;;
send)
	tcpdump -q -U -i vB -w "$dir/$2.pcap" ip6 2>/dev/null &
	capture=$!
	sleep 1
	for frames in ra dhcp send; do
		"$dir/send-frames" vA "$dir/$frames.bin" >/dev/null
	done
	sleep 1
	kill "$capture"
	wait "$capture" 2>/dev/null || true
	;;
recreate)
	from=$(wc -l <"$log")
	ip link del vA-br
	add_port A
	wait_log "$from" 'vA-br: sanitizing'
	tail -n "+$((from + 1))" "$log"
	;;
ula)
	if [ "$2" = add ]; then
		ip -6 addr add fd00:abcd::1/64 dev br-l2t nodad
	else
		ip -6 addr del fd00:abcd::1/64 dev br-l2t
	fi
	# Lets the daemon handle the address event.
	sleep 1
	;;
idle)
	pid=$(cat "$pidfile")
	# Lets notifications from the previous steps (address changes) arrive first.
	sleep 5
	before=$(sed -n 's/^voluntary_ctxt_switches:\t*//p' "/proc/$pid/status")
	sleep "$2"
	after=$(sed -n 's/^voluntary_ctxt_switches:\t*//p' "/proc/$pid/status")
	echo "idle $2 s: voluntary context switches $before -> $after (+$((after - before)))"
	;;
teardown)
	sh "$0" stop
	/usr/sbin/l2dns6rw -D 2>/dev/null || true
	ip link del br-l2t 2>/dev/null || true
	for side in A B; do
		ip link del "v$side-br" 2>/dev/null || true
	done
	rm -f "$log"
	echo "teardown done"
	;;
*)
	sed -n '2,20p' "$0" >&2
	exit 2
	;;
esac
