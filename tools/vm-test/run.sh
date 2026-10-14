#!/bin/sh
# run.sh: functional test of the l2dns6rw package on an OpenWrt VM, driven
# from this host.
#
# Usage: sh tools/vm-test/run.sh [HOST]   (default root@192.168.56.2)
#
# Needs bin/l2dns6rw-*-x86.apk from tools/sdk-build.sh x86 and the x86 SDK's
# toolchain for send-frames. The VM installs kmod-veth and tcpdump-mini from
# its own feeds, and the package with its library dependencies; the procd
# service is stopped and the daemon run directly on a test bridge. The VM's
# host key is kept in build/vm-known_hosts, never in ~/.ssh/known_hosts.
#
# Cases, each sending an RA, a DHCPv6 Reply and a SEND-signed RA (which must
# be dropped whenever a rewrite is needed): one and two configured servers
# (the second across a daemon restart, reusing the pinned link); the daemon
# stopped (the pinned program keeps sanitizing); automatic mode (the bridge's
# ULA); the port deleted and recreated (re-attached); automatic mode with no
# ULA (dropped) and then a ULA added (rewritten again); detached (passed
# unchanged); a 30 s idle check of the daemon's wakeups; and the verbose log.
# Raw evidence (captures, logs, results) goes to build/vm-test/.
#
# Exit status: 0 all checks passed, 1 a check failed or the run broke.
set -eu

repo=$(cd "$(dirname "$0")/../.." && pwd -P)
host=${1:-root@192.168.56.2}
out=$repo/build/vm-test
sdk=${OPENWRT_SDK_X86:-$repo/../openwrt-sdk-x86}
mkdir -p "$out"
ssh_options="-o BatchMode=yes -o ConnectTimeout=10 -o UserKnownHostsFile=$repo/build/vm-known_hosts -o StrictHostKeyChecking=accept-new"
# shellcheck disable=SC2086 # ssh_options holds separate options.
remote() { ssh $ssh_options "$host" "$@"; }
# shellcheck disable=SC2086
copy() { scp -q -O $ssh_options "$@"; }
vm() { remote "sh /tmp/l2t/vm.sh $*"; }

apk=$(ls "$repo"/bin/l2dns6rw-*-x86.apk 2>/dev/null | tail -n 1)
[ -n "$apk" ] || { echo "no bin/l2dns6rw-*-x86.apk; run: sh tools/sdk-build.sh x86" >&2; exit 1; }
gcc=$(ls "$sdk"/staging_dir/toolchain-*/bin/*-openwrt-linux-musl-gcc | head -n 1)
STAGING_DIR=$sdk/staging_dir "$gcc" -O2 -Wall -Wextra -Werror -o "$out/send-frames" "$repo/tools/vm-test/send-frames.c"
python3 "$repo/tools/vm-test/frames.py" write "$out"

echo "== VM preparation ($host)"
remote 'mkdir -p /tmp/l2t'
copy "$apk" "$host:/tmp/l2t/l2dns6rw.apk"
copy "$out/send-frames" "$out/ra.bin" "$out/dhcp.bin" "$out/send.bin" "$repo/tools/vm-test/vm.sh" "$host:/tmp/l2t/"
remote 'set -e
	[ ! -f /tmp/l2t/vm.sh ] || sh /tmp/l2t/vm.sh teardown >/dev/null 2>&1 || true
	apk update >/dev/null
	apk add kmod-veth tcpdump-mini >/dev/null
	apk del l2dns6rw >/dev/null 2>&1 || true
	apk add --allow-untrusted /tmp/l2t/l2dns6rw.apk >/dev/null
	/etc/init.d/l2dns6rw stop 2>/dev/null || true
	apk info -v l2dns6rw libbpf1 2>/dev/null | tr "\n" " "; echo
	sh /tmp/l2t/vm.sh setup'

status=0
fail() {
	echo "FAIL $*"
	status=1
}

check() { # NAME MODE DNS
	vm send "$1"
	copy "$host:/tmp/l2t/$1.pcap" "$out/$1.pcap"
	python3 "$repo/tools/vm-test/frames.py" check "$2" "$3" "$out/$1.pcap" | tee "$out/$1.result" || status=1
	grep -q '^FAIL' "$out/$1.result" && status=1 || true
}

echo "== configured, one server"
vm start -d fd00::53 -v
check configured rewrite fd00::53

echo "== restarted with two servers (the pinned link is reused)"
vm stop
vm start -d fd00::53 -d fd00::54 -v
check two-servers rewrite fd00::53,fd00::54

echo "== daemon stopped (the pinned program keeps sanitizing)"
vm stop
check stopped rewrite fd00::53,fd00::54

echo "== automatic mode (the bridge's ULA)"
vm start -v
check automatic rewrite fd00:abcd::1

echo "== port deleted and recreated"
vm recreate
check recreated rewrite fd00:abcd::1

echo "== automatic mode without a ULA, then with one"
vm stop
vm detach
vm ula del
vm start -v
check no-ula dropped -
vm ula add
check ula-added rewrite fd00:abcd::1

echo "== idle"
vm idle 30 | tee "$out/idle.txt"
grep -q '(+0)$' "$out/idle.txt" || fail "the idle daemon woke up"

echo "== verbose log"
remote 'cat /tmp/l2t/daemon.log' >"$out/daemon.log"
grep -q 'dev=vA-br type=RA from=fe80::a rewritten router-lifetime=1800->0 rdnss-options=1' "$out/daemon.log" ||
	fail "no RA rewrite line in the log"
grep -q 'dev=vA-br type=DHCPv6-Reply from=fe80::a rewritten dns-options=1' "$out/daemon.log" ||
	fail "no DHCPv6 rewrite line in the log"
grep -q 'DROP: SEND-signed or authenticated message needs a rewrite' "$out/daemon.log" ||
	fail "no SEND drop line in the log"
grep -q 'DROP: no DNS address for this device' "$out/daemon.log" || fail "no missing-DNS drop line in the log"
grep -q 'no ULA on it or its bridge' "$out/daemon.log" || fail "no missing-ULA warning in the log"
grep -E 'rewritten|DROP|ULA|sanitizing|stopping|packets' "$out/daemon.log" | head -n 12

echo "== detached (passes unchanged)"
vm stop
vm detach
check detached unchanged -

echo "== cleanup"
vm teardown
if [ "$status" -eq 0 ]; then
	echo "ALL CHECKS PASSED (evidence: build/vm-test/)"
else
	echo "SOME CHECKS FAILED (evidence: build/vm-test/)"
fi
exit "$status"
