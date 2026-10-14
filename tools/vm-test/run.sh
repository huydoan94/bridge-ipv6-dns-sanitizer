#!/bin/sh
# run.sh: functional test of l2dns6rw on an OpenWrt VM through a real bridge
# NFQUEUE, driven from this host.
#
# Usage: sh tools/vm-test/run.sh [HOST]   (default root@192.168.56.2)
#
# Needs bin/l2dns6rw-*-x86.apk from tools/sdk-build.sh x86 and the x86 SDK's
# toolchain for send-frames. The VM installs kmod-nft-queue, kmod-nft-bridge,
# kmod-veth and tcpdump-mini from its own feeds, and the package with
# its library dependencies; the procd service is stopped during the run. The
# VM's host key is kept in build/vm-known_hosts, never in ~/.ssh/known_hosts.
#
# Cases: rewrite with one and with two configured DNS servers (the packet
# grows) and with the bridge's ULA (automatic mode), each also sending a
# SEND-signed RA that must be dropped; automatic mode with no ULA, and no
# daemon at all, where everything queued must be dropped; and a 30 s idle
# check of the daemon's wakeups. Raw evidence (captures, daemon logs,
# results) goes to build/vm-test/.
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

apk=$(ls "$repo"/bin/l2dns6rw-*-x86.apk 2>/dev/null | tail -n 1)
[ -n "$apk" ] || { echo "no bin/l2dns6rw-*-x86.apk; run: sh tools/sdk-build.sh x86" >&2; exit 1; }
gcc=$(ls "$sdk"/staging_dir/toolchain-*/bin/*-openwrt-linux-musl-gcc | head -n 1)
STAGING_DIR=$sdk/staging_dir "$gcc" -O2 -Wall -Wextra -Werror -o "$out/send-frames" "$repo/tools/vm-test/send-frames.c"
python3 "$repo/tools/vm-test/frames.py" write "$out"

echo "== VM preparation ($host)"
# Keep the first record of the VM's packages, so a rerun still reports everything this test added.
remote 'mkdir -p /tmp/l2t && { [ -s /tmp/l2t/packages-before.txt ] || apk info >/tmp/l2t/packages-before.txt; }'
copy "$apk" "$host:/tmp/l2t/l2dns6rw.apk"
copy "$out/send-frames" "$out/ra.bin" "$out/dhcp.bin" "$out/send.bin" "$repo/tools/vm-test/vm.sh" "$host:/tmp/l2t/"
remote 'set -e
	apk update >/dev/null
	apk add kmod-nft-queue kmod-nft-bridge kmod-veth tcpdump-mini >/dev/null
	apk add --allow-untrusted /tmp/l2t/l2dns6rw.apk >/dev/null
	/etc/init.d/l2dns6rw stop 2>/dev/null || true
	apk info | grep -vxF -f /tmp/l2t/packages-before.txt >/tmp/l2t/packages-added.txt || true
	echo "added: $(tr "\n" " " </tmp/l2t/packages-added.txt)"
	apk info -v l2dns6rw libtins libnetfilter-queue1 2>/dev/null | tr "\n" " "; echo
	sh /tmp/l2t/vm.sh teardown >/dev/null
	sh /tmp/l2t/vm.sh setup'

status=0
run_case() { # NAME MODE DNS ARG...
	name=$1 mode=$2 dns=$3
	shift 3
	echo "== case $name"
	remote "sh /tmp/l2t/vm.sh case $name $*" | tee "$out/$name.vm.txt"
	copy "$host:/tmp/l2t/$name.pcap" "$out/$name.pcap"
	python3 "$repo/tools/vm-test/frames.py" check "$mode" "$dns" "$out/$name.pcap" | tee "$out/$name.result" ||
		status=1
	grep -q '^FAIL' "$out/$name.result" && status=1 || true
}

run_case configured rewrite fd00::53 -d fd00::53
run_case two-servers rewrite fd00::53,fd00::54 -d fd00::53 -d fd00::54
run_case automatic rewrite fd00:abcd::1 auto
run_case automatic-no-ula dropped - auto-no-ula
run_case no-listener dropped - none

echo "== idle"
remote 'sh /tmp/l2t/vm.sh idle 30 -d fd00::53' | tee "$out/idle.txt"
grep -q '(+0)$' "$out/idle.txt" || { echo "FAIL the idle daemon woke up"; status=1; }

echo "== cleanup"
remote 'sh /tmp/l2t/vm.sh teardown'
if [ "$status" -eq 0 ]; then
	echo "ALL CHECKS PASSED (evidence: build/vm-test/)"
else
	echo "SOME CHECKS FAILED (evidence: build/vm-test/)"
fi
exit "$status"
