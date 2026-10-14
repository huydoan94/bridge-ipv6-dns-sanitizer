#!/bin/sh
# run.sh: runs the BPF program's packet tests (tests/bpf/cases.py) in a kernel
# with BPF_PROG_TEST_RUN, which needs root.
#
# Usage: sh tests/bpf/run.sh            build natively and run with sudo (CI)
#        sh tests/bpf/run.sh HOST       run on an OpenWrt VM, for example
#                                       root@192.168.56.2, with the object
#                                       built by the x86 SDK's BPF compiler
#
# On a VM the runner is built with the x86 SDK's toolchain and needs libbpf1
# there (the l2dns6rw package depends on it). Output goes to build/bpf-tests/.
set -eu

repo=$(cd "$(dirname "$0")/../.." && pwd -P)
out=$repo/build/bpf-tests
mkdir -p "$out"
python3 "$repo/tests/bpf/cases.py" write "$out/cases.txt"

if [ "$#" -eq 0 ]; then
	triplet=$(cc -dumpmachine)
	make -s -C "$repo/src" OBJECT_DIR="$out/src" BPF_INCLUDES="-I/usr/include/$triplet" "$out/src/l2dns6rw.bpf.o"
	cc -std=c11 -D_GNU_SOURCE -O2 -Wall -Wextra -Werror -I"$repo/src" \
		-o "$out/runner" "$repo/tests/bpf/runner.c" -lbpf
	sudo -n "$out/runner" "$out/src/l2dns6rw.bpf.o" "$out/cases.txt" >"$out/results.txt"
else
	host=$1
	sdk=${OPENWRT_SDK_X86:-$repo/../openwrt-sdk-x86}
	ssh_options="-o BatchMode=yes -o ConnectTimeout=10 -o UserKnownHostsFile=$repo/build/vm-known_hosts -o StrictHostKeyChecking=accept-new"
	staging=$(ls -d "$sdk"/staging_dir/target-*)
	toolchain=$(ls -d "$sdk"/staging_dir/toolchain-*)
	# The same compile as the package: the SDK's BPF clang and headers.
	object=$out/x86/l2dns6rw.bpf.o
	make -s -C "$repo/src" OBJECT_DIR="$out/x86" BPF_CLANG="$sdk/staging_dir/host/llvm-bpf/bin/clang" \
		BPF_STRIP="$sdk/staging_dir/host/llvm-bpf/bin/llvm-strip" \
		BPF_INCLUDES="-I$staging/usr/include -I$toolchain/include" "$object"
	gcc=$(ls "$sdk"/staging_dir/toolchain-*/bin/*-openwrt-linux-musl-gcc | head -n 1)
	STAGING_DIR=$sdk/staging_dir "$gcc" -std=c11 -D_GNU_SOURCE -O2 -Wall -Wextra -Werror -I"$repo/src" \
		-isystem "$staging/usr/include" -o "$out/runner" "$repo/tests/bpf/runner.c" \
		-L"$staging/usr/lib" -Wl,-rpath-link,"$staging/usr/lib" -lbpf
	# shellcheck disable=SC2086 # ssh_options holds separate options.
	ssh $ssh_options "$host" 'mkdir -p /tmp/l2b-tests'
	# shellcheck disable=SC2086
	scp -q -O $ssh_options "$out/runner" "$object" "$out/cases.txt" "$host:/tmp/l2b-tests/"
	# shellcheck disable=SC2086
	ssh $ssh_options "$host" 'cd /tmp/l2b-tests && ./runner l2dns6rw.bpf.o cases.txt' >"$out/results.txt"
fi
python3 "$repo/tests/bpf/cases.py" check "$out/results.txt"
