#!/bin/sh
# compile-commands.sh: writes compile_commands.json at the repository root for
# editors (clangd, the C/C++ extension).
#
# Usage: sh tools/compile-commands.sh [NAME|DIRECTORY]
#
# The daemon sources under src/ get the package build's C flags and the staged
# libbpf headers of an OpenWrt SDK: NAME or DIRECTORY as sdk-resolve.sh finds
# it, x86 by default. src/l2dns6rw.bpf.c gets the SDK's BPF clang with the
# staged and toolchain headers; tests/unit-tests.c and tests/bpf/runner.c the
# host test flags. The output holds absolute paths for this machine and is
# not committed.
set -eu

repo=$(cd "$(dirname "$0")/.." && pwd -P)
. "$repo/tools/sdk-resolve.sh"
sdk_resolve "${1:-x86}"
[ -d "$sdk" ] || { echo "$0: no SDK at $sdk${variable:+; set $variable}" >&2; exit 1; }
sdk=$(cd "$sdk" && pwd)
staging=$(ls -d "$sdk"/staging_dir/target-*/usr/include | head -n 1)
toolchain=$(ls -d "$sdk"/staging_dir/toolchain-*/include | head -n 1)
bpf_clang=$sdk/staging_dir/host/llvm-bpf/bin/clang
[ -f "$staging/bpf/libbpf.h" ] ||
	echo "$0: warning: $staging has no libbpf headers yet; run: sh tools/sdk-build.sh --prepare-only ${1:-x86}" >&2
warnings='"-Wall", "-Wextra", "-Wpedantic", "-Wformat=2", "-Wshadow", "-Wconversion"'
version=$(sed -n 's/^PKG_VERSION:=//p' "$repo/Makefile")

entry() { # FILE ARGUMENTS
	printf '%s\n  {\n    "directory": "%s",\n    "file": "%s",\n    "arguments": [%s, "-c", "%s"]\n  }' \
		"$separator" "$(dirname "$1")" "$1" "$2" "$1"
	separator=,
}

output=$repo/compile_commands.json
separator=
{
	printf '['
	for file in "$repo"/src/*.c; do
		case $file in
		*.bpf.c)
			entry "$file" "\"$bpf_clang\", \"-O2\", \"-g\", \"-target\", \"bpfel\", \"-Wall\", \"-Wextra\", \"-I$repo/src\", \"-I$staging\", \"-I$toolchain\""
			;;
		*)
			entry "$file" "\"/usr/bin/gcc\", \"-std=c11\", \"-D_GNU_SOURCE\", $warnings, \"-DPROGRAM_VERSION=\\\"$version\\\"\", \"-I$repo/src\", \"-isystem\", \"$staging\""
			;;
		esac
	done
	entry "$repo/tests/unit-tests.c" "\"/usr/bin/gcc\", \"-std=c11\", \"-D_GNU_SOURCE\", $warnings, \"-I$repo/src\""
	entry "$repo/tests/bpf/runner.c" "\"/usr/bin/gcc\", \"-std=c11\", \"-D_GNU_SOURCE\", $warnings, \"-I$repo/src\", \"-isystem\", \"$staging\""
	printf '\n]\n'
} >"$output.tmp"
mv "$output.tmp" "$output"
echo "wrote $output ($(grep -c '"file"' "$output") files, SDK $sdk)"
