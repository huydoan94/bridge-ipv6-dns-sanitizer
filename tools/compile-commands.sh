#!/bin/sh
# compile-commands.sh: writes compile_commands.json at the repository root for
# editors (clangd, the C/C++ extension).
#
# Usage: sh tools/compile-commands.sh [NAME|DIRECTORY]
#
# The daemon sources under src/ get the C++ flags of the package build and the
# staged headers (libtins, libnetfilter-queue) of an OpenWrt SDK: NAME or
# DIRECTORY as sdk-resolve.sh finds it, x86 by default. tests/unit-tests.cpp
# gets the host test build's flags, with the native libtins under
# tests/build/libtins-host when it exists. The output holds absolute paths for
# this machine and is not committed.
set -eu

repo=$(cd "$(dirname "$0")/.." && pwd)
. "$repo/tools/sdk-resolve.sh"
sdk_resolve "${1:-x86}"
[ -d "$sdk" ] || { echo "$0: no SDK at $sdk${variable:+; set $variable}" >&2; exit 1; }
sdk=$(cd "$sdk" && pwd)
staging=$(ls -d "$sdk"/staging_dir/target-*/usr/include | head -n 1)
[ -f "$staging/tins/tins.h" ] ||
	echo "$0: warning: $staging has no libtins headers yet; run: sh tools/sdk-build.sh --prepare-only ${1:-x86}" >&2
host_tins=$repo/tests/build/libtins-host/include
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
	for file in "$repo"/src/*.cpp; do
		entry "$file" "\"/usr/bin/g++\", \"-std=gnu++11\", $warnings, \"-DBRIDGE_IPV6_DNS_SANITIZER_VERSION=\\\"$version\\\"\", \"-I$repo/src\", \"-isystem\", \"$staging\""
	done
	entry "$repo/tests/unit-tests.cpp" "\"/usr/bin/g++\", \"-std=gnu++11\", $warnings, \"-I$repo/src\", \"-isystem\", \"$host_tins\""
	printf '\n]\n'
} >"$output.tmp"
mv "$output.tmp" "$output"
echo "wrote $output ($(grep -c '"file"' "$output") files, SDK $sdk)"
