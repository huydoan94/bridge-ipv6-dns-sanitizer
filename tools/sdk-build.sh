#!/bin/sh
# sdk-build.sh: cleans and compiles the l2dns6rw package in an OpenWrt SDK,
# then says why the build failed, if it did. It stages the package's build
# dependencies first and never recurses into other packages or the kernel.
#
# Usage: sh tools/sdk-build.sh [--prepare-only] NAME|DIRECTORY
#
# NAME is an SDK as sdk-resolve.sh finds it: x86 is $OPENWRT_SDK_X86 or
# ../openwrt-sdk-x86, filogic is $OPENWRT_SDK_FILOGIC or ../openwrt-sdk-filogic;
# an argument with a slash is the SDK directory. The SDK's package/l2dns6rw
# must be a link to this repository.
#
# Build dependencies (libmnl, libnfnetlink, libnetfilter-queue, libtins) are
# staged with NO_DEPS=1 when their headers or libraries are missing; a recipe
# that is only in a local feed is registered with scripts/feeds first. libtins
# is staged without PCAP support, which the daemon does not use. Compilation may
# download sources missing from the SDK's dl/ cache. --prepare-only stages the
# dependencies without building the package.
#
# The output of make goes only to build/sdk-<name>.log; the terminal shows this
# script's own messages and, when a build fails, the errors found in the log
# and its last 30 lines. VERBOSE=1 also shows the full make output. The built
# package is copied to bin/ with -<name> before its extension, for example
# bin/l2dns6rw-1.6.10-r1-x86.apk, and the copy's checksum is verified.
#
# Exit status: 0 built, 2 SDK missing or not set up, 3 libraries or headers
# missing, 4 compile error, 1 any other failure.
set -u

repo=$(cd "$(dirname "$0")/.." && pwd -P)
package=l2dns6rw
prepare_only=
sdk_argument=
usage() {
	echo "usage: $0 [--prepare-only] NAME|DIRECTORY   (for example x86 or filogic)" >&2
	exit 1
}
for argument in "$@"; do
	case $argument in
	--prepare-only) [ -z "$prepare_only" ] || usage; prepare_only=1 ;;
	-*|*=*) usage ;;
	*) [ -z "$sdk_argument" ] && [ -n "$argument" ] || usage; sdk_argument=$argument ;;
	esac
done
[ -n "$sdk_argument" ] || usage
. "$repo/tools/sdk-resolve.sh"
sdk_resolve "$sdk_argument"

fail() { # STATUS MESSAGE...
	status=$1
	shift
	printf '\nCANNOT BUILD (%s): ' "$name" >&2
	printf '%s\n' "$@" >&2
	exit "$status"
}

quiet() {
	[ "${VERBOSE:-}" != 1 ]
}

# Fails like fail, first showing the end of the log when make output was hidden.
fail_log() { # STATUS MESSAGE...
	if quiet; then
		printf '\nLast 30 lines of %s:\n' "$log" >&2
		tail -n 30 "$log" >&2
	fi
	fail "$@"
}

# Runs make with its output appended to the log, and also shown with VERBOSE=1;
# make's own exit status is kept when the output goes through tee.
sdk_make() { # MAKE-ARGUMENTS...
	if quiet; then
		make "$@" >>"$log" 2>&1
		return
	fi
	{
		make "$@" 2>&1
		echo $? >"$log.status"
	} | tee -a "$log"
	make_status=$(cat "$log.status")
	rm -f "$log.status"
	return "$make_status"
}

# DEPENDENCY|FEED|LOCAL-PATH|EXTRA-MAKE-ARGUMENTS|ARTIFACTS, in build order.
dependencies() {
	cat <<'DEPENDENCIES'
libmnl|base|libs/libmnl||usr/include/libmnl/libmnl.h usr/lib/libmnl.so
libnfnetlink|base|libs/libnfnetlink||usr/include/libnfnetlink/libnfnetlink.h usr/lib/libnfnetlink.so
libnetfilter-queue|packages|libs/libnetfilter-queue||usr/include/libnetfilter_queue/libnetfilter_queue.h usr/lib/libnetfilter_queue.so
libtins|packages|libs/libtins|CONFIG_LIBTINS_ENABLE_PCAP=|usr/include/tins/tins.h usr/lib/libtins.so
DEPENDENCIES
}

elf_signature() { # PATH: class, byte order and machine of an ELF file.
	LC_ALL=C readelf -h "$1" 2>/dev/null | sed -n '/Class:/p; /Data:/p; /Machine:/p'
}

dependency_ready() { # ARTIFACTS
	for artifact in $1; do
		[ -f "$staging/$artifact" ] || return 1
		case $artifact in
		*.so) [ "$(elf_signature "$staging/$artifact")" = "$target_elf" ] || return 1 ;;
		esac
	done
}

prepare_dependencies() {
	set -- "$sdk"/staging_dir/target-*
	[ "$#" -eq 1 ] && [ -d "$1" ] || fail 2 "expected one target staging directory in $sdk"
	staging=$1
	set -- "$sdk"/staging_dir/toolchain-*/lib/libgcc_s.so.1
	[ "$#" -eq 1 ] && [ -f "$1" ] || fail 2 "expected one staged toolchain with libgcc_s.so.1 in $sdk"
	target_elf=$(elf_signature "$1")
	[ -n "$target_elf" ] || fail 2 "cannot read the target ELF type from $1"
	dependencies | while IFS='|' read -r dependency feed local_path extra artifacts; do
		if dependency_ready "$artifacts"; then
			echo "$dependency: ready"
			continue
		fi
		target=package/feeds/$feed/$dependency
		if [ ! -f "$sdk/$target/Makefile" ]; then
			[ -f "$sdk/feeds/$feed/$local_path/Makefile" ] ||
				fail 3 "the local $feed feed lacks $dependency ($local_path); update that feed first"
			echo "$dependency: registering from the local $feed feed"
			(cd "$sdk" && ./scripts/feeds install -p "$feed" "$dependency") >>"$log" 2>&1 ||
				fail_log 3 "could not register $dependency from the local $feed feed"
		fi
		echo "$dependency: staging ($target)"
		# shellcheck disable=SC2086 # extra holds make assignments without spaces.
		set -- NO_DEPS=1 CONFIG_ALL= CONFIG_ALL_NONSHARED= "CONFIG_PACKAGE_$dependency=m" $extra
		sdk_make -C "$sdk" "$target/clean" "$@" && sdk_make -C "$sdk" "$target/compile" "$@" ||
			fail_log 3 "could not stage $dependency"
		dependency_ready "$artifacts" ||
			fail_log 3 "staging $dependency did not produce: $artifacts"
	done || exit
}

# The newest package file in the SDK's bin/, which is the one just built.
newest_package() {
	find "$sdk/bin/packages" \( -name "$package-[0-9]*.apk" -o -name "${package}_[0-9]*.ipk" \) \
		-printf '%T@ %p\n' | sort -rn | head -n 1 | cut -d' ' -f2-
}

[ -f "$sdk/rules.mk" ] && [ -d "$sdk/staging_dir" ] ||
	fail 2 "no OpenWrt SDK at $sdk" "Unpack the SDK there${variable:+, or set $variable to its directory}."
sdk=$(cd "$sdk" && pwd)
link=$(readlink -f "$sdk/package/$package" 2>/dev/null)
[ "$link" = "$repo" ] ||
	fail 2 "$sdk/package/$package does not point to this repository (it is: ${link:-missing})" \
		"Fix it with: ln -sfn $repo $sdk/package/$package"
command -v readelf >/dev/null || fail 2 "readelf is needed to check staged libraries"

mkdir -p "$repo/build"
log=$repo/build/sdk-$name.log
: >"$log"
echo "Preparing $package dependencies in $sdk (log: build/sdk-$name.log)"
prepare_dependencies
if [ -n "$prepare_only" ]; then
	echo "READY ($name): all build dependencies staged"
	exit 0
fi

echo "Building $package in $sdk"
selection="NO_DEPS=1 CONFIG_PACKAGE_$package=m"
# shellcheck disable=SC2086 # selection holds make assignments without spaces.
sdk_make -C "$sdk" "package/$package/clean" $selection &&
	sdk_make -C "$sdk" "package/$package/compile" $selection
status=$?

if [ "$status" -eq 0 ]; then
	built=$(newest_package)
	[ -n "$built" ] || fail 1 "make succeeded but no $package package is in $sdk/bin/packages"
	# The SDK name goes before the extension: x86 and Filogic packages share a file name.
	file=$(basename "$built")
	copy=$repo/bin/${file%.*}-$name.${file##*.}
	mkdir -p "$repo/bin"
	cp "$built" "$copy"
	[ "$(sha256sum <"$built")" = "$(sha256sum <"$copy")" ] || fail 1 "the copy $copy does not match $built"
	echo
	echo "BUILT ($name, $package):"
	sha256sum "$built"
	echo "copied to bin/$(basename "$copy") (checksum verified)"
	exit 0
fi

libraries=$(grep -A3 "Package $package is missing dependencies" "$log" | grep -v "Package $package" | tr -s ' \n' ' ')
[ -z "$libraries" ] ||
	fail_log 3 "the package is missing libraries: $libraries" "Run: sh tools/sdk-build.sh --prepare-only $sdk_argument"
headers=$(sed -n 's/.*fatal error: \([^:]*\): No such file or directory.*/\1/p' "$log" | sort -u | tr '\n' ' ')
[ -z "$headers" ] ||
	fail_log 3 "headers not found: $headers" "A staged dependency disappeared; rerun this script to stage it again."
errors=$(grep -E '(error|Error):' "$log" | grep -v -E '^make(\[[0-9]+\])?: \*\*\*|^ERROR: package/' | head -n 20)
[ -z "$errors" ] || fail_log 4 "compile errors:" "$errors"
fail_log 1 "make exited with status $status, and the log shows no compiler error" \
	"See the compiler output with: make -C $sdk package/$package/compile $selection V=s"
