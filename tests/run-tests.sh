#!/bin/sh

set -eu

TEST_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(CDPATH= cd -- "$TEST_DIR/.." && pwd)
BUILD_DIR=${BUILD_DIR:-"$TEST_DIR/build"}
CXX=${CXX:-g++}
LOCAL_LIBTINS_PREFIX=${HOST_LIBTINS_PREFIX:-"$TEST_DIR/build/libtins-host"}
NFQUEUE_INCLUDE_DIR=${NFQUEUE_INCLUDE_DIR:-/usr/include}
NFNETLINK_INCLUDE_DIR=${NFNETLINK_INCLUDE_DIR:-$NFQUEUE_INCLUDE_DIR}
COVERAGE=${COVERAGE:-0}
SANITIZERS=${SANITIZERS:-0}
PROGRAM_VERSION=$(sed -n 's/^PKG_VERSION:=//p' "$PROJECT_DIR/Makefile")

if [ -z "$PROGRAM_VERSION" ]; then
	echo "PKG_VERSION not found in $PROJECT_DIR/Makefile" >&2
	exit 1
fi

VERSION_CPPFLAG="-DBRIDGE_IPV6_DNS_SANITIZER_VERSION=\"$PROGRAM_VERSION\""

. "$TEST_DIR/libtins-common.sh"

if [ -z "${LIBTINS_PREFIX+x}" ]; then
	if libtins_has_required_api "$LOCAL_LIBTINS_PREFIX"; then
		LIBTINS_PREFIX=$LOCAL_LIBTINS_PREFIX
	elif libtins_has_required_api /usr; then
		LIBTINS_PREFIX=/usr
	else
		echo "A compatible native libtins was not found; building it now..." >&2
		sh "$TEST_DIR/build-host-libtins.sh"
		LIBTINS_PREFIX=$LOCAL_LIBTINS_PREFIX
	fi
fi

if ! libtins_has_required_api "$LIBTINS_PREFIX"; then
	echo "Compatible libtins development headers not found under $LIBTINS_PREFIX/include" >&2
	echo "Unset LIBTINS_PREFIX to let the runner build a matching native copy automatically." >&2
	exit 1
fi

if [ ! -f "$NFQUEUE_INCLUDE_DIR/libnetfilter_queue/libnetfilter_queue.h" ]; then
	echo "libnetfilter_queue development headers not found under $NFQUEUE_INCLUDE_DIR" >&2
	echo "Ubuntu/Debian: sudo apt install libnetfilter-queue-dev" >&2
	exit 1
fi

if [ ! -f "$NFNETLINK_INCLUDE_DIR/libnfnetlink/libnfnetlink.h" ]; then
	echo "libnfnetlink development headers not found under $NFNETLINK_INCLUDE_DIR" >&2
	echo "Ubuntu/Debian: sudo apt install libnfnetlink-dev" >&2
	exit 1
fi

mkdir -p "$BUILD_DIR"
rm -f "$BUILD_DIR/unit-tests-unit-tests.gcda" \
	"$BUILD_DIR/unit-tests-unit-tests.gcno"

set --

if [ "$LIBTINS_PREFIX/include" != "/usr/include" ]; then
	set -- "$@" -isystem "$LIBTINS_PREFIX/include"
fi

if [ "$NFQUEUE_INCLUDE_DIR" != "/usr/include" ]; then
	set -- "$@" -isystem "$NFQUEUE_INCLUDE_DIR"
fi

if [ "$NFNETLINK_INCLUDE_DIR" != "/usr/include" ] &&
	[ "$NFNETLINK_INCLUDE_DIR" != "$NFQUEUE_INCLUDE_DIR" ]; then
	set -- "$@" -isystem "$NFNETLINK_INCLUDE_DIR"
fi

CXXFLAGS="-std=gnu++11 -O0 -g -Wall -Wextra -Wpedantic -Wformat=2 -Wshadow -Wconversion -Werror"
LDFLAGS=""

if [ "$COVERAGE" -eq 1 ]; then
	CXXFLAGS="$CXXFLAGS --coverage"
	LDFLAGS="$LDFLAGS --coverage"
fi

if [ "$SANITIZERS" -eq 1 ]; then
	CXXFLAGS="$CXXFLAGS -fsanitize=address,undefined -fno-omit-frame-pointer"
	LDFLAGS="$LDFLAGS -fsanitize=address,undefined"
fi

"$CXX" \
	$CXXFLAGS \
	"$VERSION_CPPFLAG" \
	-I"$PROJECT_DIR/src" \
	"$@" \
	-o "$BUILD_DIR/unit-tests" \
	"$TEST_DIR/unit-tests.cpp" \
	$LDFLAGS \
	-L"$LIBTINS_PREFIX/lib" \
	-ltins

"$BUILD_DIR/unit-tests"
sh "$TEST_DIR/init-tests.sh"

if [ "$COVERAGE" -eq 1 ]; then
	(
		cd "$BUILD_DIR"
		gcov --branch-counts --branch-probabilities \
			unit-tests-unit-tests.gcno
	)
fi
