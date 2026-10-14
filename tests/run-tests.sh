#!/bin/sh
# run-tests.sh: builds and runs the host unit tests (tests/unit-tests.c) and
# the init-script tests. COVERAGE=1 adds gcov line and branch coverage;
# SANITIZERS=1 builds with AddressSanitizer and UndefinedBehaviorSanitizer.
set -eu

TEST_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
PROJECT_DIR=$(CDPATH= cd -- "$TEST_DIR/.." && pwd -P)
BUILD_DIR=${BUILD_DIR:-"$TEST_DIR/build"}
CC=${CC:-cc}
COVERAGE=${COVERAGE:-0}
SANITIZERS=${SANITIZERS:-0}

CFLAGS="-std=c11 -D_GNU_SOURCE -O0 -g -Wall -Wextra -Wpedantic -Wformat=2 -Wshadow -Wconversion -Werror"
LDFLAGS=""
if [ "$COVERAGE" -eq 1 ]; then
	CFLAGS="$CFLAGS --coverage"
	LDFLAGS="$LDFLAGS --coverage"
fi
if [ "$SANITIZERS" -eq 1 ]; then
	CFLAGS="$CFLAGS -fsanitize=address,undefined -fno-omit-frame-pointer"
	LDFLAGS="$LDFLAGS -fsanitize=address,undefined"
fi

mkdir -p "$BUILD_DIR"
# shellcheck disable=SC2086 # CFLAGS and LDFLAGS hold separate flags.
"$CC" $CFLAGS -I"$PROJECT_DIR/src" -o "$BUILD_DIR/unit-tests" \
	"$TEST_DIR/unit-tests.c" \
	"$PROJECT_DIR/src/options.c" \
	"$PROJECT_DIR/src/dns.c" \
	"$PROJECT_DIR/src/events.c" \
	$LDFLAGS
"$BUILD_DIR/unit-tests"
sh "$TEST_DIR/init-tests.sh"
