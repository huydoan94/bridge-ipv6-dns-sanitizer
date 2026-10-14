#!/bin/sh
# host-test.sh: runs the host unit and init-script tests (tests/run-tests.sh),
# then says whether they passed and why not.
#
# Usage: sh tools/host-test.sh
#
# The tests build against the host's libnetfilter-queue headers and a native
# libtins (built once under tests/build when the host has none). The output
# goes to build/host-test.log; the terminal shows it only when the tests fail
# (its last 30 lines) or with VERBOSE=1 (all of it). Extra environment, such as
# SANITIZERS=1 or COVERAGE=1, passes through to tests/run-tests.sh.
#
# Exit status: 0 all passed, 4 compile error, 5 a test failed, 1 any other failure.
set -u

repo=$(cd "$(dirname "$0")/.." && pwd -P)
mkdir -p "$repo/build"
log=$repo/build/host-test.log

echo "Running host tests (log: build/host-test.log)"
if [ "${VERBOSE:-}" = 1 ]; then
	{
		sh "$repo/tests/run-tests.sh" 2>&1
		echo $? >"$log.status"
	} | tee "$log"
	status=$(cat "$log.status")
	rm -f "$log.status"
else
	sh "$repo/tests/run-tests.sh" >"$log" 2>&1
	status=$?
fi

summary=$(grep -E '^[0-9]+ tests, [0-9]+ assertions, [0-9]+ failures$' "$log" | tail -n 1)
if [ "$status" -eq 0 ]; then
	echo "PASSED: ${summary:-host tests}; $(grep -c '^PASS required UCI' "$log") init-script suite"
	exit 0
fi

[ "${VERBOSE:-}" = 1 ] || {
	printf '\nLast 30 lines of %s:\n' "$log" >&2
	tail -n 30 "$log" >&2
}
if grep -q -E '(error|Error):' "$log" && [ -z "$summary" ]; then
	printf '\nCANNOT TEST: compile errors:\n' >&2
	grep -E '(error|Error):' "$log" | head -n 20 >&2
	exit 4
fi
failures=$(grep -E '^FAIL ' "$log" | head -n 20)
if [ -n "$failures" ]; then
	printf '\nTESTS FAILED: %s\n%s\n' "${summary:-see the log}" "$failures" >&2
	exit 5
fi
printf '\nTESTS FAILED: tests/run-tests.sh exited with status %s\n' "$status" >&2
exit 1
