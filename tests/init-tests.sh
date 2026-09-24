#!/bin/sh

set -eu

TEST_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(CDPATH= cd -- "$TEST_DIR/.." && pwd)

NFT=nft
TEST_QUEUE_NUMBER=
TEST_VERBOSE=0
TEST_RULESET=
TEST_NFT_STATUS=0
PROCD_OPENED=0
PROCD_COMMAND=
LOG_MESSAGES=

config_load()
{
	return 0
}

config_get()
{
	eval "$1=\$TEST_QUEUE_NUMBER"
}

config_get_bool()
{
	eval "$1=\$TEST_VERBOSE"
}

nft()
{
	printf '%s\n' "$TEST_RULESET"
	return "$TEST_NFT_STATUS"
}

logger()
{
	LOG_MESSAGES="$LOG_MESSAGES $*"
}

procd_open_instance()
{
	PROCD_OPENED=1
}

procd_set_param()
{
	local name="$1"
	shift
	[ "$name" = command ] && PROCD_COMMAND="$*"
	return 0
}

procd_append_param()
{
	local name="$1"
	shift
	[ "$name" = command ] && PROCD_COMMAND="$PROCD_COMMAND $*"
	return 0
}

procd_close_instance()
{
	return 0
}

procd_add_reload_trigger()
{
	return 0
}

. "$PROJECT_DIR/files/bridge-ipv6-dns-sanitizer.init"

fail()
{
	printf 'FAIL %s\n' "$1" >&2
	exit 1
}

expect_contains()
{
	case "$1" in
		*"$2"*) ;;
		*) fail "$3" ;;
	esac
}

reset_test_state()
{
	TEST_QUEUE_NUMBER=
	TEST_VERBOSE=0
	TEST_RULESET=
	TEST_NFT_STATUS=0
	PROCD_OPENED=0
	PROCD_COMMAND=
	LOG_MESSAGES=
	NFT_ARGUMENTS=
}

expect_invalid_queue()
{
	reset_test_state
	TEST_QUEUE_NUMBER="$1"
	if start_service; then
		fail "queue '$1' unexpectedly started the service"
	fi
	[ "$PROCD_OPENED" -eq 0 ] || fail "invalid queue opened a procd instance"
	expect_contains "$LOG_MESSAGES" "required option main.queue_number" \
		"invalid queue did not log the required-option error"
}

expect_invalid_queue ""
expect_invalid_queue "-1"
expect_invalid_queue "abc"
expect_invalid_queue "1x"
expect_invalid_queue "65536"
expect_invalid_queue "999999999999999999999999"

reset_test_state
TEST_QUEUE_NUMBER=321
TEST_VERBOSE=1
TEST_RULESET='table bridge test {
	chain input {
		queue num 321; bypass
	}
}'
start_service
[ "$PROCD_COMMAND" = "$PROG -q 321 -v" ] || fail "configured queue was not passed to the daemon"
[ -z "$LOG_MESSAGES" ] || fail "matching nftables rule produced a warning"

reset_test_state
TEST_QUEUE_NUMBER=321
TEST_RULESET='table bridge test {
	chain input {
		queue num 320-322 fanout,bypass
	}
}'
start_service
[ -z "$LOG_MESSAGES" ] || fail "matching nftables queue range produced a warning"

reset_test_state
TEST_QUEUE_NUMBER=321
TEST_RULESET='table bridge test {
	chain input {
		queue num 100 bypass
	}
}'
start_service
[ "$PROCD_OPENED" -eq 1 ] || fail "missing nftables rule prevented startup"
expect_contains "$LOG_MESSAGES" "no nftables rule queues packets to NFQUEUE 321; continuing" \
	"missing nftables rule did not produce the expected warning"

reset_test_state
TEST_QUEUE_NUMBER=321
TEST_NFT_STATUS=1
start_service
[ "$PROCD_OPENED" -eq 1 ] || fail "nftables inspection failure prevented startup"
expect_contains "$LOG_MESSAGES" "could not inspect nftables rules for NFQUEUE 321; continuing" \
	"nftables inspection failure did not produce the expected warning"

printf 'PASS required UCI queue and nftables checks\n'
