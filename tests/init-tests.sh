#!/bin/sh
# Tests files/l2dns6rw.init with procd, UCI and logger stubs.

set -eu

TEST_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(CDPATH= cd -- "$TEST_DIR/.." && pwd)

TEST_DEVICES=
TEST_DNS_SERVERS=
TEST_VERBOSE=0
TEST_VALID=1
PROCD_OPENED=0
PROCD_COMMAND=
PROCD_RESPAWN=
LOG_MESSAGES=
CALLS=

config_load()
{
	return 0
}

config_get()
{
	case "$3" in
		device) eval "$1=\$TEST_DEVICES" ;;
		dns_server) eval "$1=\$TEST_DNS_SERVERS" ;;
		*) eval "$1=" ;;
	esac
}

config_get_bool()
{
	eval "$1=\$TEST_VERBOSE"
}

uci_validate_section()
{
	[ "$TEST_VALID" -eq 1 ]
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
	[ "$name" = respawn ] && PROCD_RESPAWN="$*"
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

# rc.common's stop, and the daemon as detach() runs it.
stop()
{
	CALLS="$CALLS stop"
}

fake_daemon()
{
	CALLS="$CALLS daemon $*"
}

. "$PROJECT_DIR/files/l2dns6rw.init"
PROG=fake_daemon

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
	TEST_DEVICES=
	TEST_DNS_SERVERS=
	TEST_VERBOSE=0
	TEST_VALID=1
	PROCD_OPENED=0
	PROCD_COMMAND=
	PROCD_RESPAWN=
	LOG_MESSAGES=
	CALLS=
}

reset_test_state
if start_service; then
	fail "a missing device started the service"
fi
[ "$PROCD_OPENED" -eq 0 ] || fail "a missing device opened a procd instance"
expect_contains "$LOG_MESSAGES" "required option main.device is missing" \
	"a missing device did not log the required-option error"

reset_test_state
TEST_DEVICES='l2vl0 vxlan2'
TEST_DNS_SERVERS='fd00::53 2001:db8::53'
TEST_VERBOSE=1
start_service || fail "start_service returned an error"
[ "$PROCD_COMMAND" = "fake_daemon -i l2vl0 -i vxlan2 -d fd00::53 -d 2001:db8::53 -v" ] || \
	fail "devices, DNS servers and verbose were not passed to the daemon: $PROCD_COMMAND"
[ "$PROCD_RESPAWN" = "3600 5 5" ] || fail "unexpected respawn parameters: $PROCD_RESPAWN"
[ -z "$LOG_MESSAGES" ] || fail "a valid configuration logged: $LOG_MESSAGES"

reset_test_state
TEST_DEVICES='l2vl0'
start_service || fail "start_service returned an error"
[ "$PROCD_COMMAND" = "fake_daemon -i l2vl0" ] || \
	fail "automatic mode passed more than the device: $PROCD_COMMAND"

reset_test_state
TEST_DEVICES='l2vl0'
TEST_DNS_SERVERS='invalid'
TEST_VALID=0
if start_service; then
	fail "an invalid configuration started the service"
fi
[ "$PROCD_OPENED" -eq 0 ] || fail "an invalid configuration opened a procd instance"
expect_contains "$LOG_MESSAGES" "must hold IPv6 addresses" \
	"an invalid configuration did not log the validation error"

reset_test_state
detach
[ "$CALLS" = " stop daemon -D" ] || fail "detach did not stop the service, then run the daemon with -D: $CALLS"

# Every datatype the script validates with must exist in OpenWrt's libvalidate
# (ubox validate.c): with an unknown one, validate_data prints an error that
# rc.common evaluates as shell code, and start aborts with a syntax error.
LIBVALIDATE_TYPES=" or and not neg list min max range minlength maxlength rangelength integer \
uinteger float ufloat bool string hexstring ip4addr ip6addr ipaddr cidr4 cidr6 cidr netmask4 \
netmask6 ipmask4 ipmask6 ipmask port portrange macaddr uciname wpakey wepkey hostname host \
network phonedigit directory device file regex uci "
specs=$(sed -n '/uci_validate_section/,/; then/p' "$PROJECT_DIR/files/l2dns6rw.init" | grep -o "'[a-z_]*:[^']*'")
[ -n "$specs" ] || fail "no uci_validate_section datatypes found in the init script"
for type in $(printf '%s\n' "$specs" | sed "s/^'[a-z_]*://; s/'\$//" | grep -oE '[a-z][a-z0-9]*'); do
	case "$LIBVALIDATE_TYPES" in
		*" $type "*) ;;
		*) fail "datatype $type is not known to OpenWrt's validate_data" ;;
	esac
done

printf 'PASS init script: devices, DNS servers, validation, datatypes and detach\n'
