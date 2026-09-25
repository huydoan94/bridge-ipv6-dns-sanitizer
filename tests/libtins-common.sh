#!/bin/sh

libtins_has_required_api()
{
	[ -f "$1/include/tins/constants.h" ] &&
		grep -q "struct fragment_header" "$1/include/tins/ipv6.h" 2>/dev/null &&
		grep -q "class invalid_ipv6_extension_header" "$1/include/tins/exceptions.h" 2>/dev/null
}
