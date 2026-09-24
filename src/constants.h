#ifndef BRIDGE_IPV6_DNS_CONSTANTS_H
#define BRIDGE_IPV6_DNS_CONSTANTS_H

#include <net/if.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>

#include <linux/if_ether.h>

#ifndef BRIDGE_IPV6_DNS_SANITIZER_VERSION
#define BRIDGE_IPV6_DNS_SANITIZER_VERSION "unknown"
#endif

constexpr char PROGRAM_VERSION[] = BRIDGE_IPV6_DNS_SANITIZER_VERSION;

constexpr uint16_t QUEUE_NUM = 100U;
constexpr uint32_t QUEUE_MAXLEN = 1024U;
constexpr uint32_t COPY_RANGE = UINT16_MAX;
constexpr int POLL_TIMEOUT_MS = 1000;
constexpr size_t NFQ_NETLINK_HEADROOM = 4096U;
constexpr size_t NFQ_RECV_BUFSIZE = COPY_RANGE + NFQ_NETLINK_HEADROOM;

constexpr uint16_t RA_NEUTRAL_ROUTER_LIFETIME = 0U;
constexpr uint8_t ND_OPTION_PVD = 21U;
constexpr uint16_t CHECKSUM_INVALID_XOR = 0x0001U;
constexpr size_t DHCPV6_TRANSACTION_ID_LEN = 3U;
constexpr size_t NDP_OPTION_LEN_UNIT_OCTETS = 8U;

constexpr size_t ADDR_LIST_BUFSIZE = 512U;
constexpr size_t MAC_TEXT_BUFSIZE = ETH_ALEN * 3U;
constexpr size_t CLIENT_ID_BUFSIZE = 384U;
constexpr size_t DETAIL_BUFSIZE = 1536U;
constexpr size_t ERROR_BUFSIZE = 256U;
constexpr size_t ENDPOINT_BUFSIZE = 256U;
constexpr size_t LOCAL_DNS_TEXT_BUFSIZE = INET6_ADDRSTRLEN + IF_NAMESIZE + 3U;

#endif
