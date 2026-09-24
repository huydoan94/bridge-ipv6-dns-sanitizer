#include "network.h"

#include <array>
#include <cstdio>
#include <cstring>
#include <exception>
#include <string>
#include <vector>
#include <unistd.h>

#include <tins/ipv6_address.h>
#include <tins/network_interface.h>

constexpr uint8_t IPV6_ULA_PREFIX_MASK = 0xfeU;
constexpr uint8_t IPV6_ULA_PREFIX_VALUE = 0xfcU;
constexpr size_t SYSFS_LINK_BUFSIZE = 256U;

static bool is_ula(const Tins::IPv6Address& address)
{
    return (
        address.begin()[0] & IPV6_ULA_PREFIX_MASK
    ) == IPV6_ULA_PREFIX_VALUE;
}

static bool get_bridge_master(
    const std::string& interface_name,
    std::string& master
)
{
    std::array<char, SYSFS_LINK_BUFSIZE> path;
    std::array<char, SYSFS_LINK_BUFSIZE> target;
    const char *base;
    ssize_t target_length;

    if (
        std::snprintf(
            path.data(),
            path.size(),
            "/sys/class/net/%s/master",
            interface_name.c_str()
        ) >= static_cast<int>(path.size())
    ) {
        return false;
    }

    target_length = readlink(path.data(), target.data(), target.size() - 1U);
    if (target_length < 0) {
        return false;
    }

    target[static_cast<size_t>(target_length)] = '\0';
    base = std::strrchr(target.data(), '/');
    master = base != nullptr ? base + 1 : target.data();

    return !master.empty();
}

static bool find_ula_on_interface(
    const std::string& interface_name,
    struct in6_addr *result
)
{
    const std::vector<Tins::NetworkInterface::IPv6Prefix> addresses =
        Tins::NetworkInterface(interface_name).ipv6_addresses();

    for (const Tins::NetworkInterface::IPv6Prefix& prefix : addresses) {
        if (!is_ula(prefix.address)) {
            continue;
        }

        prefix.address.copy(result->s6_addr);
        return true;
    }

    return false;
}

int resolve_local_dns(
    uint32_t indev,
    uint32_t physindev,
    struct in6_addr *dns,
    char *source_ifname,
    size_t source_ifname_len
)
{
    const std::array<uint32_t, 2> candidates = {{indev, physindev}};

    for (size_t index = 0; index < candidates.size(); ++index) {
        const uint32_t interface_index = candidates[index];

        if (interface_index == 0) {
            continue;
        }
        if (index > 0 && interface_index == candidates[0]) {
            continue;
        }

        try {
            const std::string interface_name =
                Tins::NetworkInterface::from_index(interface_index).name();
            std::string resolved_interface_name = interface_name;
            std::string master;

            if (!find_ula_on_interface(interface_name, dns)) {
                if (
                    !get_bridge_master(interface_name, master) ||
                    !find_ula_on_interface(master, dns)
                ) {
                    continue;
                }
                resolved_interface_name = master;
            }

            if (source_ifname != nullptr && source_ifname_len != 0) {
                std::snprintf(
                    source_ifname,
                    source_ifname_len,
                    "%s",
                    resolved_interface_name.c_str()
                );
            }
            return 0;
        } catch (const std::exception&) {
            continue;
        }
    }

    return -1;
}
