#include "network.h"
#include "logging.h"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netpacket/packet.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <system_error>

static bool get_bridge_master(const std::string& interface_name, std::string& master)
{
    const std::string path = SYSFS_NETWORK_DIRECTORY + interface_name + SYSFS_BRIDGE_MASTER_LINK;
    char target[SYSFS_LINK_BUFSIZE];
    const ssize_t length = readlink(path.c_str(), target, sizeof(target) - 1U);
    if (length <= 0 || static_cast<size_t>(length) == sizeof(target) - 1U)
        return false;
    target[length] = '\0';
    const char *base = std::strrchr(target, '/');
    master = base == nullptr ? target : base + 1;
    return !master.empty();
}

struct interface_dns {
    uint32_t index = 0;
    std::vector<in6_addr> servers;
};

// One OS snapshot replaces the old repeated interface/address enumeration.
static std::map<uint32_t, local_dns_source> discover_local_dns(
    const std::map<uint32_t, local_dns_source>& previous
)
{
    ifaddrs *raw = nullptr;
    if (getifaddrs(&raw) < 0)
        throw std::system_error(errno, std::generic_category(), "getifaddrs");
    const std::unique_ptr<ifaddrs, decltype(&freeifaddrs)> addresses(raw, freeifaddrs);
    std::map<std::string, interface_dns> interfaces;
    for (const ifaddrs *item = addresses.get(); item != nullptr; item = item->ifa_next) {
        if (item->ifa_addr == nullptr)
            continue;
        auto& interface = interfaces[item->ifa_name];
        if (item->ifa_addr->sa_family == AF_PACKET) {
            const auto *link = reinterpret_cast<const sockaddr_ll *>(item->ifa_addr);
            interface.index = static_cast<uint32_t>(link->sll_ifindex);
        } else if (item->ifa_addr->sa_family == AF_INET6 && interface.servers.empty()) {
            const auto *ipv6 = reinterpret_cast<const sockaddr_in6 *>(item->ifa_addr);
            if ((ipv6->sin6_addr.s6_addr[0] & IPV6_ULA_PREFIX_MASK) == IPV6_ULA_PREFIX_VALUE)
                interface.servers.push_back(ipv6->sin6_addr);
        }
    }

    std::map<uint32_t, local_dns_source> result;
    for (const auto& item : interfaces) {
        if (item.second.index == 0)
            continue;
        const auto *source = &item;
        if (source->second.servers.empty()) {
            std::string master;
            const auto bridge = get_bridge_master(item.first, master) ?
                interfaces.find(master) : interfaces.end();
            if (bridge == interfaces.end() || bridge->second.servers.empty()) {
                const auto cached = previous.find(item.second.index);
                // An interface index may be reused by a different interface.
                if (cached != previous.end() && cached->second.interface_name == item.first)
                    result.emplace(item.second.index, cached->second);
                continue;
            }
            source = &*bridge;
        }
        char description[LOCAL_DNS_TEXT_BUFSIZE];
        format_local_dns_log(&source->second.servers.front(), source->first.c_str(),
                             description, sizeof(description));
        result.emplace(item.second.index, local_dns_source{
            source->second.servers, description, item.first
        });
    }
    return result;
}

local_dns_cache::~local_dns_cache()
{
    close_file();
}

void local_dns_cache::close_file()
{
    if (file_ != nullptr) {
        fclose(file_);
        file_ = nullptr;
        unlink(path_);
        path_[0] = '\0';
    }
}

void local_dns_cache::save(const std::string& snapshot)
{
    if (file_ != nullptr && snapshot == saved_snapshot_)
        return;

    if (file_ == nullptr) {
        std::strcpy(path_, DNS_CACHE_TEMPLATE);
        const int fd = mkstemp(path_);
        if (fd < 0) {
            path_[0] = '\0';
            throw std::system_error(errno, std::generic_category(), "create DNS cache");
        }
        file_ = fdopen(fd, "w+");
        if (file_ == nullptr) {
            const int error = errno;
            close(fd);
            unlink(path_);
            path_[0] = '\0';
            throw std::system_error(error, std::generic_category(), "open DNS cache");
        }
        log_info("automatic DNS cache: %s", path_);
    }

    rewind(file_);
    if (fwrite(snapshot.data(), 1, snapshot.size(), file_) != snapshot.size() ||
        fflush(file_) != 0 || ftruncate(fileno(file_), static_cast<off_t>(snapshot.size())) < 0) {
        const int error = errno;
        close_file();
        throw std::system_error(error, std::generic_category(), "write DNS cache");
    }
    saved_snapshot_ = snapshot;
}

void local_dns_cache::refresh(clock::time_point now)
{
    if (now < next_refresh_)
        return;
    next_refresh_ = now + std::chrono::seconds(DNS_REFRESH_SECONDS);

    try {
        auto entries = discover_local_dns(entries_);
        entries_.swap(entries);
    } catch (const std::exception& error) {
        log_error("automatic DNS discovery failed: %s; retaining cached DNS and retrying in %u seconds",
                  error.what(), DNS_REFRESH_SECONDS);
    }

    if (entries_.empty() && !missing_reported_)
        log_error("no local ULA available; packets pass unchanged until the next DNS refresh");
    else if (!entries_.empty() && missing_reported_)
        log_info("automatic DNS discovery recovered");
    missing_reported_ = entries_.empty();

    try {
        std::string snapshot;
        for (const auto& item : entries_)
            snapshot += std::to_string(item.first) + " " + item.second.description + "\n";
        save(snapshot);
    } catch (const std::exception& error) {
        // Persistence is diagnostic; packet processing can use the memory cache.
        log_error("automatic DNS cache persistence failed: %s; retrying in %u seconds",
                  error.what(), DNS_REFRESH_SECONDS);
    }
}

const local_dns_source *local_dns_cache::find(uint32_t indev, uint32_t physindev) const
{
    auto entry = entries_.find(indev);
    if (entry == entries_.end())
        entry = entries_.find(physindev);
    return entry == entries_.end() ? nullptr : &entry->second;
}
