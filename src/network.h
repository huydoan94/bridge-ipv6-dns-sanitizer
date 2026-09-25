#ifndef BRIDGE_IPV6_DNS_SANITIZER_NETWORK_H
#define BRIDGE_IPV6_DNS_SANITIZER_NETWORK_H

#include "constants.h"

#include <chrono>
#include <cstdio>
#include <map>
#include <string>
#include <vector>

struct local_dns_source {
    std::vector<in6_addr> servers;
    std::string description;
    std::string interface_name;
};

class local_dns_cache {
public:
    using clock = std::chrono::steady_clock;

    local_dns_cache() = default;
    ~local_dns_cache();
    local_dns_cache(const local_dns_cache&) = delete;
    local_dns_cache& operator=(const local_dns_cache&) = delete;

    void refresh(clock::time_point now = clock::now());
    const local_dns_source *find(uint32_t indev, uint32_t physindev) const;
    const char *path() const
    {
        return path_;
    }

private:
    void save(const std::string& snapshot);
    void close_file();

    std::map<uint32_t, local_dns_source> entries_;
    clock::time_point next_refresh_ = clock::time_point::min();
    FILE *file_ = nullptr;
    char path_[sizeof(DNS_CACHE_TEMPLATE)] = {};
    std::string saved_snapshot_;
    bool missing_reported_ = false;
};

#endif
