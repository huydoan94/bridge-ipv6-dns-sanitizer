include $(TOPDIR)/rules.mk

PKG_NAME:=bridge-ipv6-dns-sanitizer
PKG_VERSION:=1.6.6
PKG_RELEASE:=1

PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE
PKG_BUILD_DEPENDS:=libnetfilter-queue libtins

include $(INCLUDE_DIR)/package.mk

define Package/bridge-ipv6-dns-sanitizer
	SECTION:=net
	CATEGORY:=Network
	TITLE:=Bridge IPv6 DNS sanitizer
	DEPENDS:=+kmod-nft-queue +libnetfilter-queue +libtins +nftables
endef

define Package/bridge-ipv6-dns-sanitizer/description
	NFQUEUE sanitizer for bridged VXLAN IPv6 configuration traffic. It
	preserves Router Advertisement prefix/route information and DHCPv6
	address assignments, neutralizes remote RA default-router lifetime,
	normalizes RA RDNSS and DHCPv6 DNS option 23 to the configured DNS list,
	or to one automatically discovered local ingress ULA when no list is set,
	and removes advertised DNS search lists.
endef

define Package/bridge-ipv6-dns-sanitizer/conffiles
/etc/config/bridge-ipv6-dns-sanitizer
endef

SANITIZE_SOURCES := logging.cpp network.cpp packet.cpp packet-parser.cpp bridge-ipv6-dns-sanitizer.cpp
SANITIZE_WARNINGS := -Wall -Wextra -Wpedantic -Wformat=2 -Wshadow -Wconversion -Werror

TARGET_CXXFLAGS += -Os $(SANITIZE_WARNINGS) -std=gnu++11 -ffunction-sections -fdata-sections
TARGET_CPPFLAGS += -isystem $(TOOLCHAIN_DIR)/include/fortify -isystem $(STAGING_DIR)/usr/include -DBRIDGE_IPV6_DNS_SANITIZER_VERSION=\"$(PKG_VERSION)\"
TARGET_LDFLAGS += -Wl,--gc-sections

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
	$(CP) ./LICENSE $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(TARGET_CXX) \
		$(TARGET_CXXFLAGS) \
		$(TARGET_CPPFLAGS) \
		-o $(PKG_BUILD_DIR)/bridge-ipv6-dns-sanitizer \
		$(addprefix $(PKG_BUILD_DIR)/,$(SANITIZE_SOURCES)) \
		$(TARGET_LDFLAGS) \
		-lnetfilter_queue \
		-ltins
endef

define Package/bridge-ipv6-dns-sanitizer/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/bridge-ipv6-dns-sanitizer \
		$(1)/usr/sbin/bridge-ipv6-dns-sanitizer
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/bridge-ipv6-dns-sanitizer.init \
		$(1)/etc/init.d/bridge-ipv6-dns-sanitizer
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/bridge-ipv6-dns-sanitizer.config \
		$(1)/etc/config/bridge-ipv6-dns-sanitizer
endef

$(eval $(call BuildPackage,bridge-ipv6-dns-sanitizer))
