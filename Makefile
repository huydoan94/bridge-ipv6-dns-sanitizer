include $(TOPDIR)/rules.mk

PKG_NAME:=l2dns6rw
PKG_VERSION:=1.6.10
PKG_RELEASE:=1

PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE
PKG_BUILD_DEPENDS:=libnetfilter-queue libtins

include $(INCLUDE_DIR)/package.mk

define Package/l2dns6rw
	SECTION:=net
	CATEGORY:=Network
	TITLE:=Bridge IPv6 DNS sanitizer
	DEPENDS:=+kmod-nft-queue +libnetfilter-queue +libtins +nftables
endef

define Package/l2dns6rw/description
	NFQUEUE sanitizer for bridged VXLAN IPv6 configuration traffic. It
	preserves Router Advertisement prefix/route information and DHCPv6
	address assignments, neutralizes remote RA default-router lifetime,
	normalizes RA RDNSS and DHCPv6 DNS option 23 to the configured DNS list,
	or to one automatically discovered local ingress ULA when no list is set,
	and removes advertised DNS search lists.
endef

define Package/l2dns6rw/conffiles
/etc/config/l2dns6rw
endef

SANITIZE_SOURCES := logging.cpp network.cpp packet.cpp packet-parser.cpp l2dns6rw.cpp
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
		-o $(PKG_BUILD_DIR)/l2dns6rw \
		$(addprefix $(PKG_BUILD_DIR)/,$(SANITIZE_SOURCES)) \
		$(TARGET_LDFLAGS) \
		-lnetfilter_queue \
		-ltins
endef

define Package/l2dns6rw/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/l2dns6rw \
		$(1)/usr/sbin/l2dns6rw
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/l2dns6rw.init \
		$(1)/etc/init.d/l2dns6rw
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/l2dns6rw.config \
		$(1)/etc/config/l2dns6rw
endef

$(eval $(call BuildPackage,l2dns6rw))
