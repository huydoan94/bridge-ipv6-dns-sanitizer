include $(TOPDIR)/rules.mk

PKG_NAME:=l2dns6rw
PKG_VERSION:=1.6.15
PKG_RELEASE:=1

PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE
PKG_BUILD_DEPENDS:=libbpf

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/bpf.mk

define Package/l2dns6rw
	SECTION:=net
	CATEGORY:=Network
	TITLE:=Bridge IPv6 DNS sanitizer
	DEPENDS:=+libbpf $(BPF_DEPENDS)
endef

define Package/l2dns6rw/description
	eBPF sanitizer for bridged IPv6 configuration traffic, attached at tcx
	ingress of the configured devices (for example a VXLAN port). It keeps
	Router Advertisement prefix/route information and DHCPv6 address
	assignments, neutralizes the RA default-router lifetime, normalizes RA
	RDNSS and DHCPv6 DNS option 23 to the configured DNS list, or to the
	device's own ULA when no list is set, and removes DNS search lists.
endef

define Package/l2dns6rw/conffiles
/etc/config/l2dns6rw
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
	$(CP) ./LICENSE $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) $(PKG_JOBS) -C $(PKG_BUILD_DIR) \
		$(TARGET_CONFIGURE_OPTS) \
		CPPFLAGS="$(TARGET_CPPFLAGS)" \
		CFLAGS="$(TARGET_CFLAGS)" \
		LDFLAGS="$(TARGET_LDFLAGS)" \
		LIBBPF_CFLAGS="-isystem $(STAGING_DIR)/usr/include" \
		BPF_CLANG="$(CLANG)" \
		BPF_TARGET="$(BPF_TARGET)" \
		BPF_STRIP="$(LLVM_STRIP)" \
		BPF_INCLUDES="-I$(STAGING_DIR)/usr/include -I$(TOOLCHAIN_DIR)/include" \
		OBJECT_DIR="$(PKG_BUILD_DIR)/build" \
		VERSION="$(PKG_VERSION)-r$(PKG_RELEASE)"
endef

define Package/l2dns6rw/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/build/l2dns6rw $(1)/usr/sbin/l2dns6rw
	$(INSTALL_DIR) $(1)/lib/bpf
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/build/l2dns6rw.bpf.o $(1)/lib/bpf/l2dns6rw.o
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/l2dns6rw.init $(1)/etc/init.d/l2dns6rw
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/l2dns6rw.config $(1)/etc/config/l2dns6rw
endef

# The program stays attached while the service is stopped or restarting;
# removing the package detaches it (after the default stop and disable).
define Package/l2dns6rw/prerm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || /usr/sbin/l2dns6rw -D
endef

$(eval $(call BuildPackage,l2dns6rw))
