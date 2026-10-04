include $(TOPDIR)/rules.mk

PKG_NAME:=fnport
PKG_VERSION:=0.3.1
PKG_RELEASE:=1
PKG_LICENSE:=MIT

include $(INCLUDE_DIR)/package.mk

define Package/fnport
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Pick DPI-passing source ports for game UDP (Fortnite)
  DEPENDS:=+ucode +ucode-mod-socket +ucode-mod-uci +ucode-mod-fs +ucode-mod-math +conntrack +nftables +kmod-nft-nat
  PKGARCH:=all
endef

define Package/fnport/description
  Some ISP DPI boxes freeze UDP flows to game servers after 25 packets, and
  which flows get frozen depends on the source port. fnport holds the first
  packet of each new game flow from selected LAN devices, probes the server
  from several candidate source ports and maps the flow to one that passes.
  Each probe and flow is preceded by one short-TTL fake QUIC Initial with a
  whitelisted SNI, which the DPI honours. No VPN: traffic goes directly to the
  game server.
endef

define Package/fnport/conffiles
/etc/config/fnport
endef

define Build/Compile
endef

define Package/fnport/install
	$(INSTALL_DIR) $(1)/etc/config $(1)/etc/init.d $(1)/usr/share/fnport
	$(INSTALL_CONF) ./files/fnport.config $(1)/etc/config/fnport
	$(INSTALL_BIN) ./files/fnport.init $(1)/etc/init.d/fnport
	$(INSTALL_DATA) ./files/fnportd.uc $(1)/usr/share/fnport/fnportd.uc
	$(INSTALL_DATA) ./files/quic_initial_vk_com.bin $(1)/usr/share/fnport/quic_initial_vk_com.bin
endef

$(eval $(call BuildPackage,fnport))
