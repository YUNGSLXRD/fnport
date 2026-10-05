include $(TOPDIR)/rules.mk

PKG_NAME:=fnport
PKG_VERSION:=0.4.2
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
	$(INSTALL_DIR) $(1)/etc/config $(1)/etc/init.d $(1)/usr/share/fnport $(1)/usr/libexec $(1)/lib/upgrade/keep.d $(1)/etc/uci-defaults
	$(INSTALL_CONF) ./files/fnport.config $(1)/etc/config/fnport
	$(INSTALL_BIN) ./files/fnport.init $(1)/etc/init.d/fnport
	$(INSTALL_DATA) ./files/fnportd.uc $(1)/usr/share/fnport/fnportd.uc
	$(INSTALL_DATA) ./files/quic_initial_vk_com.bin $(1)/usr/share/fnport/quic_initial_vk_com.bin
	$(INSTALL_DATA) ./files/quic_initial_vk_com.bin.LICENSE $(1)/usr/share/fnport/quic_initial_vk_com.bin.LICENSE
	$(INSTALL_DATA) ./files/quic_initial_gosuslugi_ru.bin $(1)/usr/share/fnport/quic_initial_gosuslugi_ru.bin
	$(INSTALL_DATA) ./files/quic_initial_gosuslugi_ru.bin.LICENSE $(1)/usr/share/fnport/quic_initial_gosuslugi_ru.bin.LICENSE
	$(INSTALL_DATA) ./files/quic_initial_ozon_ru.bin $(1)/usr/share/fnport/quic_initial_ozon_ru.bin
	$(INSTALL_DATA) ./files/quic_initial_ozon_ru.bin.LICENSE $(1)/usr/share/fnport/quic_initial_ozon_ru.bin.LICENSE
	$(INSTALL_BIN) ./files/fnport-check.uc $(1)/usr/libexec/fnport-check
	echo "$(PKG_VERSION)-r$(PKG_RELEASE)" > $(1)/usr/share/fnport/version
	# statistics and what was learnt per network survive a sysupgrade
	$(INSTALL_DATA) ./files/fnport.keep $(1)/lib/upgrade/keep.d/fnport
	$(INSTALL_BIN) ./files/fnport.defaults $(1)/etc/uci-defaults/90-fnport-spare-fakes
endef

$(eval $(call BuildPackage,fnport))
