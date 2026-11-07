include $(TOPDIR)/rules.mk

PKG_NAME:=fnport
PKG_VERSION:=0.7.0
PKG_RELEASE:=2
PKG_LICENSE:=MIT

include $(INCLUDE_DIR)/package.mk

define Package/fnport
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Pick DPI-passing source ports for game UDP (Fortnite)
  DEPENDS:=+ucode +ucode-mod-socket +ucode-mod-uci +ucode-mod-fs +ucode-mod-math +conntrack +nftables +kmod-nft-nat +kmod-nft-tproxy +kmod-tun +ip-full +ca-bundle
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
/etc/config/fnport_connections
endef

define Build/Compile
endef

define Package/fnport/install
	$(INSTALL_DIR) $(1)/etc/config $(1)/etc/init.d $(1)/usr/share/fnport $(1)/usr/libexec $(1)/lib/upgrade/keep.d $(1)/etc/uci-defaults
	$(INSTALL_CONF) ./files/fnport.config $(1)/etc/config/fnport
	$(INSTALL_BIN) ./files/fnport.init $(1)/etc/init.d/fnport
	$(INSTALL_DATA) ./files/fnportd.uc $(1)/usr/share/fnport/fnportd.uc
	$(INSTALL_DATA) ./files/fnport-udp-policy.uc $(1)/usr/share/fnport/fnport-udp-policy.uc
	$(INSTALL_DATA) ./files/quic_initial_vk_com.bin $(1)/usr/share/fnport/quic_initial_vk_com.bin
	$(INSTALL_DATA) ./files/quic_initial_vk_com.bin.LICENSE $(1)/usr/share/fnport/quic_initial_vk_com.bin.LICENSE
	$(INSTALL_DATA) ./files/quic_initial_gosuslugi_ru.bin $(1)/usr/share/fnport/quic_initial_gosuslugi_ru.bin
	$(INSTALL_DATA) ./files/quic_initial_gosuslugi_ru.bin.LICENSE $(1)/usr/share/fnport/quic_initial_gosuslugi_ru.bin.LICENSE
	$(INSTALL_DATA) ./files/quic_initial_ozon_ru.bin $(1)/usr/share/fnport/quic_initial_ozon_ru.bin
	$(INSTALL_DATA) ./files/quic_initial_ozon_ru.bin.LICENSE $(1)/usr/share/fnport/quic_initial_ozon_ru.bin.LICENSE
	$(INSTALL_BIN) ./files/fnport-check.uc $(1)/usr/libexec/fnport-check
	$(INSTALL_DATA) ./files/fnport-check-policy.uc $(1)/usr/libexec/fnport-check-policy.uc
	$(INSTALL_BIN) ./files/fnport-update.uc $(1)/usr/libexec/fnport-update
	$(INSTALL_CONF) ./files/fnport-connections.config $(1)/etc/config/fnport_connections
	$(INSTALL_BIN) ./files/fnport-connections.init $(1)/etc/init.d/fnport-connections
	$(INSTALL_DATA) ./files/connections-config.uc $(1)/usr/share/fnport/connections-config.uc
	$(INSTALL_BIN) ./files/fnport-connectionsctl.uc $(1)/usr/libexec/fnport-connectionsctl
	$(INSTALL_BIN) ./files/fnport-connections-action.sh $(1)/usr/libexec/fnport-connections-action
	$(INSTALL_BIN) ./files/fnport-connections-install.sh $(1)/usr/libexec/fnport-connections-install
	$(INSTALL_DATA) ./files/connections-cores.json $(1)/usr/share/fnport/connections-cores.json
	$(INSTALL_DATA) ./files/discord-domains.lst $(1)/usr/share/fnport/discord-domains.lst
	$(INSTALL_DATA) ./files/discord-rules.json $(1)/usr/share/fnport/discord-rules.json
	$(INSTALL_DATA) ./files/sing-box-GPL-3.0.txt $(1)/usr/share/fnport/sing-box-GPL-3.0.txt
	$(INSTALL_DATA) ./files/sing-box-SOURCES.txt $(1)/usr/share/fnport/sing-box-SOURCES.txt
	echo "$(PKG_VERSION)-r$(PKG_RELEASE)" > $(1)/usr/share/fnport/version
	# statistics and what was learnt per network survive a sysupgrade
	$(INSTALL_DATA) ./files/fnport.keep $(1)/lib/upgrade/keep.d/fnport
	$(INSTALL_BIN) ./files/fnport.defaults $(1)/etc/uci-defaults/90-fnport-spare-fakes
endef

$(eval $(call BuildPackage,fnport))
