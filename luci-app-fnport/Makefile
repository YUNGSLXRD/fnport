include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-fnport
PKG_VERSION:=0.4.1
PKG_RELEASE:=1
PKG_LICENSE:=MIT

LUCI_TITLE:=LuCI support for fnport
LUCI_DEPENDS:=+fnport +luci-base
LUCI_PKGARCH:=all

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
