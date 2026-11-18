package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/YUNGSLXRD/fnport/windows/internal/vpn"
	"github.com/YUNGSLXRD/fnport/windows/internal/wnet"
)

const (
	subscriptionMaxBytes = vpn.SubscriptionMaxBytes
	subscriptionMaxNodes = vpn.SubscriptionMaxNodes
)

type subscriptionNode = vpn.Node
type connectionSubscription = vpn.Subscription

func cloneSubscription(s *connectionSubscription) *connectionSubscription {
	return s.Clone()
}

func subscriptionURL(text string) bool {
	return vpn.IsSubscriptionURL(text)
}

func subscriptionDeviceIDAt(idFile string) (string, error) {
	return vpn.DeviceIDAt(idFile)
}

func subscriptionDeviceID() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", errors.New("недоступна папка данных fnport")
	}
	return vpn.DeviceIDAt(filepath.Join(dir, "fnport", "subscription-device-id"))
}

func subscriptionUA(ver, id string) string {
	return vpn.SubscriptionUA(ver, id)
}

func subscriptionHTTPClient() *http.Client {
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, errors.New("неверный адрес")
			}
			p, err := net.LookupPort("tcp", port)
			if err != nil {
				return nil, errors.New("неверный порт")
			}
			ip, err := netip.ParseAddr(host)
			if err != nil {
				ips := lookupAllContext(ctx, host)
				if len(ips) == 0 {
					return nil, errors.New("не найден адрес")
				}
				ip = ips[0]
			}
			return wnet.DialTCP(ctx, netip.AddrPortFrom(ip, uint16(p)))
		},
	}
	return &http.Client{Transport: tr, Timeout: 20 * time.Second}
}

func fetchSubscription(ctx context.Context, source, id, ver string, client *http.Client) (*connectionSubscription, error) {
	return vpn.FetchSubscription(ctx, source, id, ver, subscriptionOS(), subscriptionOSVersion(), client)
}

func loadSubscription(ctx context.Context, source string) (*connectionSubscription, error) {
	id, err := subscriptionDeviceID()
	if err != nil {
		return nil, err
	}
	c := subscriptionHTTPClient()
	defer c.CloseIdleConnections()
	return fetchSubscription(ctx, source, id, version, c)
}

func parseSubscription(body []byte) ([]subscriptionNode, int, error) {
	return vpn.ParseSubscription(body)
}

func retainSubscriptionSelection(next, old *connectionSubscription) {
	vpn.RetainSelection(next, old)
}

func subscriptionOS() string {
	switch runtime.GOOS {
	case "windows":
		return "Windows"
	case "darwin":
		return "macOS"
	default:
		return "Linux"
	}
}
