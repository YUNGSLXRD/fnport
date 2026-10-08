package geo

import (
	"net/netip"
	"testing"
)

func TestCity(t *testing.T) {
	for ip, c := range map[string]string{"3.66.90.173": "frankfurt", "18.157.38.117": "frankfurt", "18.133.162.202": "london",
		"13.37.148.3": "paris", "15.237.20.100": "paris", "52.1.1.1": "eu"} {
		if got := City(netip.MustParseAddr(ip)); got != c {
			t.Errorf("%s: %s", ip, got)
		}
	}
	for ip, pub := range map[string]bool{"3.66.90.173": true, "198.18.4.7": false, "192.168.1.1": false, "100.64.0.1": false} {
		if IsPublic(netip.MustParseAddr(ip)) != pub {
			t.Errorf("IsPublic(%s)", ip)
		}
	}
}
