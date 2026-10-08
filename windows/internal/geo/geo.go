// Package geo: which AWS region in Europe an address belongs to, by prefix (the regions Epic's
// beacons and game servers use), and which addresses are worth trusting from DNS.
package geo

import "net/netip"

// City: "frankfurt", "london", "paris", or "eu" for the rest
func City(a netip.Addr) string {
	if !a.Is4() {
		return "eu"
	}
	o := a.As4()
	x, y := int(o[0]), int(o[1])
	switch {
	case (x == 3 && y >= 64 && y <= 79) || (x == 18 && y >= 153 && y <= 159) || (x == 35 && y >= 156 && y <= 159):
		return "frankfurt"
	case (x == 3 && y >= 8 && y <= 11) || (x == 18 && ((y >= 130 && y <= 135) || (y >= 168 && y <= 171))) ||
		(x == 13 && y >= 40 && y <= 43) || (x == 35 && y >= 176 && y <= 179):
		return "london"
	case (x == 13 && y >= 36 && y <= 39) || (x == 15 && (y == 188 || y == 236 || y == 237)) || (x == 35 && (y == 180 || y == 181)):
		return "paris"
	}
	return "eu"
}

var ru = map[string]string{"frankfurt": "Франкфурт", "london": "Лондон", "paris": "Париж", "eu": "Европа"}

// CityRU: the city in Russian
func CityRU(a netip.Addr) string { return ru[City(a)] }

// IsFakeIP: 198.18.0.0/15, the fake addresses of Podkop and the like
func IsFakeIP(a netip.Addr) bool {
	o := a.As4()
	return a.Is4() && o[0] == 198 && (o[1] == 18 || o[1] == 19)
}

// IsPublic: a routable IPv4 address (not private, special or fakeip)
func IsPublic(a netip.Addr) bool {
	if !a.Is4() || a.IsPrivate() || a.IsLoopback() || a.IsMulticast() || a.IsUnspecified() || a.IsLinkLocalUnicast() {
		return false
	}
	o := a.As4()
	return !(o[0] == 0 || o[0] >= 224 || (o[0] == 100 && o[1] >= 64 && o[1] <= 127) || IsFakeIP(a))
}
