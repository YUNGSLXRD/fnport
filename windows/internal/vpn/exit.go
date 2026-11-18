package vpn

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"net/netip"
	"strings"
	"time"
)

// ColoCity maps Cloudflare airport codes near Russia and in Europe to Russian city names.
var ColoCity = map[string]string{
	"FRA": "Франкфурт", "AMS": "Амстердам", "ARN": "Стокгольм", "GOT": "Гетеборг", "HEL": "Хельсинки", "WAW": "Варшава",
	"LHR": "Лондон", "MAN": "Манчестер", "CDG": "Париж", "MRS": "Марсель", "DME": "Москва", "SVO": "Москва",
	"LED": "Санкт-Петербург", "KJA": "Красноярск", "SVX": "Екатеринбург", "OVB": "Новосибирск", "KZN": "Казань",
	"RIX": "Рига", "TLL": "Таллин", "VNO": "Вильнюс", "PRG": "Прага", "VIE": "Вена", "MUC": "Мюнхен",
	"DUS": "Дюссельдорф", "HAM": "Гамбург", "BER": "Берлин", "TXL": "Берлин", "STR": "Штутгарт",
	"CPH": "Копенгаген", "OSL": "Осло", "MAD": "Мадрид", "BCN": "Барселона", "MXP": "Милан", "FCO": "Рим",
	"ZRH": "Цюрих", "GVA": "Женева", "KBP": "Киев", "OTP": "Бухарест", "SOF": "София", "BUD": "Будапешт",
	"IST": "Стамбул", "ALA": "Алматы", "NQZ": "Астана", "TBS": "Тбилиси", "EVN": "Ереван", "DUB": "Дублин",
	"BRU": "Брюссель", "LUX": "Люксембург", "KIV": "Кишинёв", "MSQ": "Минск",
	"HKG": "Гонконг", "TKU": "Турку", "TMP": "Тампере", "KRK": "Краков", "GDN": "Гданьск", "WRO": "Вроцлав",
	"POZ": "Познань", "TAY": "Тарту",
}

// ColoCountry maps Cloudflare airport codes to ISO-3166 alpha-2 country codes.
var ColoCountry = map[string]string{
	"FRA": "DE", "AMS": "NL", "ARN": "SE", "GOT": "SE", "HEL": "FI", "WAW": "PL", "LHR": "GB", "MAN": "GB", "CDG": "FR",
	"MRS": "FR", "DME": "RU", "SVO": "RU", "LED": "RU", "KJA": "RU", "SVX": "RU", "OVB": "RU", "KZN": "RU",
	"RIX": "LV", "TLL": "EE", "VNO": "LT", "PRG": "CZ", "VIE": "AT", "MUC": "DE", "DUS": "DE", "HAM": "DE",
	"BER": "DE", "TXL": "DE", "STR": "DE", "CPH": "DK", "OSL": "NO", "MAD": "ES", "BCN": "ES", "MXP": "IT",
	"FCO": "IT", "ZRH": "CH", "GVA": "CH", "KBP": "UA", "OTP": "RO", "SOF": "BG", "BUD": "HU", "IST": "TR",
	"ALA": "KZ", "NQZ": "KZ", "TBS": "GE", "EVN": "AM", "DUB": "IE", "BRU": "BE", "LUX": "LU", "KIV": "MD",
	"MSQ": "BY", "HKG": "HK", "TKU": "FI", "TMP": "FI", "KRK": "PL", "GDN": "PL", "WRO": "PL", "POZ": "PL",
	"TAY": "EE",
}

// CountryRU maps ISO-3166 alpha-2 country codes to Russian country names.
var CountryRU = map[string]string{
	"DE": "Германия", "NL": "Нидерланды", "SE": "Швеция", "FI": "Финляндия", "PL": "Польша", "GB": "Великобритания",
	"FR": "Франция", "RU": "Россия", "LV": "Латвия", "EE": "Эстония", "LT": "Литва", "CZ": "Чехия", "AT": "Австрия",
	"DK": "Дания", "NO": "Норвегия", "ES": "Испания", "IT": "Италия", "CH": "Швейцария", "UA": "Украина",
	"RO": "Румыния", "BG": "Болгария", "HU": "Венгрия", "TR": "Турция", "KZ": "Казахстан", "GE": "Грузия",
	"AM": "Армения", "IE": "Ирландия", "BE": "Бельгия", "LU": "Люксембург", "US": "США",
	"MD": "Молдова", "BY": "Беларусь", "HK": "Гонконг",
}

// ExitName formats a Cloudflare colo code as "Рига (RIX), Латвия".
func ExitName(colo string) string {
	s := ColoCity[colo]
	if s == "" {
		s = colo
	} else {
		s += " (" + colo + ")"
	}
	if c := CountryRU[ColoCountry[colo]]; c != "" {
		s += ", " + c
	}
	return s
}

// WarpExitTier classifies a Cloudflare exit: 0 for preferred nearby countries
// (LV, PL, EE, FI, SE), 1 for Germany fallback, and -1 for excluded/unknown regions.
func WarpExitTier(colo string) int {
	switch ColoCountry[colo] {
	case "LV", "PL", "EE", "FI", "SE":
		return 0
	case "DE":
		return 1
	default:
		return -1
	}
}

// BetterWarpExit compares two candidate WARP exits by tier first, then RTT.
func BetterWarpExit(colo string, rtt time.Duration, bestColo string, bestRTT time.Duration) bool {
	tier := WarpExitTier(colo)
	if tier < 0 || rtt <= 0 {
		return false
	}
	if bestColo == "" {
		return true
	}
	bestTier := WarpExitTier(bestColo)
	return bestTier < 0 || tier < bestTier || (tier == bestTier && rtt < bestRTT)
}

// ExitReport holds exit metadata observed through Cloudflare's trace endpoint.
type ExitReport struct {
	Colo    string
	Country string
	Address string
	RTT     time.Duration
}

// TraceExit queries https://1.1.1.1/cdn-cgi/trace over the provided tunnel dialer.
func TraceExit(ctx context.Context, dial func(context.Context, string) (net.Conn, error)) (ExitReport, error) {
	started := time.Now()
	raw, err := dial(ctx, "1.1.1.1:443")
	if err != nil {
		return ExitReport{}, errors.New("exit_dial_failed")
	}
	defer raw.Close()
	rtt := time.Since(started)
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(deadline)
	} else {
		_ = raw.SetDeadline(time.Now().Add(8 * time.Second))
	}
	tc := tls.Client(raw, &tls.Config{ServerName: "one.one.one.one", MinVersion: tls.VersionTLS12})
	if err := tc.HandshakeContext(ctx); err != nil {
		return ExitReport{}, errors.New("exit_tls_failed")
	}
	if _, err := io.WriteString(tc, "GET /cdn-cgi/trace HTTP/1.1\r\nHost: one.one.one.one\r\nConnection: close\r\n\r\n"); err != nil {
		return ExitReport{}, errors.New("exit_write_failed")
	}
	body, _ := io.ReadAll(io.LimitReader(tc, 8192))
	kv := make(map[string]string)
	for _, line := range strings.Split(string(body), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			kv[k] = v
		}
	}
	colo := kv["colo"]
	if colo == "" {
		return ExitReport{}, errors.New("exit_trace_incomplete")
	}
	country := ColoCountry[colo]
	if country == "" {
		country = kv["loc"]
	}
	var ipStr string
	if ip, err := netip.ParseAddr(kv["ip"]); err == nil {
		ipStr = ip.String()
	}
	return ExitReport{Colo: colo, Country: country, Address: ipStr, RTT: rtt}, nil
}

// WarpEndpoints returns candidate Cloudflare WARP endpoints ordered for Russian ISPs:
// explicit setting first, then the remembered working endpoint, then 188.114.96-99 and
// 162.159.192 (excluding 162.159.193, which is commonly blocked).
func WarpEndpoints(first, remembered string) []string {
	var out []string
	if first != "" {
		out = append(out, first)
	}
	if remembered != "" && remembered != first {
		out = append(out, remembered)
	}
	ranges := []string{"188.114.96", "188.114.97", "188.114.98", "188.114.99", "162.159.192"}
	ports := []int{2408, 500, 1701, 4500, 854, 878, 894, 7559, 3138}
	pick := func(net3 string, port int) string {
		return fmt.Sprintf("%s.%d:%d", net3, 1+mrand.IntN(254), port)
	}
	for _, r := range ranges {
		out = append(out, pick(r, 2408))
	}
	for _, r := range ranges[:2] {
		for _, p := range ports[1:] {
			out = append(out, pick(r, p))
		}
	}
	for _, r := range ranges[2:] {
		for _, p := range ports[1:3] {
			out = append(out, pick(r, p))
		}
	}
	return out
}
