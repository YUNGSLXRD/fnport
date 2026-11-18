package vpn

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"net/http"
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
	"MD": "Молдова", "BY": "Беларусь", "HK": "Гонконг", "SG": "Сингапур", "JP": "Япония",
	"CA": "Канада", "AE": "ОАЭ", "IL": "Израиль", "IN": "Индия", "BR": "Бразилия", "KR": "Южная Корея",
	"RS": "Сербия", "SK": "Словакия", "SI": "Словения", "HR": "Хорватия", "PT": "Португалия",
	"GR": "Греция", "CY": "Кипр", "IS": "Исландия", "AU": "Австралия",
}

// CityRU maps common English GeoIP / data-center city names to Russian names.
var CityRU = map[string]string{
	"amsterdam":           "Амстердам",
	"rotterdam":           "Роттердам",
	"the hague":           "Гаага",
	"haarlem":             "Харлем",
	"schiphol":            "Схипхол",
	"naaldwijk":           "Налдвейк",
	"meppel":              "Меппель",
	"dronten":             "Дронтен",
	"lelystad":            "Лелистад",
	"frankfurt":           "Франкфурт",
	"frankfurt am main":   "Франкфурт",
	"falkenstein":         "Фалькенштайн",
	"nuremberg":           "Нюрнберг",
	"nürnberg":            "Нюрнберг",
	"munich":              "Мюнхен",
	"berlin":              "Берлин",
	"düsseldorf":          "Дюссельдорф",
	"dusseldorf":          "Дюссельдорф",
	"hamburg":             "Гамбург",
	"stuttgart":           "Штутгарт",
	"limburg":             "Лимбург",
	"limburg an der lahn": "Лимбург",
	"helsinki":            "Хельсинки",
	"espoo":               "Эспоо",
	"tuusula":             "Туусула",
	"turku":               "Турку",
	"tampere":             "Тампере",
	"stockholm":           "Стокгольм",
	"gothenburg":          "Гетеборг",
	"warsaw":              "Варшава",
	"krakow":              "Краков",
	"gdansk":              "Гданьск",
	"wroclaw":             "Вроцлав",
	"poznan":              "Познань",
	"riga":                "Рига",
	"tallinn":             "Таллин",
	"tartu":               "Тарту",
	"vilnius":             "Вильнюс",
	"kaunas":              "Каунас",
	"london":              "Лондон",
	"manchester":          "Манчестер",
	"slough":              "Слау",
	"coventry":            "Ковентри",
	"paris":               "Париж",
	"marseille":           "Марсель",
	"strasbourg":          "Страсбург",
	"gravelines":          "Гравлин",
	"roubaix":             "Рубе",
	"vienna":              "Вена",
	"zurich":              "Цюрих",
	"zürich":              "Цюрих",
	"geneva":              "Женева",
	"prague":              "Прага",
	"bratislava":          "Братислава",
	"budapest":            "Будапешт",
	"bucharest":           "Бухарест",
	"sofia":               "София",
	"belgrade":            "Белград",
	"zagreb":              "Загреб",
	"ljubljana":           "Любляна",
	"madrid":              "Мадрид",
	"barcelona":           "Барселона",
	"lisbon":              "Лиссабон",
	"milan":               "Милан",
	"rome":                "Рим",
	"athens":              "Афины",
	"limassol":            "Лимассол",
	"nicosia":             "Никосия",
	"istanbul":            "Стамбул",
	"ankara":              "Анкара",
	"izmir":               "Измир",
	"antalya":             "Анталья",
	"dublin":              "Дублин",
	"brussels":            "Брюссель",
	"luxembourg":          "Люксембург",
	"copenhagen":          "Копенгаген",
	"oslo":                "Осло",
	"reykjavik":           "Рейкьявик",
	"moscow":              "Москва",
	"saint petersburg":    "Санкт-Петербург",
	"st petersburg":       "Санкт-Петербург",
	"novosibirsk":         "Новосибирск",
	"yekaterinburg":       "Екатеринбург",
	"kazan":               "Казань",
	"almaty":              "Алматы",
	"astana":              "Астана",
	"tbilisi":             "Тбилиси",
	"yerevan":             "Ереван",
	"minsk":               "Минск",
	"chisinau":            "Кишинёв",
	"chișinău":            "Кишинёв",
	"kyiv":                "Киев",
	"kiev":                "Киев",
	"singapore":           "Сингапур",
	"tokyo":               "Токио",
	"osaka":               "Осака",
	"seoul":               "Сеул",
	"hong kong":           "Гонконг",
	"dubai":               "Дубай",
	"tel aviv":            "Тель-Авив",
	"mumbai":              "Мумбаи",
	"new york":            "Нью-Йорк",
	"new york city":       "Нью-Йорк",
	"ashburn":             "Ашберн",
	"miami":               "Майами",
	"los angeles":         "Лос-Анджелес",
	"chicago":             "Чикаго",
	"dallas":              "Даллас",
	"seattle":             "Сиэтл",
	"san jose":            "Сан-Хосе",
	"secaucus":            "Секокус",
	"toronto":             "Торонто",
	"montreal":            "Монреаль",
	"sao paulo":           "Сан-Паулу",
	"são paulo":           "Сан-Паулу",
	"sydney":              "Сидней",
}

// TranslateCity returns a localized Russian city name when known, or the cleaned input.
func TranslateCity(city string) string {
	c := strings.TrimSpace(city)
	if c == "" {
		return ""
	}
	if ru, ok := CityRU[strings.ToLower(c)]; ok {
		return ru
	}
	return c
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

// FormatExitLocation formats an ExitReport for display in the UI.
// For WARP it shows the Cloudflare colo ("Рига (RIX), Латвия");
// for VPN / AmneziaWG it shows GeoIP "Город, Страна" (or "Страна").
func FormatExitLocation(r ExitReport, isWARP bool) string {
	if isWARP {
		if r.Colo != "" {
			return ExitName(r.Colo)
		}
		return ""
	}
	cc := strings.ToUpper(strings.TrimSpace(r.Country))
	cName := CountryRU[cc]
	if cName == "" {
		cName = strings.TrimSpace(r.CountryName)
	}
	if cName == "" {
		cName = cc
	}
	city := TranslateCity(r.City)
	if city != "" && cName != "" {
		if strings.EqualFold(city, cName) {
			return cName
		}
		return city + ", " + cName
	}
	if cName != "" {
		return cName
	}
	if city != "" {
		return city
	}
	if r.Colo != "" {
		return ExitName(r.Colo)
	}
	return ""
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

// ExitReport holds exit metadata observed through GeoIP or Cloudflare's trace endpoint,
// plus optional one-shot server latency.
type ExitReport struct {
	Colo        string
	Country     string
	CountryName string
	City        string
	Address     string
	RTT         time.Duration
	ServerPing  time.Duration
}

// TraceExit queries https://1.1.1.1/cdn-cgi/trace over the provided tunnel dialer.
func TraceExit(ctx context.Context, dial func(context.Context, string) (net.Conn, error)) (ExitReport, error) {
	return traceExitInternal(ctx, dial, false)
}

func traceExitInternal(ctx context.Context, dial func(context.Context, string) (net.Conn, error), preferLocCountry bool) (ExitReport, error) {
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
	if colo == "" && kv["loc"] == "" {
		return ExitReport{}, errors.New("exit_trace_incomplete")
	}
	var country string
	if preferLocCountry && kv["loc"] != "" && kv["loc"] != "XX" {
		country = strings.ToUpper(kv["loc"])
	} else {
		country = ColoCountry[colo]
		if country == "" {
			country = strings.ToUpper(kv["loc"])
		}
	}
	var ipStr string
	if ip, err := netip.ParseAddr(kv["ip"]); err == nil {
		ipStr = ip.String()
	}
	return ExitReport{Colo: colo, Country: country, Address: ipStr, RTT: rtt}, nil
}

func fetchHTTPSJSON(
	parent context.Context,
	dialHost func(ctx context.Context, host string, port uint16) (net.Conn, error),
	host, reqPath string,
) ([]byte, time.Duration, error) {
	ctx, cancel := context.WithTimeout(parent, 4500*time.Millisecond)
	defer cancel()
	started := time.Now()
	raw, err := dialHost(ctx, host, 443)
	if err != nil {
		return nil, 0, err
	}
	defer raw.Close()
	rtt := time.Since(started)
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop()
	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	}
	tc := tls.Client(raw, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, 0, err
	}
	reqStr := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: curl/8.5.0\r\nAccept: application/json\r\nConnection: close\r\n\r\n", reqPath, host)
	if _, err := io.WriteString(tc, reqStr); err != nil {
		return nil, 0, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(io.LimitReader(tc, 32768)), nil)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, errors.New("geoip_bad_status")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16384))
	if err != nil {
		return nil, 0, err
	}
	return body, rtt, nil
}

// ProbeVPNExit resolves the VPN exit IP's country and city once via GeoIP (ipwho.is -> ipinfo.io -> Cloudflare trace).
func ProbeVPNExit(
	ctx context.Context,
	dialHost func(ctx context.Context, host string, port uint16) (net.Conn, error),
) (ExitReport, error) {
	if body, rtt, err := fetchHTTPSJSON(ctx, dialHost, "ipwho.is", "/?fields=success,ip,country_code,country,city&lang=ru"); err == nil {
		var res struct {
			Success     *bool  `json:"success"`
			IP          string `json:"ip"`
			CountryCode string `json:"country_code"`
			Country     string `json:"country"`
			City        string `json:"city"`
		}
		if json.Unmarshal(body, &res) == nil && (res.Success == nil || *res.Success) && len(strings.TrimSpace(res.CountryCode)) == 2 {
			var ipStr string
			if ip, e := netip.ParseAddr(strings.TrimSpace(res.IP)); e == nil {
				ipStr = ip.String()
			}
			cc := strings.ToUpper(strings.TrimSpace(res.CountryCode))
			return ExitReport{
				Country:     cc,
				CountryName: strings.TrimSpace(res.Country),
				City:        TranslateCity(res.City),
				Address:     ipStr,
				RTT:         rtt,
			}, nil
		}
	}

	if body, rtt, err := fetchHTTPSJSON(ctx, dialHost, "ipinfo.io", "/json"); err == nil {
		var res struct {
			IP      string `json:"ip"`
			City    string `json:"city"`
			Country string `json:"country"`
		}
		if json.Unmarshal(body, &res) == nil && len(strings.TrimSpace(res.Country)) == 2 {
			var ipStr string
			if ip, e := netip.ParseAddr(strings.TrimSpace(res.IP)); e == nil {
				ipStr = ip.String()
			}
			cc := strings.ToUpper(strings.TrimSpace(res.Country))
			return ExitReport{
				Country: cc,
				City:    TranslateCity(res.City),
				Address: ipStr,
				RTT:     rtt,
			}, nil
		}
	}

	return traceExitInternal(ctx, func(cctx context.Context, addr string) (net.Conn, error) {
		h, pStr, e := net.SplitHostPort(addr)
		if e != nil {
			return nil, e
		}
		var port uint16 = 443
		if pStr == "80" {
			port = 80
		}
		return dialHost(cctx, h, port)
	}, true)
}

// PingEndpoint measures one-shot direct network latency to a VPN server endpoint.
func PingEndpoint(
	ctx context.Context,
	addr netip.AddrPort,
	udpOnly bool,
	dialTCP func(context.Context, netip.AddrPort) (net.Conn, error),
	dialUDP func(context.Context, netip.AddrPort) (net.Conn, error),
) (time.Duration, error) {
	if !addr.IsValid() || addr.Port() == 0 {
		return 0, errors.New("invalid_endpoint")
	}

	if !udpOnly {
		if dialTCP == nil {
			return 0, errors.New("no_tcp_dialer")
		}
		pctx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
		defer cancel()
		t0 := time.Now()
		c, err := dialTCP(pctx, addr)
		if err != nil {
			return 0, err
		}
		best := time.Since(t0)
		_ = c.Close()
		if best < 350*time.Millisecond && ctx.Err() == nil {
			pctx2, cancel2 := context.WithTimeout(ctx, 1500*time.Millisecond)
			t1 := time.Now()
			if c2, e2 := dialTCP(pctx2, addr); e2 == nil {
				if d2 := time.Since(t1); d2 < best {
					best = d2
				}
				_ = c2.Close()
			}
			cancel2()
		}
		if best < time.Millisecond {
			best = time.Millisecond
		}
		return best, nil
	}

	// UDP-only endpoint (Hysteria 2 / QUIC / WireGuard): race a QUIC Version Negotiation
	// datagram probe against a TCP handshake so standard QUIC and port-443 servers respond.
	pctx, cancel := context.WithTimeout(ctx, 2200*time.Millisecond)
	defer cancel()
	type res struct {
		d   time.Duration
		err error
	}
	ch := make(chan res, 2)
	started := 0

	if dialUDP != nil {
		started++
		go func() {
			uc, err := dialUDP(pctx, addr)
			if err != nil {
				ch <- res{0, err}
				return
			}
			defer uc.Close()
			stop := context.AfterFunc(pctx, func() { _ = uc.Close() })
			defer stop()
			if dl, ok := pctx.Deadline(); ok {
				_ = uc.SetDeadline(dl)
			}
			// 1200-byte RFC 9000 Long Header packet with reserved greasing version 0x5a6a7a8a
			// triggers an immediate stateless Version Negotiation packet from QUIC servers.
			pkt := make([]byte, 1200)
			pkt[0] = 0xc0
			pkt[1], pkt[2], pkt[3], pkt[4] = 0x5a, 0x6a, 0x7a, 0x8a
			pkt[5] = 8
			_, _ = rand.Read(pkt[6:14])
			pkt[14] = 8
			_, _ = rand.Read(pkt[15:23])
			t0 := time.Now()
			if _, err := uc.Write(pkt); err != nil {
				ch <- res{0, err}
				return
			}
			reply := make([]byte, 1500)
			n, err := uc.Read(reply)
			if err != nil || n < 7 {
				ch <- res{0, errors.New("udp_no_reply")}
				return
			}
			d := time.Since(t0)
			if d < time.Millisecond {
				d = time.Millisecond
			}
			ch <- res{d, nil}
		}()
	}

	if dialTCP != nil {
		started++
		go func() {
			t0 := time.Now()
			c, err := dialTCP(pctx, addr)
			if err != nil {
				ch <- res{0, err}
				return
			}
			d := time.Since(t0)
			_ = c.Close()
			if d < time.Millisecond {
				d = time.Millisecond
			}
			ch <- res{d, nil}
		}()
	}

	if started == 0 {
		return 0, errors.New("no_dialer")
	}
	var lastErr error
	for i := 0; i < started; i++ {
		r := <-ch
		if r.err == nil {
			cancel()
			return r.d, nil
		}
		lastErr = r.err
	}
	return 0, lastErr
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
