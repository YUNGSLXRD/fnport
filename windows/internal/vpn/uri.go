package vpn

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

// CoreOutbounds lists the UDP-capable sing-box outbound types supported by fnport.
var CoreOutbounds = map[string]bool{
	"vless":       true,
	"hysteria2":   true,
	"shadowsocks": true,
	"trojan":      true,
	"socks":       true,
}

var ssCiphers = map[string]bool{
	"2022-blake3-aes-128-gcm":       true,
	"2022-blake3-aes-256-gcm":       true,
	"2022-blake3-chacha20-poly1305": true,
	"aes-128-gcm":                   true,
	"aes-192-gcm":                   true,
	"aes-256-gcm":                   true,
	"chacha20-ietf-poly1305":        true,
	"xchacha20-ietf-poly1305":       true,
}

// ProtocolLabel returns a human-readable protocol name.
func ProtocolLabel(proto string) string {
	switch proto {
	case "off", "":
		return "Выключено"
	case "warp":
		return "WARP"
	case "amneziawg", "wireguard":
		return "AmneziaWG / WireGuard"
	case "vless":
		return "VLESS"
	case "hysteria2":
		return "Hysteria 2"
	case "shadowsocks":
		return "Shadowsocks"
	case "trojan":
		return "Trojan"
	case "socks":
		return "SOCKS5"
	default:
		return strings.ToUpper(proto)
	}
}

// ProtocolShortBadge returns a compact badge label for subscription server rows.
func ProtocolShortBadge(proto string) string {
	switch proto {
	case "vless":
		return "VLESS"
	case "hysteria2":
		return "HY2"
	case "shadowsocks":
		return "SS"
	case "trojan":
		return "TROJAN"
	case "socks":
		return "SOCKS5"
	case "amneziawg", "wireguard":
		return "AWG"
	default:
		return strings.ToUpper(proto)
	}
}

// DetectInputKind inspects raw user text to show a friendly live hint in the UI.
func DetectInputKind(text string) string {
	t := strings.TrimSpace(text)
	if t == "" {
		return ""
	}
	if IsSubscriptionURL(t) {
		return "subscription"
	}
	if LooksLikeWGConf(t) {
		return "amneziawg"
	}
	lower := strings.ToLower(t)
	switch {
	case strings.HasPrefix(lower, "vless://"):
		return "vless"
	case strings.HasPrefix(lower, "hy2://"), strings.HasPrefix(lower, "hysteria2://"):
		return "hysteria2"
	case strings.HasPrefix(lower, "ss://"):
		return "shadowsocks"
	case strings.HasPrefix(lower, "trojan://"):
		return "trojan"
	case strings.HasPrefix(lower, "socks5://"), strings.HasPrefix(lower, "socks://"):
		return "socks"
	case strings.HasPrefix(t, "{"):
		return "json"
	default:
		return ""
	}
}

// SanitizeOutbound rejects unsafe keys (listeners, local file reads, commands, detours,
// system TUNs, routing overrides) and optionally pins bind_interface.
func SanitizeOutbound(v any, iface string) error {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if strings.HasSuffix(k, "_path") || k == "command" || k == "executable" || k == "arguments" || k == "directory" {
				return errors.New("в профиле запрещены локальные файлы и команды")
			}
			switch k {
			case "inbounds", "outbounds", "endpoints", "route", "dns", "experimental", "services", "log",
				"network_namespaces", "listen", "listen_port", "external_controller", "external_ui",
				"clash_api", "v2ray_api", "ssh_server", "relay_server_port",
				"auto_route", "auto_redirect", "set_system_proxy", "netns", "routing_mark",
				"inet4_bind_address", "inet6_bind_address", "detour":
				return errors.New("в профиле запрещены слушатели, маршруты и цепочки detour")
			case "system_interface", "system":
				if val != false {
					return errors.New("системные интерфейсы в профиле запрещены")
				}
			case "bind_interface":
				if iface != "" {
					x[k] = iface
				}
			}
			if err := SanitizeOutbound(val, iface); err != nil {
				return err
			}
		}
	case []any:
		for _, item := range x {
			if err := SanitizeOutbound(item, iface); err != nil {
				return err
			}
		}
	}
	return nil
}

// ValidateOutboundObject checks that obj is a safe, UDP-capable single outbound object.
func ValidateOutboundObject(obj map[string]any, iface string) (string, error) {
	if obj == nil {
		return "", errors.New("конфигурация должна быть объектом JSON")
	}
	if err := SanitizeOutbound(obj, iface); err != nil {
		return "", err
	}
	typ, _ := obj["type"].(string)
	if !CoreOutbounds[typ] {
		return "", errors.New("поддерживаются профили VLESS, Hysteria 2, Shadowsocks, Trojan и SOCKS5")
	}
	server, _ := obj["server"].(string)
	if strings.TrimSpace(server) == "" {
		return "", errors.New("в профиле не указан адрес сервера")
	}
	if !outboundSupportsUDP(obj, typ) {
		return "", errors.New("выбранный профиль отключает UDP и не подходит для голосовых каналов")
	}
	return typ, nil
}

func outboundSupportsUDP(obj map[string]any, typ string) bool {
	if netStr, ok := obj["network"].(string); ok && netStr != "" && netStr != "udp" {
		return false
	}
	if netList, ok := obj["network"].([]any); ok && len(netList) > 0 {
		hasUDP := false
		for _, n := range netList {
			if n == "udp" {
				hasUDP = true
			}
		}
		if !hasUDP {
			return false
		}
	}
	switch typ {
	case "socks":
		if ver, _ := obj["version"].(string); ver == "4" || ver == "4a" {
			return false
		}
	case "shadowsocks":
		method, _ := obj["method"].(string)
		if !ssCiphers[method] {
			return false
		}
		if plugin, _ := obj["plugin"].(string); plugin != "" {
			return false
		}
	}
	return true
}

// ImportProfile parses a URI link (vless://, hy2://, ss://, trojan://, socks5://),
// a single-object sing-box JSON outbound, or a WireGuard/AmneziaWG .conf.
// Errors never include user input or parser diagnostics that might leak credentials.
func ImportProfile(text string, required bool) (raw json.RawMessage, protocol string, name string, err error) {
	text = strings.TrimSpace(strings.TrimPrefix(text, "\ufeff"))
	if text == "" || text == "null" {
		if required {
			return nil, "", "", errors.New("вставьте ссылку подключения, подписку или конфигурацию")
		}
		return nil, "", "", nil
	}
	if LooksLikeWGConf(text) {
		_, b, e := ImportAWG(text)
		return b, "amneziawg", "", e
	}
	lower := strings.ToLower(text)
	switch {
	case strings.HasPrefix(lower, "vless://"):
		return parseVLESSURI(text)
	case strings.HasPrefix(lower, "hy2://"), strings.HasPrefix(lower, "hysteria2://"):
		return parseHysteria2URI(text)
	case strings.HasPrefix(lower, "ss://"):
		return parseShadowsocksURI(text)
	case strings.HasPrefix(lower, "trojan://"):
		return parseTrojanURI(text)
	case strings.HasPrefix(lower, "socks5://"), strings.HasPrefix(lower, "socks://"):
		return parseSOCKSURI(text)
	case strings.Contains(text, "://"):
		return nil, "", "", errors.New("поддерживаются ссылки vless://, hy2://, ss://, trojan://, socks5:// и подписки https://")
	default:
		return parseSingleOutboundJSON(text)
	}
}

func parseSingleOutboundJSON(text string) (json.RawMessage, string, string, error) {
	dec := json.NewDecoder(bytes.NewReader([]byte(text)))
	dec.UseNumber()
	var obj map[string]any
	if dec.Decode(&obj) != nil || obj == nil {
		return nil, "", "", errors.New("конфигурация должна быть ссылкой подключения или объектом JSON")
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return nil, "", "", errors.New("нужен один JSON-объект профиля")
	}

	if _, hasPriv := obj["private_key"]; hasPriv {
		if _, hasPeer := obj["peer_key"]; hasPeer {
			cfg, err := ParseAWGJSON(json.RawMessage(text))
			if err != nil {
				return nil, "", "", err
			}
			b, _ := json.Marshal(cfg)
			return b, "amneziawg", "", nil
		}
	}

	name, _ := obj["name"].(string)
	if name == "" {
		name, _ = obj["tag"].(string)
	}
	delete(obj, "name")
	delete(obj, "tag")
	typ, err := ValidateOutboundObject(obj, "")
	if err != nil {
		return nil, "", "", err
	}
	b, err := json.Marshal(obj)
	if err != nil {
		return nil, "", "", errors.New("не удалось обработать JSON профиля")
	}
	return b, typ, name, nil
}

func parseHostPort(u *url.URL, defaultPort int) (string, int, error) {
	host := u.Hostname()
	if host == "" {
		return "", 0, errors.New("missing_host")
	}
	if u.Port() == "" {
		if defaultPort > 0 {
			return host, defaultPort, nil
		}
		return "", 0, errors.New("missing_port")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return "", 0, errors.New("invalid_port")
	}
	return host, port, nil
}

func unescapeFragment(s string) string {
	if dec, err := url.PathUnescape(s); err == nil {
		return dec
	}
	return s
}

func queryBool(q url.Values, keys ...string) bool {
	for _, k := range keys {
		switch strings.ToLower(strings.TrimSpace(q.Get(k))) {
		case "1", "true", "yes":
			return true
		}
	}
	return false
}

func buildTLSOptions(host string, q url.Values, defaultSec string) (map[string]any, error) {
	sec := strings.ToLower(strings.TrimSpace(q.Get("security")))
	if sec == "" {
		sec = defaultSec
	}
	switch sec {
	case "", "none":
		return nil, nil
	case "tls", "reality", "xtls":
		if sec == "xtls" {
			sec = "tls"
		}
		tlsObj := map[string]any{"enabled": true}
		sni := q.Get("sni")
		if sni == "" {
			sni = q.Get("peer")
		}
		if sni == "" {
			sni = host
		}
		tlsObj["server_name"] = sni
		if alpn := q.Get("alpn"); alpn != "" {
			var list []string
			for _, part := range strings.Split(alpn, ",") {
				if p := strings.TrimSpace(part); p != "" {
					list = append(list, p)
				}
			}
			if len(list) > 0 {
				tlsObj["alpn"] = list
			}
		}
		fp := strings.TrimSpace(q.Get("fp"))
		if sec == "reality" && fp == "" {
			fp = "chrome"
		}
		if fp != "" {
			tlsObj["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
		}
		if sec == "reality" {
			pbk := strings.TrimSpace(q.Get("pbk"))
			if pbk == "" {
				return nil, errors.New("missing_reality_key")
			}
			tlsObj["reality"] = map[string]any{
				"enabled":    true,
				"public_key": pbk,
				"short_id":   strings.TrimSpace(q.Get("sid")),
			}
		}
		if queryBool(q, "allowInsecure", "insecure") {
			tlsObj["insecure"] = true
		}
		return tlsObj, nil
	default:
		return nil, errors.New("unsupported_security")
	}
}

func buildV2RayTransport(q url.Values) (map[string]any, error) {
	if ht := q.Get("headerType"); ht != "" && ht != "none" {
		return nil, errors.New("unsupported_header_type")
	}
	typ := strings.ToLower(strings.TrimSpace(q.Get("type")))
	switch typ {
	case "", "tcp", "raw":
		return nil, nil
	case "ws":
		t := map[string]any{"type": "ws"}
		wsPath := q.Get("path")
		ed := q.Get("ed")
		if idx := strings.Index(wsPath, "?ed="); idx >= 0 {
			if ed == "" {
				ed = wsPath[idx+4:]
			}
			wsPath = wsPath[:idx]
		}
		if wsPath != "" {
			t["path"] = wsPath
		}
		if h := q.Get("host"); h != "" {
			t["headers"] = map[string]string{"Host": h}
		}
		if ed != "" {
			if n, err := strconv.Atoi(ed); err == nil && n > 0 && n <= 16384 {
				t["max_early_data"] = n
				t["early_data_header_name"] = "Sec-WebSocket-Protocol"
			}
		}
		return t, nil
	case "httpupgrade":
		t := map[string]any{"type": "httpupgrade"}
		if p := q.Get("path"); p != "" {
			t["path"] = p
		}
		if h := q.Get("host"); h != "" {
			t["host"] = h
		}
		return t, nil
	case "http", "h2":
		t := map[string]any{"type": "http"}
		if p := q.Get("path"); p != "" {
			t["path"] = p
		}
		if h := q.Get("host"); h != "" {
			var hosts []string
			for _, part := range strings.Split(h, ",") {
				if s := strings.TrimSpace(part); s != "" {
					hosts = append(hosts, s)
				}
			}
			if len(hosts) > 0 {
				t["host"] = hosts
			}
		}
		return t, nil
	case "grpc":
		svc := q.Get("serviceName")
		if svc == "" {
			svc = strings.TrimPrefix(q.Get("path"), "/")
		}
		return map[string]any{"type": "grpc", "service_name": svc}, nil
	case "quic":
		return map[string]any{"type": "quic"}, nil
	default:
		return nil, errors.New("unsupported_transport")
	}
}

func parseVLESSURI(text string) (json.RawMessage, string, string, error) {
	fail := func() (json.RawMessage, string, string, error) {
		return nil, "", "", errors.New("некорректная ссылка VLESS")
	}
	u, err := url.Parse(text)
	if err != nil || u.User == nil {
		return fail()
	}
	if _, hasPass := u.User.Password(); hasPass || u.User.Username() == "" {
		return fail()
	}
	host, port, err := parseHostPort(u, 0)
	if err != nil {
		return fail()
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return fail()
	}
	allowedParams := map[string]bool{
		"encryption": true, "security": true, "sni": true, "peer": true, "fp": true,
		"pbk": true, "sid": true, "spx": true, "type": true, "host": true,
		"path": true, "ed": true, "serviceName": true, "mode": true, "authority": true,
		"alpn": true, "flow": true, "headerType": true, "allowInsecure": true,
		"insecure": true, "packetEncoding": true, "packet_encoding": true,
	}
	for k, vals := range q {
		if !allowedParams[k] || len(vals) != 1 {
			return fail()
		}
	}
	if enc := q.Get("encryption"); enc != "" && enc != "none" {
		return fail()
	}
	out := map[string]any{
		"type":        "vless",
		"server":      host,
		"server_port": port,
		"uuid":        u.User.Username(),
	}
	if flow := strings.TrimSpace(q.Get("flow")); flow != "" {
		out["flow"] = flow
	}
	pe := strings.TrimSpace(q.Get("packetEncoding"))
	if pe == "" {
		pe = strings.TrimSpace(q.Get("packet_encoding"))
	}
	if pe != "" {
		out["packet_encoding"] = pe
	}
	tlsObj, err := buildTLSOptions(host, q, "")
	if err != nil {
		return fail()
	}
	if tlsObj != nil {
		out["tls"] = tlsObj
	}
	trObj, err := buildV2RayTransport(q)
	if err != nil {
		return fail()
	}
	if trObj != nil {
		out["transport"] = trObj
	}
	b, err := json.Marshal(out)
	if err != nil {
		return fail()
	}
	return b, "vless", unescapeFragment(u.Fragment), nil
}

func parseHysteria2URI(text string) (json.RawMessage, string, string, error) {
	fail := func() (json.RawMessage, string, string, error) {
		return nil, "", "", errors.New("некорректная ссылка Hysteria 2")
	}
	u, err := url.Parse(text)
	if err != nil {
		return fail()
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return fail()
	}
	var serverPorts []string
	firstHopPort := 443
	if mport := strings.TrimSpace(q.Get("mport")); mport != "" {
		ports, first, e := parsePortHopping(mport)
		if e != nil {
			return fail()
		}
		serverPorts, firstHopPort = ports, first
	} else if portsParam := strings.TrimSpace(q.Get("ports")); portsParam != "" {
		ports, first, e := parsePortHopping(portsParam)
		if e != nil {
			return fail()
		}
		serverPorts, firstHopPort = ports, first
	}
	defPort := 443
	if len(serverPorts) > 0 {
		defPort = firstHopPort
	}
	host, port, err := parseHostPort(u, defPort)
	if err != nil {
		return fail()
	}

	password := ""
	if u.User != nil {
		if pass, ok := u.User.Password(); ok {
			password = u.User.Username() + ":" + pass
		} else {
			password = u.User.Username()
		}
	}
	if password == "" {
		password = q.Get("auth")
	}

	sni := strings.TrimSpace(q.Get("sni"))
	if sni == "" {
		sni = strings.TrimSpace(q.Get("peer"))
	}
	if sni == "" {
		sni = host
	}
	tlsObj := map[string]any{
		"enabled":     true,
		"server_name": sni,
	}
	if queryBool(q, "insecure", "allowInsecure") {
		tlsObj["insecure"] = true
	}
	if alpn := q.Get("alpn"); alpn != "" {
		var list []string
		for _, part := range strings.Split(alpn, ",") {
			if p := strings.TrimSpace(part); p != "" {
				list = append(list, p)
			}
		}
		if len(list) > 0 {
			tlsObj["alpn"] = list
		}
	}

	out := map[string]any{
		"type":        "hysteria2",
		"server":      host,
		"server_port": port,
		"tls":         tlsObj,
	}
	if password != "" {
		out["password"] = password
	}
	if len(serverPorts) > 0 {
		out["server_ports"] = serverPorts
	}
	if obfs := strings.ToLower(strings.TrimSpace(q.Get("obfs"))); obfs != "" && obfs != "none" {
		obfsPass := q.Get("obfs-password")
		if obfs != "salamander" || obfsPass == "" {
			return fail()
		}
		out["obfs"] = map[string]any{"type": "salamander", "password": obfsPass}
	}
	if up, e := strconv.Atoi(q.Get("upmbps")); e == nil && up > 0 && up <= 10000 {
		out["up_mbps"] = up
	}
	if down, e := strconv.Atoi(q.Get("downmbps")); e == nil && down > 0 && down <= 10000 {
		out["down_mbps"] = down
	}
	b, err := json.Marshal(out)
	if err != nil {
		return fail()
	}
	return b, "hysteria2", unescapeFragment(u.Fragment), nil
}

func parsePortHopping(spec string) ([]string, int, error) {
	var out []string
	firstPort := 0
	for _, item := range strings.Split(spec, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		sep := "-"
		if strings.Contains(item, ":") {
			sep = ":"
		}
		loStr, hiStr, hasRange := strings.Cut(item, sep)
		if !hasRange {
			hiStr = loStr
		}
		lo, err1 := strconv.Atoi(strings.TrimSpace(loStr))
		hi, err2 := strconv.Atoi(strings.TrimSpace(hiStr))
		if err1 != nil || err2 != nil || lo < 1 || hi > 65535 || lo > hi {
			return nil, 0, errors.New("invalid_port_range")
		}
		if firstPort == 0 {
			firstPort = lo
		}
		out = append(out, strconv.Itoa(lo)+":"+strconv.Itoa(hi))
	}
	if len(out) == 0 {
		return nil, 0, errors.New("empty_port_range")
	}
	return out, firstPort, nil
}

func decodeBase64Any(s string) (string, bool) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		if b, err := enc.DecodeString(s); err == nil && utf8.Valid(b) {
			return string(b), true
		}
	}
	return "", false
}

func parseShadowsocksURI(text string) (json.RawMessage, string, string, error) {
	fail := func() (json.RawMessage, string, string, error) {
		return nil, "", "", errors.New("некорректная или неподдерживаемая ссылка Shadowsocks")
	}
	body := text[len("ss://"):]
	fragment := ""
	if idx := strings.IndexByte(body, '#'); idx >= 0 {
		fragment = unescapeFragment(body[idx+1:])
		body = body[:idx]
	}
	rawQuery := ""
	if idx := strings.IndexByte(body, '?'); idx >= 0 {
		rawQuery = body[idx+1:]
		body = body[:idx]
	}
	body = strings.TrimSuffix(body, "/")

	q, err := url.ParseQuery(rawQuery)
	if err != nil || q.Get("plugin") != "" {
		return fail()
	}

	var method, password, hostPort string
	if at := strings.LastIndexByte(body, '@'); at >= 0 {
		userPart := body[:at]
		hostPort = body[at+1:]
		if unescaped, e := url.PathUnescape(userPart); e == nil {
			userPart = unescaped
		}
		m, p, hasColon := strings.Cut(userPart, ":")
		if hasColon && ssCiphers[strings.ToLower(m)] {
			method, password = strings.ToLower(m), p
		} else if decoded, ok := decodeBase64Any(userPart); ok {
			m2, p2, ok2 := strings.Cut(decoded, ":")
			if !ok2 {
				return fail()
			}
			method, password = strings.ToLower(m2), p2
		} else {
			return fail()
		}
	} else {
		decoded, ok := decodeBase64Any(body)
		if !ok {
			return fail()
		}
		at := strings.LastIndexByte(decoded, '@')
		if at < 0 {
			return fail()
		}
		m, p, ok2 := strings.Cut(decoded[:at], ":")
		if !ok2 {
			return fail()
		}
		method, password, hostPort = strings.ToLower(m), p, decoded[at+1:]
	}

	if !ssCiphers[method] || password == "" {
		return fail()
	}
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil || host == "" {
		return fail()
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fail()
	}
	out := map[string]any{
		"type":        "shadowsocks",
		"server":      host,
		"server_port": port,
		"method":      method,
		"password":    password,
	}
	if queryBool(q, "uot") {
		out["udp_over_tcp"] = map[string]any{"enabled": true}
	}
	b, err := json.Marshal(out)
	if err != nil {
		return fail()
	}
	return b, "shadowsocks", fragment, nil
}

func parseTrojanURI(text string) (json.RawMessage, string, string, error) {
	fail := func() (json.RawMessage, string, string, error) {
		return nil, "", "", errors.New("некорректная ссылка Trojan")
	}
	u, err := url.Parse(text)
	if err != nil || u.User == nil {
		return fail()
	}
	password := u.User.Username()
	if pass, ok := u.User.Password(); ok {
		password += ":" + pass
	}
	if password == "" {
		return fail()
	}
	host, port, err := parseHostPort(u, 443)
	if err != nil {
		return fail()
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return fail()
	}
	out := map[string]any{
		"type":        "trojan",
		"server":      host,
		"server_port": port,
		"password":    password,
	}
	tlsObj, err := buildTLSOptions(host, q, "tls")
	if err != nil {
		return fail()
	}
	if tlsObj != nil {
		out["tls"] = tlsObj
	}
	trObj, err := buildV2RayTransport(q)
	if err != nil {
		return fail()
	}
	if trObj != nil {
		out["transport"] = trObj
	}
	b, err := json.Marshal(out)
	if err != nil {
		return fail()
	}
	return b, "trojan", unescapeFragment(u.Fragment), nil
}

func parseSOCKSURI(text string) (json.RawMessage, string, string, error) {
	fail := func() (json.RawMessage, string, string, error) {
		return nil, "", "", errors.New("некорректная ссылка SOCKS5")
	}
	u, err := url.Parse(text)
	if err != nil {
		return fail()
	}
	host, port, err := parseHostPort(u, 0)
	if err != nil {
		return fail()
	}
	out := map[string]any{
		"type":        "socks",
		"version":     "5",
		"server":      host,
		"server_port": port,
	}
	if u.User != nil {
		if pass, hasPass := u.User.Password(); hasPass {
			out["username"] = u.User.Username()
			out["password"] = pass
		} else if rawUser := u.User.Username(); rawUser != "" {
			if decoded, ok := decodeBase64Any(rawUser); ok && strings.Contains(decoded, ":") {
				usr, pwd, _ := strings.Cut(decoded, ":")
				out["username"] = usr
				out["password"] = pwd
			} else {
				out["username"] = rawUser
			}
		}
	}
	b, err := json.Marshal(out)
	if err != nil {
		return fail()
	}
	return b, "socks", unescapeFragment(u.Fragment), nil
}
