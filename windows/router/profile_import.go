package main

import (
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"strings"
)

// Never include input or URL parser diagnostics in an error: links contain keys.
func importConnection(text string, required bool) (json.RawMessage, string, error) {
	text = strings.TrimSpace(text)
	if looksLikeAWGConf(text) {
		raw, err := importAWGConf(text)
		return raw, "amneziawg", err
	}
	if !strings.Contains(text, "://") {
		b, e := connectionConfigJSON(text, required)
		return b, "", e
	}
	fail := func() (json.RawMessage, string, error) {
		return nil, "", errors.New("ссылка не поддерживается или содержит неизвестные настройки; для сложных конфигураций используйте JSON")
	}
	u, e := url.Parse(text)
	if e != nil || u.User == nil || u.Hostname() == "" {
		return fail()
	}
	if u.Scheme != "vless" {
		return fail()
	}
	port, e := strconv.Atoi(u.Port())
	if e != nil || port < 1 || port > 65535 {
		return fail()
	}
	q, e := url.ParseQuery(u.RawQuery)
	if e != nil {
		return fail()
	}
	allowed := strings.Fields("encryption security sni fp pbk sid spx type host path serviceName alpn flow headerType allowInsecure insecure packetEncoding")
	for k, values := range q {
		ok := false
		for _, a := range allowed {
			if a == k {
				ok = true
			}
		}
		if !ok || len(values) != 1 {
			return fail()
		}
	}
	if q.Get("encryption") != "" && q.Get("encryption") != "none" {
		return fail()
	}
	if q.Get("headerType") != "" && q.Get("headerType") != "none" {
		return fail()
	}
	o := map[string]any{"type": "vless", "server": u.Hostname(), "server_port": port, "uuid": u.User.Username()}
	if _, present := u.User.Password(); present {
		return fail()
	}
	if f := q.Get("flow"); f != "" {
		o["flow"] = f
	}
	if p := q.Get("packetEncoding"); p != "" {
		o["packet_encoding"] = p
	}
	sec := q.Get("security")
	switch sec {
	case "", "none":
	case "tls", "reality":
		tls := map[string]any{"enabled": true}
		name := q.Get("sni")
		if name == "" {
			name = u.Hostname()
		}
		tls["server_name"] = name
		if a := q.Get("alpn"); a != "" {
			tls["alpn"] = strings.Split(a, ",")
		}
		fp := q.Get("fp")
		if sec == "reality" && fp == "" {
			fp = "chrome"
		}
		if fp != "" {
			tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
		}
		if sec == "reality" {
			if q.Get("pbk") == "" {
				return fail()
			}
			tls["reality"] = map[string]any{"enabled": true, "public_key": q.Get("pbk"), "short_id": q.Get("sid")}
		}
		if q.Get("allowInsecure") == "1" || q.Get("insecure") == "1" {
			tls["insecure"] = true
		}
		o["tls"] = tls
	default:
		return fail()
	}
	switch typ := q.Get("type"); typ {
	case "", "tcp", "raw":
	case "ws", "httpupgrade":
		t := map[string]any{"type": typ}
		if p := q.Get("path"); p != "" {
			t["path"] = p
		}
		if h := q.Get("host"); h != "" {
			t["headers"] = map[string]string{"Host": h}
		}
		o["transport"] = t
	case "grpc":
		o["transport"] = map[string]any{"type": "grpc", "service_name": q.Get("serviceName")}
	default:
		return fail()
	}
	b, e := json.Marshal(o)
	return b, "vless", e
}

func connectionConfigJSON(text string, required bool) (json.RawMessage, error) {
	text = strings.TrimSpace(text)
	if text == "" && !required {
		return nil, nil
	}
	if !json.Valid([]byte(text)) || !strings.HasPrefix(text, "{") || len(text) > 1<<20 {
		return nil, errors.New("invalid profile JSON")
	}
	return json.RawMessage(text), nil
}
