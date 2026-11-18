package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestRouterProfileImportsAndRejectsLeaks(t *testing.T) {
	vlessLink := "vless://00000000-0000-4000-8000-000000000001@server.example:443?encryption=none&security=tls&sni=example.org&type=ws&host=example.org&path=%2Fws#name"
	raw, kind, err := importConnection(vlessLink, true)
	if err != nil || kind != "vless" {
		t.Fatal("VLESS import failed", err)
	}
	var node map[string]any
	if json.Unmarshal(raw, &node) != nil || node["server_port"] != float64(443) || node["transport"].(map[string]any)["path"] != "/ws" {
		t.Fatal("transport fields lost")
	}

	hy2Link := "hy2://secret@hy2.example.org:443?sni=hy2.example.org&mport=20000-30000&obfs=salamander&obfs-password=pw#HY2"
	if _, kind, err := importConnection(hy2Link, true); err != nil || kind != "hysteria2" {
		t.Fatal("Hysteria2 import failed", err)
	}

	ssLink := "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pw")) + "@198.51.100.2:8388#SS"
	if _, kind, err := importConnection(ssLink, true); err != nil || kind != "shadowsocks" {
		t.Fatal("Shadowsocks import failed", err)
	}

	trojanLink := "trojan://secret@tr.example.org:443?sni=tr.example.org#TR"
	if _, kind, err := importConnection(trojanLink, true); err != nil || kind != "trojan" {
		t.Fatal("Trojan import failed", err)
	}

	socksLink := "socks5://user:pass@198.51.100.3:1080#S5"
	if _, kind, err := importConnection(socksLink, true); err != nil || kind != "socks" {
		t.Fatal("SOCKS5 import failed", err)
	}

	// Plain WireGuard .conf without Jc/H1..H4 also imports cleanly
	plainWG := "[Interface]\nPrivateKey = cGFzc3dvcmRwYXNzd29yZHBhc3N3b3JkcGFzc3dvcmQ=\nAddress = 10.9.0.2/32\nDNS = 1.1.1.1\n[Peer]\nPublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=\nEndpoint = vpn.example.org:51820\nAllowedIPs = 0.0.0.0/0\n"
	if _, kind, err := importConnection(plainWG, true); err != nil || kind != "amneziawg" {
		t.Fatal("plain WireGuard .conf import failed", err)
	}

	for _, bad := range []string{
		strings.Replace(vlessLink, "#name", "&unknown=private-secret#name", 1),
		"vless://private-secret@bad:port?security=tls",
		"hysteria2://private-secret@example.org:443?obfs=unknown",
		"vmess://private-secret@example.org:443",
		"http://private-secret@example.org:8080",
	} {
		_, _, err := importConnection(bad, true)
		if err == nil || strings.Contains(err.Error(), "private-secret") {
			t.Fatalf("invalid URI accepted or leaked secret: %v", err)
		}
	}
}
