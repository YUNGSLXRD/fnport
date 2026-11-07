package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRouterVLESSImport(t *testing.T) {
	link := "vless://00000000-0000-4000-8000-000000000001@server.example:443?encryption=none&security=tls&sni=example.org&type=ws&host=example.org&path=%2Fws#name"
	raw, kind, err := importConnection(link, true)
	if err != nil || kind != "vless" {
		t.Fatal("VLESS import failed", err)
	}
	var node map[string]any
	if json.Unmarshal(raw, &node) != nil || node["server_port"] != float64(443) || node["transport"].(map[string]any)["path"] != "/ws" {
		t.Fatal("transport fields lost")
	}
	for _, bad := range []string{strings.Replace(link, "#name", "&unknown=private-secret#name", 1), "vless://private-secret@bad:port?security=tls", "hysteria2://private-secret@example.org:443"} {
		_, _, err := importConnection(bad, true)
		if err == nil || strings.Contains(err.Error(), "private-secret") {
			t.Fatal("invalid URI accepted or leaked")
		}
	}
}
