package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/YUNGSLXRD/fnport/windows/internal/wnet"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestImportVLESSAndEpicSelection(t *testing.T) {
	link := "vless://00000000-0000-4000-8000-000000000001@127.0.0.1:443?encryption=none&security=tls&sni=example.org&type=ws&host=example.org&path=%2Fws#test"
	raw, typ, err := importConnection(link, true)
	if err != nil || typ != "vless" {
		t.Fatal("link import failed")
	}
	var m map[string]any
	json.Unmarshal(raw, &m)
	if m["server_port"] != float64(443) || m["transport"].(map[string]any)["path"] != "/ws" {
		t.Fatal("transport fields lost")
	}
	cv := connectionView{}
	s := defaultSettings()
	s.Connection.Protocol = "vless"
	cv.load(s)
	cv.enabled.Value = true
	cv.epic.Value = true
	cv.config.SetText(link)
	c, _, err := cv.draft()
	if err != nil || !c.Epic || c.Protocol != "vless" {
		t.Fatal("Epic not selected", err)
	}
	if !c.selects(wnet.ProcessOwner{}, "accounts.epicgames.com") || c.selects(wnet.ProcessOwner{}, "epicgames.com.other.test") {
		t.Fatal("incorrect Epic domain match")
	}
	for _, bad := range []string{strings.Replace(link, "#test", "&secret=bad", 1), strings.Replace(link, "type=ws", "type=xhttp", 1), "vless://sensitive@invalid"} {
		_, _, e := importConnection(bad, true)
		if e == nil || strings.Contains(e.Error(), "sensitive") {
			t.Fatal("unsupported or leaked link")
		}
	}
}

func TestImportVLESSRealCoreCheck(t *testing.T) {
	core := os.Getenv("FNPORT_TEST_SING_BOX")
	if core == "" {
		t.Skip("native core not configured")
	}
	for _, security := range []string{"security=tls&type=ws&host=example.org&path=%2Fws", "security=reality&type=tcp&fp=chrome&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=abcd"} {
		raw, _, err := importConnection("vless://00000000-0000-4000-8000-000000000001@localhost:443?encryption=none&sni=example.org&"+security, true)
		if err != nil {
			t.Fatal(err)
		}
		b, _, err := connectionConfig(connectionSettings{Enabled: true, Protocol: "vless", Config: raw, Epic: true}, "lo0", 12000, "user", "pass")
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		cmd := exec.CommandContext(ctx, core, "check", "-c", "stdin")
		cmd.Stdin = bytes.NewReader(b)
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		err = cmd.Run()
		cancel()
		if err != nil {
			t.Fatal("core rejected imported VLESS configuration")
		}
	}
}
