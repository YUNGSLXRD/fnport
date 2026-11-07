package main

import (
	"strings"
	"testing"
)

const sampleAWGConf = `# exported config
[Interface]
PrivateKey = cGFzc3dvcmRwYXNzd29yZHBhc3N3b3JkcGFzc3dvcmQ=
Address = 10.9.0.2/32, fd00::2/128
DNS = 1.1.1.1, 8.8.8.8
MTU = 1420
Jc = 4
Jmin = 40
Jmax = 70
S1 = 15
S2 = 20
H1 = 123456789
H2 = 234567890
H3 = 345678901
H4 = 456789012
I1 = <b 0x0102>
[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
PresharedKey = cGFzc3dvcmRwYXNzd29yZHBhc3N3b3JkcGFzc3dvcmQ=
Endpoint = vpn.example.org:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 0
`

func TestImportAmneziaWGConf(t *testing.T) {
	raw, protocol, err := importConnection(strings.ReplaceAll(sampleAWGConf, "\n", "\r\n"), true)
	if err != nil || protocol != "amneziawg" {
		t.Fatal("conf not imported", err)
	}
	s, err := parseNativeAWG(raw)
	if err != nil {
		t.Fatal(err)
	}
	if s.Address != "10.9.0.2" || s.Endpoint != "vpn.example.org:51820" || s.MTU != 1420 || s.H1 != 123456789 || s.S1 != 15 || s.Keepalive == nil || *s.Keepalive != 0 || s.PresharedKey == "" || s.I1 != "<b 0x0102>" {
		t.Fatal("import lost protocol parameters")
	}
}

func TestImportAmneziaWGConfRejectsUnsupportedWithoutLeaks(t *testing.T) {
	for _, replace := range []struct{ old, new string }{
		{"Jc = 4", "Jc = private-secret"}, {"[Peer]", "[Peer]\nPostUp = private-secret"},
		{"H1 = 123456789", "H1 = 123-456-private-secret"}, {"S1 = 15", "S3 = 30"},
		{"Endpoint = vpn.example.org:51820", "Endpoint = private-secret:bad"},
		{"[Peer]", "[Peer]\n[Peer]"}, {"MTU = 1420", "MTU = 1500"},
	} {
		_, err := importAWGConf(strings.Replace(sampleAWGConf, replace.old, replace.new, 1))
		if err == nil || strings.Contains(err.Error(), "private-secret") {
			t.Fatal("accepted malformed config or leaked input", err)
		}
	}
}

func TestRouterPacketTemplatesAreBoundedBeforeNativeParser(t *testing.T) {
	for _, input := range []string{"<r -1>", "<r 1001>", "<>", "<1>", "<b 0xzz>", "<c><c>", "<wt -1><r 4>", "<wt 4000><wt 4000><r 1>", "<r 1000><r 1000>", "prefix<r 1>"} {
		if validPacketTemplate(input) {
			t.Fatal("unsafe template accepted")
		}
	}
	for _, input := range []string{"<b 0x1234><r 100><c><t>", "<r 1>", "<wt 15><b 0xF>"} {
		if !validPacketTemplate(input) {
			t.Fatal("valid template rejected")
		}
	}
}
