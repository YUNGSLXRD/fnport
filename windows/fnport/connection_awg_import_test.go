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
	if s.Address != "10.9.0.2" || s.Endpoint != "vpn.example.org:51820" || s.MTU != 1420 || s.H1 != "123456789" || s.S1 != 15 || s.Keepalive == nil || *s.Keepalive != 0 || s.PresharedKey == "" || s.I1 != "<b 0x0102>" {
		t.Fatal("import lost protocol parameters")
	}
	settings := defaultSettings()
	settings.Connection.Enabled = true
	settings.Connection.Protocol = "amneziawg"
	var cv connectionView
	cv.load(settings)
	if cv.config.SingleLine {
		t.Fatal("conf editor strips line breaks")
	}
	cv.config.SetText(sampleAWGConf)
	connection, _, err := cv.draft()
	if err != nil || connection.Protocol != "amneziawg" || connection.validate() != nil {
		t.Fatal("UI cannot apply conf", err)
	}
}

func TestImportAmneziaWG2And3Conf(t *testing.T) {
	awg23 := strings.NewReplacer(
		"S2 = 20", "S2 = 20\nS3 = 18\nS4 = 24\nHeaderProtectionKey = cGFzc3dvcmRwYXNzd29yZHBhc3N3b3JkcGFzc3dvcmQ=\nContentPaddingAddition = 0-32\nRandomTrailers = true",
		"H1 = 123456789", "H1 = 100000-199999",
		"H2 = 234567890", "H2 = 200000-299999",
		"H3 = 345678901", "H3 = 300000-399999",
		"H4 = 456789012", "H4 = 400000-499999",
		"I1 = <b 0x0102>", "I1 = <b 0x0102><rc 8><rd 4>",
	).Replace(sampleAWGConf)
	raw, err := importAWGConf(awg23)
	if err != nil {
		t.Fatalf("AWG 2.0/3.0 import failed: %v", err)
	}
	s, err := parseNativeAWG(raw)
	if err != nil || s.S3 != 18 || s.S4 != 24 || s.H1 != "100000-199999" || !s.RandomTrailers {
		t.Fatalf("AWG 2.0/3.0 parameters lost: %v %+v", err, s)
	}
}

func TestImportAmneziaWGConfRejectsUnsupportedWithoutLeaks(t *testing.T) {
	for _, replace := range []struct{ old, new string }{
		{"Jc = 4", "Jc = private-secret"}, {"[Peer]", "[Peer]\nPostUp = private-secret"},
		{"H1 = 123456789", "H1 = 123-456-private-secret"}, {"S1 = 15", "S3 = 2000"},
		{"Endpoint = vpn.example.org:51820", "Endpoint = private-secret:bad"},
		{"[Peer]", "[Peer]\n[Peer]"}, {"MTU = 1420", "MTU = 1500"},
	} {
		_, err := importAWGConf(strings.Replace(sampleAWGConf, replace.old, replace.new, 1))
		if err == nil || strings.Contains(err.Error(), "private-secret") {
			t.Fatal("accepted malformed config or leaked input", err)
		}
	}
}
