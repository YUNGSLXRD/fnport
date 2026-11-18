package vpn

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	testPrivKey = "cGf4bH9iL2jN5pQ8rS1tU4vW7xY0zA3bC6dE9fG2hI4="
	testPubKey  = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
)

func TestParseWGAndAWGConf(t *testing.T) {
	// Plain WireGuard config with ListenPort, DNS, Table, PreUp, PostDown
	plainWG := `# Standard WireGuard export
[Interface]
PrivateKey = ` + testPrivKey + `
Address = 10.66.66.2/32, fd42:42:42::2/128
ListenPort = 51820
DNS = 1.1.1.1, 1.0.0.1
Table = auto
SaveConfig = false

[Peer]
PublicKey = ` + testPubKey + `
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`
	cfg, err := ParseWGConf(plainWG)
	if err != nil {
		t.Fatalf("ParseWGConf plain WG failed: %v", err)
	}
	if cfg.Address != "10.66.66.2" || cfg.Endpoint != "vpn.example.com:51820" || cfg.Jc != 0 {
		t.Fatalf("unexpected plain WG config: %+v", cfg)
	}
	if cfg.H1 != "1" || cfg.H2 != "2" || cfg.H3 != "3" || cfg.H4 != "4" {
		t.Fatalf("unexpected default H1..H4: %+v", cfg)
	}

	// AmneziaWG 1.5 config with empty I2..I5 lines (as Amnezia exports)
	awgConf := `[Interface]
PrivateKey = ` + testPrivKey + `
Address = 172.16.0.2/32
Jc = 4
Jmin = 40
Jmax = 70
S1 = 15
S2 = 25
H1 = 101
H2 = 102
H3 = 103
H4 = 104
I1 = <b 0xc700000001>
I2 = 
I3 =
I4 = 
I5 =

[Peer]
PublicKey = ` + testPubKey + `
Endpoint = 198.51.100.10:443
AllowedIPs = 0.0.0.0/0
`
	awg, err := ParseWGConf(awgConf)
	if err != nil {
		t.Fatalf("ParseWGConf AWG with empty I2..I5 failed: %v", err)
	}
	if awg.Jc != 4 || awg.I1 != "<b 0xc700000001>" || awg.I2 != "" {
		t.Fatalf("unexpected AWG config: %+v", awg)
	}

	// AmneziaWG 2.0 / 3.0 config with S3, S4, H1..H4 ranges, <rc>/<rd>, HeaderProtectionKey, ContentPaddingAddition
	awg3Conf := `[Interface]
PrivateKey = ` + testPrivKey + `
Address = 10.8.1.2/32
Jc = 5
Jmin = 64
Jmax = 256
S1 = 24
S2 = 32
S3 = 16
S4 = 20
H1 = 100000-199999
H2 = 200000-299999
H3 = 300000-399999
H4 = 400000-499999
HeaderProtectionKey = ` + testPrivKey + `
ContentPaddingAddition = 0-64
RandomTrailers = true
DisableCookies = true
I1 = <b 0xc000000001><rc 12><rd 8><t>

[Peer]
PublicKey = ` + testPubKey + `
Endpoint = 198.51.100.20:443
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 15-25
`
	awg3, err := ParseWGConf(awg3Conf)
	if err != nil {
		t.Fatalf("ParseWGConf AWG 2.0/3.0 failed: %v", err)
	}
	if awg3.S3 != 16 || awg3.S4 != 20 || awg3.H1 != "100000-199999" || !awg3.RandomTrailers || !awg3.DisableCookies || awg3.KeepaliveRange != "15-25" {
		t.Fatalf("unexpected AWG 2.0/3.0 parsed fields: %+v", awg3)
	}
	rawAWG3, err := json.Marshal(awg3)
	if err != nil {
		t.Fatalf("Marshal AWG 2.0/3.0 failed: %v", err)
	}
	roundtripAWG3, err := ParseAWGJSON(rawAWG3)
	if err != nil || roundtripAWG3.H2 != "200000-299999" || roundtripAWG3.ContentPaddingAddition != "0-64" {
		t.Fatalf("AWG 2.0/3.0 JSON roundtrip failed: %v %+v", err, roundtripAWG3)
	}
	// Overlapping H1/H2 ranges must be rejected
	badOverlap := roundtripAWG3
	badOverlap.H2 = "150000-250000"
	if badOverlap.Validate(true) == nil {
		t.Fatal("overlapping H1/H2 ranges were accepted")
	}
	// HeaderProtectionKey requires S1..S4 >= 12
	badPadding := roundtripAWG3
	badPadding.S3 = 8
	if badPadding.Validate(true) == nil {
		t.Fatal("HeaderProtectionKey with S3 < 12 was accepted")
	}

	// WARP config fills default Jc/Jmin/Jmax and clears engage.cloudflareclient.com
	warpPlain := `[Interface]
PrivateKey = ` + testPrivKey + `
Address = 172.16.0.2/32
[Peer]
PublicKey = ` + testPubKey + `
Endpoint = engage.cloudflareclient.com:2408
`
	wcfg, err := ParseWARPConf(warpPlain, 4, 40, 70)
	if err != nil {
		t.Fatalf("ParseWARPConf failed: %v", err)
	}
	if wcfg.Jc != 4 || wcfg.Jmin != 40 || wcfg.Jmax != 70 || wcfg.Endpoint != "" {
		t.Fatalf("unexpected WARP defaults: %+v", wcfg)
	}
}

func TestImportAllSupportedURIs(t *testing.T) {
	cases := []struct {
		name  string
		uri   string
		proto string
		title string
	}{
		{
			name:  "VLESS Reality",
			uri:   "vless://11111111-2222-3333-4444-555555555555@example.com:443?security=reality&sni=www.microsoft.com&fp=chrome&pbk=testpbk&sid=01ab&type=tcp&flow=xtls-rprx-vision&spx=%2F#DE%20Frankfurt",
			proto: "vless",
			title: "DE Frankfurt",
		},
		{
			name:  "VLESS WS EarlyData",
			uri:   "vless://11111111-2222-3333-4444-555555555555@cdn.example.com:443?security=tls&type=ws&host=ws.example.com&path=%2Fws%3Fed%3D2048#NL%20WS",
			proto: "vless",
			title: "NL WS",
		},
		{
			name:  "Hysteria2 Salamander PortHop",
			uri:   "hy2://secretpass@hy2.example.com:443?sni=hy2.example.com&obfs=salamander&obfs-password=obfspw&mport=20000-40000&upmbps=100&downmbps=200#FI%20Helsinki",
			proto: "hysteria2",
			title: "FI Helsinki",
		},
		{
			name:  "Shadowsocks SIP002",
			uri:   "ss://" + base64.RawURLEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:mysecret")) + "@198.51.100.5:8388/#Outline%20Server",
			proto: "shadowsocks",
			title: "Outline Server",
		},
		{
			name:  "Shadowsocks 2022 Plain",
			uri:   "ss://2022-blake3-aes-128-gcm:AAECAwQFBgcICQoLDA0ODw%3D%3D@198.51.100.6:8388?uot=1#SS2022",
			proto: "shadowsocks",
			title: "SS2022",
		},
		{
			name:  "Trojan gRPC",
			uri:   "trojan://trojanpass@tr.example.com:443?security=tls&sni=tr.example.com&type=grpc&serviceName=gunService#SE%20Trojan",
			proto: "trojan",
			title: "SE Trojan",
		},
		{
			name:  "SOCKS5 Auth",
			uri:   "socks5://alice:wonderland@198.51.100.7:1080#SOCKS%20Node",
			proto: "socks",
			title: "SOCKS Node",
		},
	}

	for _, tc := range cases {
		raw, proto, name, err := ImportProfile(tc.uri, true)
		if err != nil {
			t.Fatalf("%s failed: %v", tc.name, err)
		}
		if proto != tc.proto || name != tc.title {
			t.Fatalf("%s got proto=%q name=%q, want %q / %q", tc.name, proto, name, tc.proto, tc.title)
		}
		var obj map[string]any
		if err := json.Unmarshal(raw, &obj); err != nil {
			t.Fatalf("%s invalid JSON: %v", tc.name, err)
		}
		if tc.proto == "hysteria2" {
			ports, ok := obj["server_ports"].([]any)
			if !ok || len(ports) != 1 || ports[0] != "20000:40000" {
				t.Fatalf("expected server_ports [20000:40000], got %v", obj["server_ports"])
			}
		}
	}

	// Reject TCP-only / unsafe schemes and local file paths in JSON
	for _, bad := range []string{
		"http://proxy.example.com:8080",
		"ssh://user@example.com:22",
		`{"type":"vless","server":"1.2.3.4","server_port":443,"uuid":"1111","tls":{"enabled":true,"certificate_path":"/etc/passwd"}}`,
		`{"type":"naive","server":"1.2.3.4","server_port":443}`,
	} {
		if _, _, _, err := ImportProfile(bad, true); err == nil {
			t.Fatalf("expected error for unsupported/unsafe input")
		}
	}
}

func TestSubscriptionAndDisplayNodeName(t *testing.T) {
	lines := "vless://11111111-2222-3333-4444-555555555555@de.example.com:443?security=tls#\U0001F1E9\U0001F1EA%20%D0%93%D0%B5%D1%80%D0%BC%D0%B0%D0%BD%D0%B8%D1%8F%20%231\n" +
		"hy2://pw@nl.example.com:443?sni=nl.example.com#Amsterdam%20Fast\n" +
		"http://unsupported.example.com:8080#SkipMe\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(lines))
	nodes, skipped, err := ParseSubscription([]byte(encoded))
	if err != nil {
		t.Fatalf("ParseSubscription failed: %v", err)
	}
	if len(nodes) != 2 || skipped != 1 {
		t.Fatalf("got %d nodes, %d skipped; want 2, 1", len(nodes), skipped)
	}
	clean1, cc1 := DisplayNodeName(nodes[0].Name)
	if cc1 != "DE" || clean1 != "Германия #1" {
		t.Fatalf("got clean=%q cc=%q, want 'Германия #1' / 'DE'", clean1, cc1)
	}
	clean2, cc2 := DisplayNodeName(nodes[1].Name)
	if cc2 != "NL" || clean2 != "Amsterdam Fast" {
		t.Fatalf("got clean=%q cc=%q, want 'Amsterdam Fast' / 'NL'", clean2, cc2)
	}
}

func TestBeaconExclusionAndLeaseCache(t *testing.T) {
	if !MatchEpic("account-public-service-prod.ol.epicgames.com", nil) {
		t.Fatal("expected Epic account service to match")
	}
	if MatchEpic("ping-eu.ds.on.epicgames.com", nil) {
		t.Fatal("Epic QoS beacon must never match tunnel domain list")
	}

	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7, Response: true, RCode: dnsmessage.RCodeSuccess})
	_ = b.StartQuestions()
	name, _ := dnsmessage.NewName("discord.com.")
	_ = b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	_ = b.StartAnswers()
	_ = b.AResource(dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 300}, dnsmessage.AResource{A: [4]byte{162, 159, 135, 232}})
	wire, _ := b.Finish()

	var cache LeaseCache
	now := time.Now()
	added := cache.Learn("discord", wire, now)
	if len(added) != 1 || added[0] != netip.MustParseAddr("162.159.135.232") {
		t.Fatalf("expected 1 newly learned IP, got %v", added)
	}
	if _, changed := cache.Snapshot(now); !changed {
		t.Fatal("expected initial snapshot to report changed=true")
	}
	// Learning the same IP 5 seconds later must not trigger a redundant dirty flush
	added2 := cache.Learn("discord", wire, now.Add(5*time.Second))
	if len(added2) != 0 {
		t.Fatalf("expected 0 new IPs on repeat DNS query, got %v", added2)
	}
	if _, changed := cache.Snapshot(now.Add(5 * time.Second)); changed {
		t.Fatal("repeat DNS query within TTL window must not mark LeaseCache dirty")
	}
	if got := cache.ServiceOf(netip.MustParseAddr("162.159.135.232")); got != "discord" {
		t.Fatalf("ServiceOf = %q, want discord", got)
	}
}

func TestExtractEndpointAndExitFormatting(t *testing.T) {
	vlessRaw, proto, _, err := ImportProfile("vless://11111111-2222-3333-4444-555555555555@nl.example.com:8443?security=reality&pbk=test&sni=www.microsoft.com#NL", true)
	if err != nil {
		t.Fatal(err)
	}
	host, port, udpOnly, ok := ExtractServerEndpoint(proto, vlessRaw, "")
	if !ok || host != "nl.example.com" || port != 8443 || udpOnly {
		t.Fatalf("ExtractServerEndpoint VLESS: ok=%v host=%q port=%d udpOnly=%v", ok, host, port, udpOnly)
	}

	hy2Raw, hyProto, _, err := ImportProfile("hy2://secret@de.example.com:443?sni=de.example.com#DE", true)
	if err != nil {
		t.Fatal(err)
	}
	host2, port2, udpOnly2, ok2 := ExtractServerEndpoint(hyProto, hy2Raw, "")
	if !ok2 || host2 != "de.example.com" || port2 != 443 || !udpOnly2 {
		t.Fatalf("ExtractServerEndpoint HY2: ok=%v host=%q port=%d udpOnly=%v", ok2, host2, port2, udpOnly2)
	}

	loc := FormatExitLocation(ExitReport{Country: "NL", City: "Amsterdam"}, false)
	if loc != "Амстердам, Нидерланды" {
		t.Fatalf("FormatExitLocation = %q, want 'Амстердам, Нидерланды'", loc)
	}
	locSG := FormatExitLocation(ExitReport{Country: "SG", City: "Singapore"}, false)
	if locSG != "Сингапур" {
		t.Fatalf("FormatExitLocation SG = %q, want 'Сингапур'", locSG)
	}
	locWARP := FormatExitLocation(ExitReport{Colo: "RIX", Country: "LV"}, true)
	if locWARP != "Рига (RIX), Латвия" {
		t.Fatalf("FormatExitLocation WARP = %q, want 'Рига (RIX), Латвия'", locWARP)
	}

	rtt, err := PingEndpoint(
		context.Background(),
		netip.MustParseAddrPort("198.51.100.10:443"),
		false,
		func(ctx context.Context, ap netip.AddrPort) (net.Conn, error) {
			time.Sleep(3 * time.Millisecond)
			c1, c2 := net.Pipe()
			_ = c2.Close()
			return c1, nil
		},
		nil,
	)
	if err != nil || rtt < time.Millisecond {
		t.Fatalf("PingEndpoint failed: rtt=%v err=%v", rtt, err)
	}
}
