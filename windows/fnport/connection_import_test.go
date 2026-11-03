package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/YUNGSLXRD/fnport/windows/internal/wnet"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strconv"
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

func TestImportedVLESSRoundTrip(t *testing.T) {
	core := os.Getenv("FNPORT_TEST_SING_BOX")
	if core == "" {
		t.Skip("native core not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	reserve, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reserve.Addr().(*net.TCPAddr).Port
	reserve.Close()
	uuid := "00000000-0000-4000-8000-000000000001"
	config, _ := json.Marshal(map[string]any{"log": map[string]any{"disabled": true}, "inbounds": []any{map[string]any{"type": "vless", "listen": "127.0.0.1", "listen_port": port, "users": []any{map[string]any{"uuid": uuid}}}}, "outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}}, "route": map[string]any{"final": "direct"}})
	server := exec.CommandContext(ctx, core, "run", "-c", "stdin")
	server.Stdin = bytes.NewReader(config)
	server.Stdout = io.Discard
	server.Stderr = io.Discard
	server.WaitDelay = time.Second
	if err := server.Start(); err != nil {
		t.Fatal("test VLESS server did not start")
	}
	defer func() { cancel(); server.Wait() }()
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	ready := false
	for i := 0; i < 100; i++ {
		c, e := net.DialTimeout("tcp4", address, 50*time.Millisecond)
		if e == nil {
			c.Close()
			ready = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ready {
		t.Fatal("test VLESS listener unavailable")
	}
	raw, _, err := importConnection("vless://"+uuid+"@"+address+"?security=none&type=tcp", true)
	if err != nil {
		t.Fatal(err)
	}
	client, err := startConnectionCommand(ctx, connectionSettings{Enabled: true, Protocol: "vless", Config: raw, Epic: true, Discord: true}, "lo0", func(ctx context.Context, args ...string) *exec.Cmd { return exec.CommandContext(ctx, core, args...) })
	if err != nil {
		t.Fatal("imported VLESS client did not start", err)
	}
	defer client.close()
	tcpEcho, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpEcho.Close()
	go func() {
		c, e := tcpEcho.Accept()
		if e == nil {
			io.Copy(c, c)
			c.Close()
		}
	}()
	dst := tcpEcho.Addr().(*net.TCPAddr).AddrPort()
	tcpConn, err := client.dial(ctx, dst)
	if err != nil {
		t.Fatal("TCP via VLESS", err)
	}
	defer tcpConn.Close()
	tcpConn.SetDeadline(time.Now().Add(3 * time.Second))
	payload := []byte("Epic service test")
	tcpConn.Write(payload)
	back := make([]byte, len(payload))
	if _, err := io.ReadFull(tcpConn, back); err != nil || !bytes.Equal(back, payload) {
		t.Fatal("VLESS TCP roundtrip failed", err)
	}
	udpEcho, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udpEcho.Close()
	go func() {
		b := make([]byte, 2048)
		for {
			n, p, e := udpEcho.ReadFromUDP(b)
			if e != nil {
				return
			}
			udpEcho.WriteToUDP(b[:n], p)
		}
	}()
	udpConn, err := client.udp(ctx, udpEcho.LocalAddr().(*net.UDPAddr).AddrPort())
	if err != nil {
		t.Fatal("UDP via VLESS", err)
	}
	defer udpConn.Close()
	udpConn.SetDeadline(time.Now().Add(3 * time.Second))
	payload = []byte("Discord voice test")
	udpConn.Write(payload)
	back = make([]byte, 128)
	n, err := udpConn.Read(back)
	if err != nil || !bytes.Equal(back[:n], payload) {
		t.Fatal("VLESS UDP roundtrip failed", err)
	}
	direct, err := net.DialUDP("udp4", nil, udpEcho.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Close()
	direct.SetDeadline(time.Now().Add(5 * time.Second))
	directTimes := make([]time.Duration, 0, 100)
	for i := 0; i < 100; i++ {
		start := time.Now()
		direct.Write([]byte("ping"))
		if _, e := direct.Read(back); e != nil {
			t.Fatal(e)
		}
		directTimes = append(directTimes, time.Since(start))
	}
	dev := newChanDev()
	cfg := testConfig()
	cfg.captureAll = true
	engine := newEngine(cfg, dev, clientIP, &tcpRelay{ctx: ctx})
	defer engine.close()
	router := &connectionRouter{settings: connectionSettings{Enabled: true, Protocol: "vless", Discord: true}, transport: client, trace: &networkTrace{}}
	router.ownerLookup = func(uint8, netip.AddrPort, netip.AddrPort) (wnet.ProcessOwner, error) {
		return wnet.ProcessOwner{Name: "Discord.exe", PID: 1}, nil
	}
	engine.connection = router
	go engine.run()
	dstUDP := udpEcho.LocalAddr().(*net.UDPAddr).AddrPort()
	srcUDP := netip.AddrPortFrom(clientIP, 55000)
	fullTimes := make([]time.Duration, 0, 100)
	for i := 0; i < 110; i++ {
		start := time.Now()
		dev.in <- wnet.BuildUDP4(srcUDP, dstUDP, []byte("ping"), uint16(i))
		select {
		case <-dev.out:
			if i >= 10 {
				fullTimes = append(fullTimes, time.Since(start))
			}
		case <-time.After(time.Second):
			t.Fatal("engine latency sample timed out")
		}
	}
	sort.Slice(directTimes, func(i, j int) bool { return directTimes[i] < directTimes[j] })
	sort.Slice(fullTimes, func(i, j int) bool { return fullTimes[i] < fullTimes[j] })
	f := flowOf(engine, 55000, dstUDP)
	if f == nil {
		t.Fatal("voice flow missing")
	}
	t.Logf("Local echo, 100 samples: direct median=%s p95=%s; fnport+SOCKS+VLESS median=%s p95=%s; max fnport queue=%s max socket write=%s", directTimes[50], directTimes[95], fullTimes[50], fullTimes[95], time.Duration(f.queueMaxNS.Load()), time.Duration(f.writeMaxNS.Load()))

}
