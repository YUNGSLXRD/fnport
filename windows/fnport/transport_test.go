package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func transportSettings(raw string) connectionSettings {
	return connectionSettings{Enabled: true, Protocol: "custom", Config: json.RawMessage(raw)}
}
func TestTransportConfigOwnership(t *testing.T) {
	s := transportSettings(`{"outbounds":[{"type":"vless","tag":"chosen","bind_interface":"wrong","uuid":"secret","transport":{"type":"ws","path":"/keep"},"future":{"opaque":123}}],"dns":{"servers":[{"type":"udp","tag":"d","server":"1.1.1.1","bind_interface":"wrong"}]},"future_top":{"keep":true}}`)
	s.Final = "chosen"
	b, udp, err := connectionConfig(s, "Ethernet", 12345, "user", "pass")
	if err != nil || !udp {
		t.Fatalf("compile: %v, udp=%v", err, udp)
	}
	var root map[string]any
	if err = json.Unmarshal(b, &root); err != nil {
		t.Fatal(err)
	}
	route := root["route"].(map[string]any)
	if route["final"] != "chosen" || route["default_interface"] != "Ethernet" || len(route) != 3 {
		t.Fatal(route)
	}
	out := root["outbounds"].([]any)[0].(map[string]any)
	if out["bind_interface"] != "Ethernet" || out["future"].(map[string]any)["opaque"] != float64(123) {
		t.Fatal(out)
	}
	dns := root["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
	if dns["bind_interface"] != "Ethernet" {
		t.Fatal(dns)
	}
	in := root["inbounds"].([]any)[0].(map[string]any)
	if in["type"] != "socks" || in["listen"] != "127.0.0.1" || root["future_top"] == nil {
		t.Fatal("lost ownership or unknown config")
	}
	if !bytes.Contains(s.Config, []byte("wrong")) {
		t.Fatal("mutated raw settings")
	}
}
func TestTransportValidate(t *testing.T) {
	for _, raw := range []string{
		`null`, `[]`, `{"type":"http"} {}`,
		`{"type":"http","listen":"0.0.0.0"}`,
		`{"outbounds":[],"route":{}}`,
		`{"outbounds":[],"inbounds":[]}`,
		`{"type":"http","experimental":{"clash_api":{"external_controller":"secret"}}}`,
		`{"type":"wireguard","system_interface":true}`,
		`{"type":"wireguard","system":true}`,
		`{"type":"http","tls":{"listen_port":1}}`,
		`{"type":"http","netns":"secret"}`,
		`{"outbounds":[{"type":"http","tag":"x"},{"type":"http","tag":"x"}]}`,
	} {
		s := transportSettings(raw)
		s.Final = "x"
		if err := s.validate(); err == nil {
			t.Fatalf("accepted %s", raw)
		} else if strings.Contains(err.Error(), "secret") {
			t.Fatal("secret diagnostic")
		}
	}
	s := transportSettings(`broken secret`)
	s.Enabled = false
	if err := s.validate(); err != nil {
		t.Fatal("disabled draft rejected")
	}
	s.Enabled = true
	s.Protocol = "warp"
	if err := s.validate(); err != nil {
		t.Fatal("native warp rejected")
	}
	for _, typ := range []string{"http", "ssh", "tor", "shadowtls", "naive"} {
		s = transportSettings(`{"type":"` + typ + `"}`)
		s.Discord = true
		if err := s.validate(); err == nil {
			t.Fatal("TCP-only voice accepted:", typ)
		}
	}
	s = transportSettings(`{"type":"new-protocol","unknown":{"new":true}}`)
	if err := s.validate(); err != nil {
		t.Fatal("future custom protocol rejected:", err)
	}
	_, udp, err := connectionConfig(s, "eth", 1, "u", "p")
	if err != nil || udp {
		t.Fatal("unknown UDP advertised")
	}
	s = transportSettings(`{"endpoints":[{"type":"wireguard","tag":"wg","system_interface":false,"peers":[]} ]}`)
	s.Final = "wg"
	s.Discord = true
	if err := s.validate(); err != nil {
		t.Fatal("userspace endpoint:", err)
	}
	s = transportSettings(`{"outbounds":[{"type":"selector","tag":"sel","outbounds":["tcp","udp"]},{"type":"http","tag":"tcp"},{"type":"direct","tag":"udp"}]}`)
	s.Final = "sel"
	s.Discord = true
	if err := s.validate(); err == nil {
		t.Fatal("mixed selector advertised UDP")
	}
	s = transportSettings(`{"type":"http"}`)
	s.Protocol = "vless"
	if err := s.validate(); err == nil {
		t.Fatal("protocol mismatch accepted")
	}
	s = transportSettings(`{"outbounds":[{"type":"direct","tag":"one"}]}`)
	if err := s.validate(); err == nil {
		t.Fatal("implicit final accepted")
	}
}

type transportMock struct {
	listener                             net.Listener
	sockets                              sync.Map
	relay                                *net.UDPConn
	badAuth, noAuth, reject, remoteRelay bool
	alter                                byte
}

func newTransportMock(t *testing.T) *transportMock {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		l.Close()
		t.Fatal(err)
	}
	m := &transportMock{listener: l, relay: relay}
	t.Cleanup(func() {
		l.Close()
		relay.Close()
		m.sockets.Range(func(k, v any) bool { k.(net.Conn).Close(); return true })
	})
	return m
}
func (m *transportMock) start() {
	go func() {
		for {
			c, err := m.listener.Accept()
			if err != nil {
				return
			}
			m.sockets.Store(c, true)
			go m.serve(c)
		}
	}()
	go func() {
		b := make([]byte, 65535)
		for {
			n, from, err := m.relay.ReadFromUDP(b)
			if err != nil {
				return
			}
			packet := append([]byte(nil), b[:n]...)
			if len(packet) > 9 {
				switch m.alter {
				case 1:
					packet[2] = 1
				case 2:
					packet[9] ^= 1
				case 3:
					packet[0] = 1
				}
			}
			_, _ = m.relay.WriteToUDP(packet, from)
		}
	}()
}
func (m *transportMock) serve(c net.Conn) {
	defer c.Close()
	defer m.sockets.Delete(c)
	var greet [3]byte
	if _, err := io.ReadFull(c, greet[:]); err != nil || greet != [3]byte{5, 1, 2} {
		return
	}
	if m.noAuth {
		_, _ = c.Write([]byte{5, 0})
		return
	}
	if _, err := c.Write([]byte{5, 2}); err != nil {
		return
	}
	var auth [2]byte
	if _, err := io.ReadFull(c, auth[:]); err != nil || auth[0] != 1 {
		return
	}
	user := make([]byte, int(auth[1]))
	if _, err := io.ReadFull(c, user); err != nil {
		return
	}
	var plen [1]byte
	if _, err := io.ReadFull(c, plen[:]); err != nil {
		return
	}
	pass := make([]byte, int(plen[0]))
	if _, err := io.ReadFull(c, pass); err != nil {
		return
	}
	if string(user) != "u" || string(pass) != "p" || m.badAuth {
		_, _ = c.Write([]byte{1, 1})
		return
	}
	_, _ = c.Write([]byte{1, 0})
	var head [3]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return
	}
	_, err := connectionReadAddress(c)
	if err != nil {
		return
	}
	if m.reject {
		_, _ = c.Write([]byte{5, 7, 0})
		return
	}
	reply := m.relay.LocalAddr().(*net.UDPAddr).AddrPort()
	if m.remoteRelay {
		reply = netip.MustParseAddrPort("192.0.2.1:1234")
	}
	_, _ = c.Write(append([]byte{5, 0, 0}, connectionAddress(reply)...))
	if head[1] == 1 {
		_, _ = io.Copy(c, c)
	} else {
		_, _ = io.Copy(io.Discard, c)
	}
}
func transportClient(m *transportMock) *connectionTransport {
	ctx, cancel := context.WithCancel(context.Background())
	return &connectionTransport{address: m.listener.Addr().String(), user: "u", password: "p", udpSupported: true, ctx: ctx, cancel: cancel, conns: map[*connectionTracked]struct{}{}}
}
func TestTransportTCPAndUDP(t *testing.T) {
	m := newTransportMock(t)
	m.start()
	c := transportClient(m)
	defer c.close()
	for _, udp := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		dst := netip.MustParseAddrPort("203.0.113.2:9001")
		var conn net.Conn
		var err error
		if udp {
			conn, err = c.udp(ctx, dst)
		} else {
			conn, err = c.dial(ctx, dst)
		}
		cancel() // setup context must not own the returned connection.
		if err != nil {
			t.Fatal(err)
		}
		if err = conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		for _, payload := range []string{"hello", "second datagram"} {
			if _, err = conn.Write([]byte(payload)); err != nil {
				t.Fatal(err)
			}
			b := make([]byte, 128)
			n, e := conn.Read(b)
			if e != nil || string(b[:n]) != payload {
				t.Fatalf("echo udp=%v: %q %v", udp, b[:n], e)
			}
		}
		if udp && conn.RemoteAddr().String() != dst.String() {
			t.Fatal("UDP remote address")
		}
		c.mu.Lock()
		count := len(c.conns)
		c.mu.Unlock()
		if count != 1 {
			t.Fatal("flow not tracked")
		}
		conn.Close()
	}
	c.mu.Lock()
	count := len(c.conns)
	c.mu.Unlock()
	if count != 0 {
		t.Fatal("closed flow retained")
	}
}
func TestTransportUDPValidation(t *testing.T) {
	for _, alter := range []byte{1, 2, 3} {
		t.Run(string(rune('0'+alter)), func(t *testing.T) {
			m := newTransportMock(t)
			m.alter = alter
			m.start()
			c := transportClient(m)
			defer c.close()
			conn, err := c.udp(context.Background(), netip.MustParseAddrPort("[2001:db8::1]:9000"))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(time.Second))
			conn.Write([]byte("payload"))
			if _, err = conn.Read(make([]byte, 128)); err == nil {
				t.Fatal("malformed reply accepted")
			}
		})
	}
}
func TestTransportAuthAndReplies(t *testing.T) {
	for _, mode := range []string{"auth", "noauth", "reject", "remote"} {
		t.Run(mode, func(t *testing.T) {
			m := newTransportMock(t)
			m.badAuth = mode == "auth"
			m.noAuth = mode == "noauth"
			m.reject = mode == "reject"
			m.remoteRelay = mode == "remote"
			m.start()
			c := transportClient(m)
			defer c.close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if conn, err := c.udp(ctx, netip.MustParseAddrPort("203.0.113.1:1234")); err == nil {
				conn.Close()
				t.Fatal("unsafe SOCKS response accepted")
			}
		})
	}
}
func TestTransportLifecycle(t *testing.T) {
	m := newTransportMock(t)
	m.start()
	c := transportClient(m)
	tcp, err := c.dial(context.Background(), netip.MustParseAddrPort("203.0.113.1:1234"))
	if err != nil {
		t.Fatal(err)
	}
	udp, err := c.udp(context.Background(), netip.MustParseAddrPort("203.0.113.1:1234"))
	if err != nil {
		t.Fatal(err)
	}
	c.close()
	c.close()
	if _, err = tcp.Write([]byte("closed")); err == nil {
		t.Fatal("TCP left open")
	}
	if _, err = udp.Write([]byte("closed")); err == nil {
		t.Fatal("UDP left open")
	}
	if conn, err := c.dial(context.Background(), netip.MustParseAddrPort("203.0.113.1:1234")); err == nil {
		conn.Close()
		t.Fatal("dial after close")
	}
}
func TestTransportAssociationControlLifetime(t *testing.T) {
	m := newTransportMock(t)
	m.start()
	c := transportClient(m)
	defer c.close()
	conn, err := c.udp(context.Background(), netip.MustParseAddrPort("203.0.113.1:1234"))
	if err != nil {
		t.Fatal(err)
	}
	m.sockets.Range(func(k, v any) bool { k.(net.Conn).Close(); return true })
	result := make(chan error, 1)
	go func() { _, e := conn.Read(make([]byte, 10)); result <- e }()
	select {
	case e := <-result:
		if e == nil {
			t.Fatal("control EOF not propagated")
		}
	case <-time.After(time.Second):
		t.Fatal("UDP survived control close")
	}
}
func TestTransportHandshakeCancellation(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan struct{})
	go func() {
		conn, e := l.Accept()
		if e == nil {
			defer conn.Close()
			<-done
		}
	}()
	defer close(done)
	c := &connectionTransport{address: l.Addr().String(), user: "u", password: "p", ctx: context.Background()}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if conn, e := c.dial(ctx, netip.MustParseAddrPort("203.0.113.1:1234")); e == nil {
		conn.Close()
		t.Fatal("uncancelled handshake")
	}
}
func TestTransportUDPShortRead(t *testing.T) {
	m := newTransportMock(t)
	m.start()
	c := transportClient(m)
	defer c.close()
	conn, err := c.udp(context.Background(), netip.MustParseAddrPort("203.0.113.1:1234"))
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(time.Second))
	conn.Write([]byte("long payload"))
	if n, e := conn.Read(make([]byte, 2)); n != 2 || e != io.ErrShortBuffer {
		t.Fatalf("%d %v", n, e)
	}
	conn.Write(nil)
	if n, e := conn.Read(make([]byte, 2)); n != 0 || e != nil {
		t.Fatalf("zero datagram %d %v", n, e)
	}
}

// A subprocess mock verifies version/check/run arguments and stdin delivery
// without installing or downloading a core. Never used in production.
func TestTransportCoreHelper(t *testing.T) {
	if os.Getenv("FNPORT_TRANSPORT_HELPER") != "1" {
		return
	}
	args := os.Args
	marker := -1
	for i, a := range args {
		if a == "--" {
			marker = i
			break
		}
	}
	if marker < 0 || marker+1 >= len(args) {
		os.Exit(2)
	}
	args = args[marker+1:]
	if args[0] == "version" {
		if os.Getenv("FNPORT_TRANSPORT_BAD_VERSION") == "1" {
			io.WriteString(os.Stdout, "sing-box version 0.0.0\n")
		} else {
			io.WriteString(os.Stdout, "sing-box version "+connectionCoreVersion+"\n")
		}
		os.Exit(0)
	}
	if len(args) != 3 || args[1] != "-c" || args[2] != "stdin" {
		os.Exit(3)
	}
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		os.Exit(4)
	}
	var cfg struct {
		Inbounds []struct {
			Listen string                                `json:"listen"`
			Port   int                                   `json:"listen_port"`
			Users  []struct{ Username, Password string } `json:"users"`
		} `json:"inbounds"`
	}
	if json.Unmarshal(raw, &cfg) != nil || len(cfg.Inbounds) != 1 || len(cfg.Inbounds[0].Users) != 1 {
		os.Exit(5)
	}
	if args[0] == "check" {
		if os.Getenv("FNPORT_TRANSPORT_BAD_CHECK") == "1" {
			io.WriteString(os.Stderr, "secret credentials")
			os.Exit(6)
		}
		os.Exit(0)
	}
	if args[0] != "run" {
		os.Exit(7)
	}
	if os.Getenv("FNPORT_TRANSPORT_EXIT_RUN") == "1" {
		os.Exit(8)
	}
	in := cfg.Inbounds[0]
	l, e := net.Listen("tcp", net.JoinHostPort(in.Listen, strconv.Itoa(in.Port)))
	if e != nil {
		os.Exit(9)
	}
	for {
		conn, e := l.Accept()
		if e != nil {
			os.Exit(10)
		}
		go func() {
			defer conn.Close()
			greet := make([]byte, 3)
			if _, e := io.ReadFull(conn, greet); e != nil {
				return
			}
			conn.Write([]byte{5, 2})
			h := make([]byte, 2)
			if _, e := io.ReadFull(conn, h); e != nil {
				return
			}
			u := make([]byte, int(h[1]))
			io.ReadFull(conn, u)
			io.ReadFull(conn, h[:1])
			p := make([]byte, int(h[0]))
			io.ReadFull(conn, p)
			if string(u) != in.Users[0].Username || string(p) != in.Users[0].Password {
				conn.Write([]byte{1, 1})
				return
			}
			conn.Write([]byte{1, 0})
		}()
	}
}
func TestTransportCoreProcess(t *testing.T) {
	for _, mode := range []string{"ok", "version", "check", "exit"} {
		t.Run(mode, func(t *testing.T) {
			command := func(ctx context.Context, args ...string) *exec.Cmd {
				cmd := exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=^TestTransportCoreHelper$", "--"}, args...)...)
				cmd.Env = append(os.Environ(), "FNPORT_TRANSPORT_HELPER=1")
				switch mode {
				case "version":
					cmd.Env = append(cmd.Env, "FNPORT_TRANSPORT_BAD_VERSION=1")
				case "check":
					cmd.Env = append(cmd.Env, "FNPORT_TRANSPORT_BAD_CHECK=1")
				case "exit":
					cmd.Env = append(cmd.Env, "FNPORT_TRANSPORT_EXIT_RUN=1")
				}
				return cmd
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			c, err := startConnectionCommand(ctx, transportSettings(`{"type":"direct"}`), "Ethernet", command)
			if mode != "ok" {
				if err == nil {
					c.close()
					t.Fatal("invalid core accepted")
				}
				if strings.Contains(err.Error(), "secret credentials") {
					t.Fatal("core diagnostic leaked")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if c.user == "" || c.password == "" || c.user == c.password {
				t.Fatal("invalid random authentication")
			}
			cancel()
			select {
			case <-c.done:
			case <-time.After(3 * time.Second):
				t.Fatal("child not reaped on cancellation")
			}
			c.close()
		})
	}
}

func TestTransportRealCore(t *testing.T) {
	core := os.Getenv("FNPORT_TEST_SING_BOX")
	if core == "" {
		core = os.Getenv("FNPORT_SING_BOX_TEST_BIN")
	}
	if core == "" {
		core = os.Getenv("FNPORT_TRANSPORT_TEST_CORE")
	}
	if core == "" {
		t.Skip("set FNPORT_TEST_SING_BOX to a verified native sing-box 1.14.4 executable")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	iface := ""
	for _, i := range interfaces {
		if i.Flags&net.FlagLoopback != 0 {
			iface = i.Name
			break
		}
	}
	if iface == "" {
		t.Fatal("loopback interface unavailable")
	}
	command := func(ctx context.Context, args ...string) *exec.Cmd { return exec.CommandContext(ctx, core, args...) }
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c, err := startConnectionCommand(ctx, transportSettings(`{"type":"direct"}`), iface, command)
	if err != nil {
		t.Fatal(err)
	}
	defer c.close()
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	go func() {
		conn, e := tcp.Accept()
		if e == nil {
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		}
	}()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		b := make([]byte, 65535)
		for {
			n, addr, e := udp.ReadFromUDP(b)
			if e != nil {
				return
			}
			_, _ = udp.WriteToUDP(b[:n], addr)
		}
	}()
	for _, datagrams := range []bool{false, true} {
		setup, finish := context.WithTimeout(ctx, time.Second)
		var conn net.Conn
		if datagrams {
			conn, err = c.udp(setup, udp.LocalAddr().(*net.UDPAddr).AddrPort())
		} else {
			conn, err = c.dial(setup, tcp.Addr().(*net.TCPAddr).AddrPort())
		}
		finish()
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		payload := []byte("real pinned core echo")
		if _, e := conn.Write(payload); e != nil {
			conn.Close()
			t.Fatal(e)
		}
		b := make([]byte, len(payload))
		if _, e := io.ReadFull(conn, b); e != nil {
			conn.Close()
			t.Fatal(e)
		}
		if !bytes.Equal(b, payload) {
			t.Fatal("real core payload mismatch")
		}
		conn.Close()
	}
	bad := transportSettings(`{"type":"future-nonexistent"}`)
	if other, e := startConnectionCommand(ctx, bad, iface, command); e == nil {
		other.close()
		t.Fatal("actual core check accepted nonexistent protocol")
	}
}

func TestTransportCapabilityOptions(t *testing.T) {
	for _, tt := range []struct {
		raw string
		udp bool
	}{
		{`{"type":"naive","udp_over_tcp":{"enabled":true}}`, true},
		{`{"type":"naive"}`, false},
		{`{"type":"socks","version":"4a"}`, false},
		{`{"type":"vless","network":["tcp"]}`, false},
		{`{"type":"vless","network":["tcp","udp"]}`, true},
		{`{"type":"snell","version":4}`, true},
	} {
		_, udp, err := connectionConfig(transportSettings(tt.raw), "Ethernet", 1, "u", "p")
		if err != nil || udp != tt.udp {
			t.Fatalf("%s: UDP=%v err=%v", tt.raw, udp, err)
		}
	}
	s := transportSettings(`{"outbounds":[{"type":"direct","tag":"out","detour":"tcp"},{"type":"ssh","tag":"tcp"}]}`)
	s.Final = "out"
	_, udp, err := connectionConfig(s, "Ethernet", 1, "u", "p")
	if err != nil || udp {
		t.Fatal("TCP-only detour advertised UDP")
	}
	s = transportSettings(`{}`)
	s.Protocol = "amneziawg"
	if err := s.validate(); err == nil {
		t.Fatal("native AWG validation not delegated")
	}
}
