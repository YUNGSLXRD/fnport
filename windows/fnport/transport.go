package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const connectionCoreVersion = "1.14.4"

type connectionSettings struct {
	Enabled      bool                    `json:"enabled"`
	Protocol     string                  `json:"protocol"`
	Config       json.RawMessage         `json:"config"`
	Processes    []string                `json:"processes"`
	Epic         bool                    `json:"epic"`
	Discord      bool                    `json:"discord"`
	Final        string                  `json:"final"`
	Subscription *connectionSubscription `json:"subscription,omitempty"`
}

type connectionProtocol struct {
	ID, Label         string
	Endpoint, TCPOnly bool
}

// Descriptive catalog, not a claim about compiled-in features. The bundled core's
// check command is authoritative. Transport/TLS/multiplex options stay in Config.
func connectionProtocols() []connectionProtocol {
	return []connectionProtocol{
		{"warp", "WARP (native)", false, false},
		{"amneziawg", "AmneziaWG 1.5 (native)", false, false},
		{"socks", "SOCKS", false, false}, {"http", "HTTP CONNECT", false, true},
		{"shadowsocks", "Shadowsocks", false, false},
		{"vmess", "VMess", false, false}, {"vless", "VLESS", false, false},
		{"trojan", "Trojan", false, false}, {"naive", "Naive (UDP requires UoT)", false, false},
		{"shadowtls", "ShadowTLS (detour)", false, true}, {"anytls", "AnyTLS", false, false},
		{"snell", "Snell", false, false},
		{"hysteria", "Hysteria", false, false}, {"hysteria2", "Hysteria 2", false, false},
		{"tuic", "TUIC", false, false}, {"ssh", "SSH", false, true}, {"tor", "Tor", false, true},
		{"wireguard", "WireGuard", true, false}, {"tailscale", "Tailscale", true, false},
		{"openconnect", "OpenConnect", true, false}, {"openvpn-client", "OpenVPN client", true, false},
		{"direct", "Direct", false, false}, {"bridge", "Bridge", false, false},
		{"selector", "Selector", false, false}, {"urltest", "URLTest", false, false},
		{"custom", "Custom outbound / full JSON", false, false},
	}
}

func (s connectionSettings) validate() error {
	if !s.Enabled || s.Protocol == "warp" {
		return nil
	}
	if s.Protocol == "amneziawg" {
		return validateNativeAWG(s.Config)
	}
	_, _, err := connectionConfig(s, "physical", 1, "validation", "validation")
	return err
}

// No user-supplied JSON values or core diagnostics may appear in returned errors:
// a malformed type, tag or even parser diagnostic may contain credentials.
func connectionConfig(s connectionSettings, iface string, port int, user, password string) ([]byte, bool, error) {
	fail := func(msg string) ([]byte, bool, error) { return nil, false, errors.New(msg) }
	if strings.TrimSpace(iface) == "" {
		return fail("connection requires a physical interface")
	}
	if s.Protocol == "" {
		return fail("select a connection protocol")
	}
	if s.Protocol == "warp" || s.Protocol == "amneziawg" {
		return fail("selected protocol uses the native parent transport")
	}
	var root map[string]any
	dec := json.NewDecoder(bytes.NewReader(s.Config))
	dec.UseNumber()
	if dec.Decode(&root) != nil || root == nil {
		return fail("connection config must be a JSON object")
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return fail("connection config must contain one JSON object")
	}
	// Reject remote whole-config routing/listeners; only fnport owns these.
	for _, key := range []string{"inbounds", "route", "experimental", "services", "network_namespaces"} {
		if _, ok := root[key]; ok {
			return fail("imported listeners, routing, services and experimental APIs are prohibited")
		}
	}
	if err := connectionSafeFields(root, iface); err != nil {
		return nil, false, err
	}
	_, outFull := root["outbounds"]
	_, epFull := root["endpoints"]
	full := outFull || epFull
	final := s.Final
	if !full {
		typ, _ := root["type"].(string)
		if typ == "" || (s.Protocol != "custom" && typ != s.Protocol) {
			return fail("outbound type must match the selected protocol")
		}
		tag, _ := root["tag"].(string)
		if tag == "" {
			tag = "fnport-out"
			root["tag"] = tag
		}
		if final != "" && final != tag {
			return fail("final tag does not match the outbound")
		}
		final = tag
		endpoint := false
		for _, p := range connectionProtocols() {
			if p.ID == typ {
				endpoint = p.Endpoint
			}
		}
		key := "outbounds"
		if endpoint {
			key = "endpoints"
		}
		root = map[string]any{key: []any{root}}
	} else if final == "" {
		return fail("full config requires an explicit final tag")
	}
	nodes := map[string]map[string]any{}
	for _, key := range []string{"outbounds", "endpoints"} {
		raw, exists := root[key]
		if !exists {
			continue
		}
		list, ok := raw.([]any)
		if !ok {
			return fail("outbounds and endpoints must be arrays")
		}
		for _, v := range list {
			obj, ok := v.(map[string]any)
			if !ok {
				return fail("outbound or endpoint must be an object")
			}
			tag, _ := obj["tag"].(string)
			typ, _ := obj["type"].(string)
			if tag == "" || typ == "" || nodes[tag] != nil {
				return fail("outbounds and endpoints require unique tags and types")
			}
			nodes[tag] = obj
		}
	}
	if nodes[final] == nil {
		return fail("final tag must name an outbound or endpoint")
	}
	if s.Protocol != "custom" {
		typ, _ := nodes[final]["type"].(string)
		if typ != s.Protocol {
			return fail("final type must match the selected protocol")
		}
	}
	// Binding a raw outbound as well as the route prevents an imported bind from
	// overriding the physical default. Virtual selector/urltest nodes have no dial fields.
	for _, obj := range nodes {
		typ, _ := obj["type"].(string)
		switch typ {
		case "selector", "urltest", "block", "dns":
		default:
			obj["bind_interface"] = iface
		}
	}
	udp := connectionUDP(nodes, final, map[string]bool{})
	if s.Discord && !udp {
		return fail("selected connection cannot guarantee UDP required for Discord voice; choose a UDP-capable protocol")
	}
	root["log"] = map[string]any{"disabled": true}
	root["route"] = map[string]any{"final": final, "default_interface": iface, "auto_detect_interface": false}
	root["inbounds"] = []any{map[string]any{"type": "socks", "tag": "fnport-local", "listen": "127.0.0.1", "listen_port": port,
		"users": []any{map[string]any{"username": user, "password": password}}}}
	b, err := json.Marshal(root)
	if err != nil {
		return fail("cannot encode connection config")
	}
	return b, udp, nil
}

// Unknown outbound options are preserved. Known ways of opening imported
// listeners, creating system TUNs or bypassing interface binding are forbidden.
func connectionSafeFields(v any, iface string) error {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			switch k {
			case "listen", "listen_port", "external_controller", "external_ui", "clash_api", "v2ray_api", "ssh_server", "relay_server_port":
				return errors.New("imported listener or API settings are prohibited")
			case "system_interface", "system":
				if val != false {
					return errors.New("system interfaces are prohibited; use userspace endpoints")
				}
			case "auto_route", "auto_redirect", "set_system_proxy", "netns", "routing_mark", "inet4_bind_address", "inet6_bind_address":
				return errors.New("imported system routing and binding overrides are prohibited")
			case "bind_interface":
				x[k] = iface
			}
			if err := connectionSafeFields(val, iface); err != nil {
				return err
			}
		}
	case []any:
		for _, val := range x {
			if err := connectionSafeFields(val, iface); err != nil {
				return err
			}
		}
	}
	return nil
}

// Conservative for selectors and unknown protocols: every selectable branch
// must support datagrams. Custom future protocols still work for TCP.
func connectionUDP(nodes map[string]map[string]any, tag string, visiting map[string]bool) bool {
	n := nodes[tag]
	if n == nil || visiting[tag] {
		return false
	}
	visiting[tag] = true
	defer delete(visiting, tag)
	typ, _ := n["type"].(string)
	if network, ok := n["network"].(string); ok && network != "" && network != "udp" {
		return false
	}
	if networks, ok := n["network"].([]any); ok && len(networks) > 0 {
		udp := false
		for _, network := range networks {
			if network == "udp" {
				udp = true
			}
		}
		if !udp {
			return false
		}
	}
	switch typ {
	case "selector", "urltest":
		branches, ok := n["outbounds"].([]any)
		if !ok || len(branches) == 0 {
			return false
		}
		for _, b := range branches {
			t, ok := b.(string)
			if !ok || !connectionUDP(nodes, t, visiting) {
				return false
			}
		}
		return true
	case "socks":
		if ver, _ := n["version"].(string); ver == "4" || ver == "4a" {
			return false
		}
	case "naive":
		uot, ok := n["udp_over_tcp"].(map[string]any)
		if !ok || uot["enabled"] != true {
			return false
		}
	case "http", "ssh", "tor", "shadowtls", "block", "dns":
		return false
	default:
		known := false
		for _, p := range connectionProtocols() {
			if p.ID == typ && p.ID != "custom" && p.ID != "warp" && p.ID != "amneziawg" {
				known = true
			}
		}
		if !known {
			return false
		}
	}
	// Conservatively reject detours with unverified packet support.
	if detour, _ := n["detour"].(string); detour != "" && !connectionUDP(nodes, detour, visiting) {
		return false
	}
	return true
}

type connectionTransport struct {
	address, user, password string
	udpSupported            bool
	ctx                     context.Context
	cancel                  context.CancelFunc
	done                    chan struct{}
	mu                      sync.Mutex
	closed                  bool
	exitCode                int
	exitUnexpected          bool
	conns                   map[*connectionTracked]struct{}
	once                    sync.Once
}

type connectionCommand func(context.Context, ...string) *exec.Cmd

func startConnection(ctx context.Context, s connectionSettings, iface string) (*connectionTransport, error) {
	path := filepath.Join(appDir(), "sing-box.exe")
	return startConnectionCommand(ctx, s, iface, func(ctx context.Context, args ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, path, args...)
		cmd.Dir = appDir()
		return cmd
	})
}

// stdin is supported by the pinned official core's readConfigAt for both
// check and run: github.com/SagerNet/sing-box/blob/v1.14.4/cmd/sing-box/cmd_run.go.
// No config files, temporary directories or diagnostic logs are created.
func startConnectionCommand(ctx context.Context, s connectionSettings, iface string, command connectionCommand) (*connectionTransport, error) {
	if !s.Enabled {
		return nil, errors.New("connection is disabled")
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	if s.Protocol == "warp" || s.Protocol == "amneziawg" {
		return nil, errors.New("selected protocol uses the native parent transport")
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return nil, errors.New("cannot generate local SOCKS credentials")
	}
	user, password := hex.EncodeToString(random[:16]), hex.EncodeToString(random[16:])
	// Core cannot inherit a pre-bound listener. Reserve then release an ephemeral
	// port; authenticated readiness prevents accepting an unrelated listener.
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, errors.New("cannot reserve local SOCKS port")
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	config, udp, err := connectionConfig(s, iface, port, user, password)
	if err != nil {
		return nil, err
	}
	checkCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	versionCmd := command(checkCtx, "version")
	connectionPrepareCommand(versionCmd)
	var version connectionVersionWriter
	versionCmd.Stdout = &version
	versionCmd.Stderr = io.Discard
	err = versionCmd.Run()
	if err != nil || !strings.HasPrefix(version.text, "sing-box version "+connectionCoreVersion+"\n") {
		cancel()
		return nil, errors.New("bundled sing-box.exe must be official version " + connectionCoreVersion)
	}
	check := command(checkCtx, "check", "-c", "stdin")
	connectionPrepareCommand(check)
	check.Stdin = bytes.NewReader(config)
	check.Stdout = io.Discard
	check.Stderr = io.Discard
	err = check.Run()
	cancel()
	if err != nil {
		return nil, errors.New("bundled sing-box rejected connection config or lacks required features (diagnostics withheld to protect credentials)")
	}
	life, stop := context.WithCancel(ctx)
	cmd := command(life, "run", "-c", "stdin")
	connectionPrepareCommand(cmd)
	cmd.Stdin = bytes.NewReader(config)
	cmd.Stdout = io.Discard
	var diagnostic connectionCoreDiagnostic
	cmd.Stderr = &diagnostic
	started := time.Now()
	if cmd.Start() != nil {
		stop()
		return nil, errors.New("cannot start bundled sing-box.exe")
	}
	c := &connectionTransport{address: net.JoinHostPort("127.0.0.1", fmt.Sprint(port)), user: user, password: password, udpSupported: udp,
		ctx: life, cancel: stop, done: make(chan struct{}), conns: map[*connectionTracked]struct{}{}}
	go func() {
		_ = cmd.Wait()
		c.mu.Lock()
		c.exitCode = cmd.ProcessState.ExitCode()
		c.exitUnexpected = !c.closed && life.Err() == nil
		unexpected, code := c.exitUnexpected, c.exitCode
		c.mu.Unlock()
		if unexpected {
			logf("Подключения: sing-box неожиданно завершился; код %d (0x%08X), работал %s, диагностика %s. Дополнительное подключение недоступно.", code, uint32(code), time.Since(started).Round(time.Millisecond), diagnostic.category())
		}
		close(c.done)
		c.close()
	}()
	go func() { <-life.Done(); c.close() }()
	ready, finish := context.WithTimeout(life, 8*time.Second)
	defer finish()
	tick := time.NewTicker(30 * time.Millisecond)
	defer tick.Stop()
	for {
		attempt, end := context.WithTimeout(ready, 200*time.Millisecond)
		conn, e := c.authenticate(attempt)
		end()
		if e == nil {
			conn.Close()
			return c, nil
		}
		select {
		case <-c.done:
			c.close()
			return nil, errors.New("sing-box exited before local SOCKS became ready")
		case <-ready.Done():
			c.close()
			return nil, errors.New("local authenticated SOCKS did not become ready")
		case <-tick.C:
		}
	}
}

// Bound stdout collection: version output is not logged or included in errors.
type connectionVersionWriter struct{ text string }

func (w *connectionVersionWriter) Write(b []byte) (int, error) {
	n := len(b)
	if len(w.text) < 256 {
		limit := 256 - len(w.text)
		if len(b) > limit {
			b = b[:limit]
		}
		w.text += string(b)
	}
	w.text = strings.ReplaceAll(w.text, "\r\n", "\n")
	return n, nil
}

func (c *connectionTransport) close() {
	c.once.Do(func() {
		c.mu.Lock()
		c.closed = true
		list := make([]*connectionTracked, 0, len(c.conns))
		for v := range c.conns {
			list = append(list, v)
		}
		c.mu.Unlock()
		if c.cancel != nil {
			c.cancel()
		}
		for _, v := range list {
			v.Close()
		}
	})
	if c.done != nil {
		<-c.done
	}
}

type connectionTracked struct {
	net.Conn
	owner *connectionTransport
	once  sync.Once
}

func (c *connectionTracked) Close() error {
	var err error
	c.once.Do(func() { err = c.Conn.Close(); c.owner.mu.Lock(); delete(c.owner.conns, c); c.owner.mu.Unlock() })
	return err
}
func (c *connectionTransport) track(conn net.Conn) (net.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		conn.Close()
		return nil, net.ErrClosed
	}
	t := &connectionTracked{Conn: conn, owner: c}
	if c.conns == nil {
		c.conns = map[*connectionTracked]struct{}{}
	}
	c.conns[t] = struct{}{}
	return t, nil
}

// Cancellation applies to setup; after return the caller owns deadlines and
// Close, while parent-context cancellation/transport close closes every flow.
func (c *connectionTransport) setup(ctx context.Context) (context.Context, func()) {
	setup, cancel := context.WithTimeout(ctx, 10*time.Second)
	stop := context.AfterFunc(c.ctx, cancel)
	return setup, func() { stop(); cancel() }
}
func connectionIOContext(ctx context.Context, conn net.Conn) func() {
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()); close(done) })
	return func() {
		if !stop() {
			<-done
		}
		_ = conn.SetDeadline(time.Time{})
	}
}

// RFC 1928 / 1929, requiring username/password even if the listener offers
// unauthenticated access. Used for both TCP and UDP control connections.
func (c *connectionTransport) authenticate(ctx context.Context) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", c.address)
	if err != nil {
		return nil, connectionFailure("local_connect", err)
	}
	reset := connectionIOContext(ctx, conn)
	defer reset()
	fail := func(err error) (net.Conn, error) { conn.Close(); return nil, connectionFailure("local_auth", err) }
	if err := connectionWrite(conn, []byte{5, 1, 2}); err != nil {
		return fail(err)
	}
	var reply [2]byte
	if _, err = io.ReadFull(conn, reply[:]); err != nil || reply != [2]byte{5, 2} {
		return fail(err)
	}
	auth := []byte{1, byte(len(c.user))}
	auth = append(auth, c.user...)
	auth = append(auth, byte(len(c.password)))
	auth = append(auth, c.password...)
	if err = connectionWrite(conn, auth); err != nil {
		return fail(err)
	}
	if _, err = io.ReadFull(conn, reply[:]); err != nil || reply != [2]byte{1, 0} {
		return fail(err)
	}
	return conn, nil
}
func connectionWrite(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
func connectionAddress(dst netip.AddrPort) []byte {
	addr := dst.Addr().Unmap()
	var b []byte
	if addr.Is4() {
		a := addr.As4()
		b = append([]byte{1}, a[:]...)
	} else {
		a := addr.As16()
		b = append([]byte{4}, a[:]...)
	}
	return binary.BigEndian.AppendUint16(b, dst.Port())
}
func connectionReadAddress(r io.Reader) (netip.AddrPort, error) {
	var t [1]byte
	if _, err := io.ReadFull(r, t[:]); err != nil {
		return netip.AddrPort{}, err
	}
	size := 0
	switch t[0] {
	case 1:
		size = 4
	case 4:
		size = 16
	default:
		return netip.AddrPort{}, errors.New("SOCKS reply must use an IP address")
	}
	b := make([]byte, size+2)
	if _, err := io.ReadFull(r, b); err != nil {
		return netip.AddrPort{}, err
	}
	a, _ := netip.AddrFromSlice(b[:size])
	return netip.AddrPortFrom(a.Unmap(), binary.BigEndian.Uint16(b[size:])), nil
}
func connectionRequest(ctx context.Context, conn net.Conn, cmd byte, dst netip.AddrPort) (netip.AddrPort, error) {
	reset := connectionIOContext(ctx, conn)
	defer reset()
	req := append([]byte{5, cmd, 0}, connectionAddress(dst)...)
	if err := connectionWrite(conn, req); err != nil {
		return netip.AddrPort{}, connectionFailure("socks_write", err)
	}
	var head [3]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return netip.AddrPort{}, connectionFailure("socks_read", err)
	}
	if head != [3]byte{5, 0, 0} {
		return netip.AddrPort{}, &connectionSetupError{stage: "socks_reply", code: uint32(head[1])}
	}
	addr, err := connectionReadAddress(conn)
	if err != nil {
		return netip.AddrPort{}, errors.New("invalid SOCKS reply address")
	}
	return addr, nil
}
func (c *connectionTransport) dial(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	if !dst.IsValid() || dst.Port() == 0 {
		return nil, errors.New("invalid TCP destination")
	}
	ctx, finish := c.setup(ctx)
	defer finish()
	conn, err := c.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	if _, err = connectionRequest(ctx, conn, 1, dst); err != nil {
		conn.Close()
		return nil, err
	}
	return c.track(conn)
}
func (c *connectionTransport) udp(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	if !c.udpSupported {
		return nil, errors.New("UDP is unsupported or unverified for the selected connection protocol")
	}
	if !dst.IsValid() || dst.Port() == 0 {
		return nil, errors.New("invalid UDP destination")
	}
	ctx, finish := c.setup(ctx)
	defer finish()
	control, err := c.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	// Bind before ASSOCIATE so the client port is supplied as required by RFC1928.
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		control.Close()
		return nil, errors.New("cannot open local UDP socket")
	}
	relay, err := connectionRequest(ctx, control, 3, socket.LocalAddr().(*net.UDPAddr).AddrPort())
	if err != nil {
		socket.Close()
		control.Close()
		return nil, err
	}
	if relay.Addr().IsUnspecified() {
		relay = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), relay.Port())
	}
	if !relay.Addr().IsLoopback() || !relay.Addr().Is4() || relay.Port() == 0 {
		socket.Close()
		control.Close()
		return nil, errors.New("SOCKS UDP relay must be IPv4 loopback")
	}
	u := &connectionDatagrams{socket: socket, control: control, relay: relay, target: netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port())}
	tracked, err := c.track(u)
	if err != nil {
		return nil, err
	}
	// RFC1928: association ends when the TCP control connection closes.
	go func() { _, _ = io.Copy(io.Discard, control); tracked.Close() }()
	return tracked, nil
}

type connectionDatagrams struct {
	socket        *net.UDPConn
	control       net.Conn
	relay, target netip.AddrPort
	once          sync.Once
}

func (u *connectionDatagrams) Read(b []byte) (int, error) {
	packet := make([]byte, 65535)
	for {
		n, from, err := u.socket.ReadFromUDPAddrPort(packet)
		if err != nil {
			return 0, err
		}
		if from != u.relay {
			continue
		}
		if n < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
			return 0, errors.New("invalid or fragmented SOCKS UDP datagram")
		}
		r := bytes.NewReader(packet[3:n])
		dst, err := connectionReadAddress(r)
		if err != nil || dst != u.target {
			return 0, errors.New("SOCKS UDP reply target mismatch")
		}
		payload := packet[n-r.Len() : n]
		copied := copy(b, payload)
		if copied < len(payload) {
			return copied, io.ErrShortBuffer
		}
		return copied, nil
	}
}
func (u *connectionDatagrams) Write(b []byte) (int, error) {
	header := append([]byte{0, 0, 0}, connectionAddress(u.target)...)
	if len(b)+len(header) > 65507 {
		return 0, errors.New("SOCKS UDP datagram too large")
	}
	packet := append(header, b...)
	n, err := u.socket.WriteToUDPAddrPort(packet, u.relay)
	if err != nil {
		return 0, err
	}
	if n != len(packet) {
		return 0, io.ErrShortWrite
	}
	return len(b), nil
}
func (u *connectionDatagrams) Close() error {
	var err error
	u.once.Do(func() { err = u.socket.Close(); u.control.Close() })
	return err
}
func (u *connectionDatagrams) LocalAddr() net.Addr               { return u.socket.LocalAddr() }
func (u *connectionDatagrams) RemoteAddr() net.Addr              { return net.UDPAddrFromAddrPort(u.target) }
func (u *connectionDatagrams) SetDeadline(t time.Time) error     { return u.socket.SetDeadline(t) }
func (u *connectionDatagrams) SetReadDeadline(t time.Time) error { return u.socket.SetReadDeadline(t) }
func (u *connectionDatagrams) SetWriteDeadline(t time.Time) error {
	return u.socket.SetWriteDeadline(t)
}

func connectionPrepareCommand(cmd *exec.Cmd) {
	cmd.WaitDelay = 2 * time.Second
	connectionHideWindow(cmd)
}
