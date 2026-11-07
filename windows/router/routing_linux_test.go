//go:build linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// A real client lives in a second Linux network namespace. Only test data passes
// through this fixture; it does not need any external server or credentials.
func TestLinuxClientProcess(t *testing.T) {
	if os.Getenv("FNPORT_ROUTER_CLIENT_TEST") != "1" {
		t.Skip("child fixture")
	}
	requireNetworkNamespace(t)
	ready, goPipe := os.NewFile(3, "ready"), os.NewFile(4, "go")
	defer ready.Close()
	defer goPipe.Close()
	commands := bufio.NewReader(goPipe)
	fmt.Fprintln(ready, "ready")
	if _, err := commands.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	source := net.ParseIP("10.88.0.2")
	dns, err := (&net.Dialer{LocalAddr: &net.UDPAddr{IP: source}}).DialContext(ctx, "udp4", "10.88.0.1:53")
	if err != nil {
		t.Fatal(err)
	}
	dns.SetDeadline(time.Now().Add(4 * time.Second))
	query := dnsQuery(t, "account.epicgames.com", dnsmessage.TypeA)
	if _, err = dns.Write(query); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 2048)
	n, err := dns.Read(buffer)
	dns.Close()
	if err != nil {
		t.Fatal("selected LAN DNS failed", err)
	}
	var parser dnsmessage.Parser
	header, err := parser.Start(buffer[:n])
	if err != nil || header.RCode != dnsmessage.RCodeSuccess {
		t.Fatal("selected LAN DNS invalid")
	}
	if _, err = parser.AllQuestions(); err != nil {
		t.Fatal(err)
	}
	answers, err := parser.AllAnswers()
	if err != nil || len(answers) != 1 {
		t.Fatal("selected LAN DNS missing address")
	}
	tcpCheck := func(ip, expected string) {
		t.Helper()
		conn, err := (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(ip)}}).DialContext(ctx, "tcp4", "198.51.100.9:443")
		if err != nil {
			t.Fatal("LAN TCP dial", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(4 * time.Second))
		conn.Write([]byte("hello"))
		reply := make([]byte, len(expected))
		if _, err = io.ReadFull(conn, reply); err != nil || string(reply) != expected {
			t.Fatalf("LAN %s got %q: %v", ip, reply, err)
		}
	}
	tcpCheck("10.88.0.2", "hello")  // SOCKS echo, proving TProxy selected the VPN.
	tcpCheck("10.88.0.3", "direct") // The other device must bypass the VPN.
	udp, err := (&net.Dialer{LocalAddr: &net.UDPAddr{IP: source}}).DialContext(ctx, "udp4", "198.51.100.9:9108")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	udp.SetDeadline(time.Now().Add(4 * time.Second))
	payload := bytes.Repeat([]byte{0x39}, 1200)
	udp.Write(payload)
	n, err = udp.Read(buffer)
	if err != nil || !bytes.Equal(buffer[:n], payload) {
		t.Fatal("game UDP did not stay direct", err)
	}
	fmt.Fprintln(ready, "phase1")
	if _, err := commands.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	tcpCheck("10.88.0.2", "direct") // Transport stopped: interception disabled.
}

func testSOCKSEcho(t *testing.T) (net.Listener, *sync.Map) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	destinations := &sync.Map{}
	go func() {
		for {
			socket, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer socket.Close()
				socket.SetDeadline(time.Now().Add(15 * time.Second))
				var head [2]byte
				if _, err := io.ReadFull(socket, head[:]); err != nil || head[0] != 5 {
					return
				}
				methods := make([]byte, head[1])
				if _, err := io.ReadFull(socket, methods); err != nil {
					return
				}
				socket.Write([]byte{5, 0})
				var request [4]byte
				if _, err := io.ReadFull(socket, request[:]); err != nil || request[1] != 1 {
					return
				}
				host := ""
				switch request[3] {
				case 1:
					b := make([]byte, 4)
					if _, err := io.ReadFull(socket, b); err != nil {
						return
					}
					host = net.IP(b).String()
				case 3:
					var length [1]byte
					io.ReadFull(socket, length[:])
					b := make([]byte, int(length[0]))
					if _, err := io.ReadFull(socket, b); err != nil {
						return
					}
					host = string(b)
				default:
					return
				}
				var port [2]byte
				if _, err := io.ReadFull(socket, port[:]); err != nil {
					return
				}
				destinations.Store(net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port[:])))), true)
				socket.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
				io.Copy(socket, socket)
			}()
		}
	}()
	return listener, destinations
}

func TestLinuxSelectedClientRouting(t *testing.T) {
	requireNetworkNamespace(t)
	coreFile := os.Getenv("FNPORT_TEST_SING_BOX")
	if coreFile == "" {
		t.Skip("pinned core required")
	}
	runNetTest(t, "", "ip", "link", "set", "lo", "up")
	runNetTest(t, "", "ip", "addr", "add", "198.51.100.9/32", "dev", "lo")
	defer runNetTest(t, "", "ip", "addr", "del", "198.51.100.9/32", "dev", "lo")
	upstream, destinations := testSOCKSEcho(t)
	defer upstream.Close()
	direct, err := net.Listen("tcp4", "198.51.100.9:443")
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Close()
	go func() {
		for {
			c, err := direct.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				b := make([]byte, 5)
				if _, err := io.ReadFull(c, b); err == nil {
					c.Write([]byte("direct"))
				}
			}()
		}
	}()
	game, err := net.ListenPacket("udp4", "198.51.100.9:9108")
	if err != nil {
		t.Fatal(err)
	}
	defer game.Close()
	go func() {
		b := make([]byte, 2048)
		for {
			n, from, e := game.ReadFrom(b)
			if e != nil {
				return
			}
			game.WriteTo(b[:n], from)
		}
	}()
	readyRead, readyWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	goRead, goWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readyRead.Close()
	defer goWrite.Close()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command("unshare", "--net", executable, "-test.run=^TestLinuxClientProcess$", "-test.v")
	child.Env = append(os.Environ(), "FNPORT_ROUTER_CLIENT_TEST=1")
	child.ExtraFiles = []*os.File{readyWrite, goRead}
	var output bytes.Buffer
	child.Stdout = &output
	child.Stderr = &output
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	readyWrite.Close()
	goRead.Close()
	finished := make(chan error, 1)
	go func() { finished <- child.Wait() }()
	defer func() {
		child.Process.Kill()
		select {
		case <-finished:
		case <-time.After(time.Second):
		}
	}()
	reader := bufio.NewReader(readyRead)
	phase := func(expected string) {
		t.Helper()
		line, err := reader.ReadString('\n')
		if err != nil || line != expected+"\n" {
			t.Fatalf("client stage %q: %v, %s", line, err, output.String())
		}
	}
	phase("ready")
	runNetTest(t, "", "ip", "link", "add", "fnp-test-r", "type", "veth", "peer", "name", "fnp-test-c")
	defer runNetTest(t, "", "ip", "link", "del", "fnp-test-r")
	runNetTest(t, "", "ip", "link", "set", "fnp-test-c", "netns", strconv.Itoa(child.Process.Pid))
	runNetTest(t, "", "ip", "addr", "add", "10.88.0.1/24", "dev", "fnp-test-r")
	runNetTest(t, "", "ip", "link", "set", "fnp-test-r", "up")
	clientCommand := func(args ...string) {
		runNetTest(t, "", "nsenter", append([]string{"-t", strconv.Itoa(child.Process.Pid), "-n", "ip"}, args...)...)
	}
	clientCommand("link", "set", "lo", "up")
	clientCommand("addr", "add", "10.88.0.2/24", "dev", "fnp-test-c")
	clientCommand("addr", "add", "10.88.0.3/24", "dev", "fnp-test-c")
	clientCommand("link", "set", "fnp-test-c", "up")
	clientCommand("route", "add", "default", "via", "10.88.0.1")
	c := routerTestConfig()
	c.WAN = "lo"
	c.LAN = []string{"fnp-test-r"}
	c.Devices = []string{"10.88.0.2"}
	c.Profile = fmt.Sprintf(`{"type":"socks","server":"127.0.0.1","server_port":%d}`, upstream.Addr().(*net.TCPAddr).Port)
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	cache := &serviceAddresses{}
	fw, err := newOwnedFirewall(t.Context(), c, nil, cache)
	if err != nil {
		t.Fatal(err)
	}
	defer fw.close()
	raw, err := c.coreConfig()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	core, err := startCore(t.Context(), coreFile, dir, raw)
	if err != nil {
		t.Fatal(err)
	}
	defer core.close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ready := make(chan struct{})
	broker := newDNSBroker(c, []string{"epicgames.com"}, nil, cache, func(ip netip.Addr) bool { return ip == netip.MustParseAddr("10.88.0.2") })
	broker.publish = fw.publish
	broker.ready = ready
	broker.resolve = func(_ context.Context, q []byte, selected bool) ([]byte, error) {
		if !selected {
			t.Error("wrong DNS path")
		}
		return dnsAnswer(t, q, [4]byte{198, 51, 100, 9}, 60), nil
	}
	dnsDone := make(chan error, 1)
	go func() { dnsDone <- broker.serve(ctx, ":10553") }()
	select {
	case <-ready:
	case err := <-dnsDone:
		t.Fatal(err)
	case <-time.After(3 * time.Second):
		t.Fatal("DNS not ready")
	}
	if err := fw.alive(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintln(goWrite, "go")
	phase("phase1")
	if _, ok := destinations.Load("198.51.100.9:443"); !ok {
		t.Fatal("selected TCP never reached VPN")
	}
	core.close()
	if err := fw.alive(t.Context(), false); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintln(goWrite, "stopped")
	select {
	case err := <-finished:
		if err != nil {
			t.Fatalf("client: %v: %s", err, output.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("client stuck after stopping VPN")
	}
}
