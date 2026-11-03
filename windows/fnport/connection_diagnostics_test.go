package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestConnectionFailurePrivacyAndCodes(t *testing.T) {
	e := connectionFailure("local_connect", &net.OpError{Op: "dial", Net: "tcp", Err: syscall.Errno(10061)})
	if e.code != 10061 || e.timeout {
		t.Fatal(e)
	}
	e = connectionFailure("local_auth", fmt.Errorf("password=private-secret: %w", context.DeadlineExceeded))
	if !e.timeout || strings.Contains(e.Error(), "secret") {
		t.Fatal(e)
	}
	if s := connectionFailure("transport", errors.New("vless://private-secret")).Error(); strings.Contains(s, "secret") {
		t.Fatal(s)
	}
	m := newTransportMock(t)
	m.reject = true
	m.start()
	c := transportClient(m)
	defer c.close()
	_, err := c.dial(context.Background(), netip.MustParseAddrPort("203.0.113.1:443"))
	var setup *connectionSetupError
	if !errors.As(err, &setup) || setup.stage != "socks_reply" || setup.code == 0 {
		t.Fatalf("lost SOCKS reply code: %v", err)
	}
}

func TestConnectionFailureWindow(t *testing.T) {
	var w connectionFailureWindow
	now := time.Now()
	if n, ok := w.record(now); !ok || n != 1 {
		t.Fatal(n, ok)
	}
	for i := 0; i < 99; i++ {
		if _, ok := w.record(now.Add(time.Second)); ok {
			t.Fatal("failure flood")
		}
	}
	if n, ok := w.record(now.Add(10 * time.Second)); !ok || n != 100 {
		t.Fatal(n, ok)
	}
}

func TestConnectionCoreDiagnosticPrivacy(t *testing.T) {
	var d connectionCoreDiagnostic
	for _, s := range []string{strings.Repeat("private-secret ", 1000), "pa", "nic: private-secret\n"} {
		if n, err := d.Write([]byte(s)); n != len(s) || err != nil {
			t.Fatal(n, err)
		}
	}
	if d.category() != "panic" || len(d.tail) > 64 {
		t.Fatal("bad category or unbounded retention")
	}
	d.Write([]byte("fatal error: runtime: out of memory\npanic: private-secret"))
	if d.category() != "out_of_memory" {
		t.Fatal(d.category())
	}
}

func TestConnectionCoreExitAccounting(t *testing.T) {
	for _, stop := range []bool{false, true} {
		t.Run(fmt.Sprint("requested=", stop), func(t *testing.T) {
			var child *exec.Cmd
			command := func(ctx context.Context, args ...string) *exec.Cmd {
				cmd := exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=^TestTransportCoreHelper$", "--"}, args...)...)
				cmd.Env = append(os.Environ(), "FNPORT_TRANSPORT_HELPER=1")
				if args[0] == "run" {
					child = cmd
				}
				return cmd
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			c, err := startConnectionCommand(ctx, transportSettings(`{"type":"direct"}`), "Ethernet", command)
			if err != nil {
				t.Fatal(err)
			}
			defer c.close()
			if stop {
				cancel()
			} else if err := child.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-c.done:
			case <-time.After(3 * time.Second):
				t.Fatal("missing exit event")
			}
			c.mu.Lock()
			unexpected, code := c.exitUnexpected, c.exitCode
			c.mu.Unlock()
			if unexpected == stop || code == 0 {
				t.Fatalf("unexpected=%t exit=%d", unexpected, code)
			}
		})
	}
}
