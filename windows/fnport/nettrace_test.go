package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNetworkTraceDomainsAndDNS(t *testing.T) {
	for _, s := range []string{"https://example.org/a?token=secret", "user:pass@example.org", "example.org\nsecret", "a..org", "-bad.org", "127.0.0.1", "a.org/path", "name with spaces"} {
		if got := traceDomain(s); got != "" {
			t.Fatalf("accepted %q as %q", s, got)
		}
	}
	if got := traceDomain("Login.EpicGames.COM."); got != "login.epicgames.com" {
		t.Fatal(got)
	}
	b := []byte(`[{"Entry":"EPIC.example.","Data":"192.0.2.1","TimeToLive":30},{"Entry":"epic.example","Data":"192.0.2.1","TimeToLive":30},{"Entry":"other.example","Data":"192.0.2.1","TimeToLive":60},{"Entry":"expired.example","Data":"192.0.2.1","TimeToLive":0},{"Entry":"https://secret.example/creds","Data":"192.0.2.1","TimeToLive":60},{"Entry":"ipv6.example","Data":"2001:db8::1","TimeToLive":10}]`)
	dns, err := parseNetworkTraceDNS(b)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(dns[netip.MustParseAddr("192.0.2.1")], ","); got != "epic.example,other.example" {
		t.Fatal(got)
	}
	if len(dns[netip.MustParseAddr("2001:db8::1")]) != 1 {
		t.Fatal("missing IPv6 DNS")
	}
	for _, s := range []string{"", "null", "[]", `{}`, `{"Entry":"epic.example","Data":"192.0.2.1","TimeToLive":1}`} {
		if _, err := parseNetworkTraceDNS([]byte(s)); err != nil {
			t.Fatalf("valid cache output %q: %v", s, err)
		}
	}
	if _, err := parseNetworkTraceDNS([]byte(`[{`)); err == nil {
		t.Fatal("accepted corrupt JSON")
	}
	if got := traceDomainSource("DNS"); got != "system_wide_dns_cache_not_process_ownership" {
		t.Fatal(got)
	}
	if got := traceDomainSource("TLS_SNI"); got != "tls_sni" {
		t.Fatal(got)
	}
}

func TestNetworkTraceRotation(t *testing.T) {
	dir := t.TempDir()
	unrelated := filepath.Join(dir, "keep.jsonl")
	if err := os.WriteFile(unrelated, []byte("keep me"), 0600); err != nil {
		t.Fatal(err)
	}
	log, err := openNetworkTraceLog(dir, 1024, 3)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 80; i++ {
		if err := log.write(networkTraceEvent{Timestamp: time.Now().UTC(), Kind: "endpoint", Note: fmt.Sprintf("%d %s", i, strings.Repeat("x", 100))}); err != nil {
			t.Fatal(err)
		}
	}
	if err := log.close(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, e := range entries {
		if !traceLogFilename(e.Name()) {
			continue
		}
		count++
		path := filepath.Join(dir, e.Name())
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		info, err := f.Stat()
		if err != nil {
			t.Fatal(err)
		}
		if info.Size() > 1024 {
			t.Fatal("log exceeded size cap")
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			var event networkTraceEvent
			if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
				t.Fatal(err)
			}
		}
		if err := scanner.Err(); err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
	if count != 3 {
		t.Fatalf("retained %d trace files, want 3", count)
	}
	if b, err := os.ReadFile(unrelated); err != nil || string(b) != "keep me" {
		t.Fatal("rotation modified unrelated file")
	}
	for _, name := range []string{"trace-invalid-000001.jsonl", "trace-20060102T150405.000000000Z-00000x.jsonl", "trace-20060102T150405.000000000Z-000001.jsonl.bak"} {
		if traceLogFilename(name) {
			t.Fatalf("accepted unrelated name %q", name)
		}
	}
}

func TestNetworkTraceQueueNeverBlocks(t *testing.T) {
	trace := &networkTrace{done: make(chan struct{}), queue: make(chan networkTraceObservation, 8)}
	src, dst := netip.MustParseAddrPort("192.0.2.1:12345"), netip.MustParseAddrPort("203.0.113.1:443")
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				trace.observe(6, src, dst, "https://secret.example/path", "TLS_SNI")
			}
		}()
	}
	wg.Wait()
	if got := trace.dropped.Load(); got != 992 {
		t.Fatalf("dropped=%d, want 992", got)
	}
	if got := (<-trace.queue).domain; got != "" {
		t.Fatal("queued a URL")
	}
	close(trace.done)
	trace.observe(6, src, dst, "epic.example", "sni")
	var absent *networkTrace
	absent.observe(6, src, dst, "", "")
	if err := absent.close(); err != nil {
		t.Fatal(err)
	}
}

func TestNetworkTraceDisabledAndCancellation(t *testing.T) {
	trace, err := startNetworkTrace(context.Background(), networkTraceSettings{})
	if trace != nil || err != nil {
		t.Fatalf("disabled: %v %v", trace, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	trace, err = startNetworkTrace(ctx, networkTraceSettings{Enabled: true})
	if trace != nil || err != context.Canceled {
		t.Fatalf("canceled: %v %v", trace, err)
	}
}

func TestNetworkTraceWorkerCloseAndOverflowRecord(t *testing.T) {
	log, err := openNetworkTraceLog(t.TempDir(), 4096, 2)
	if err != nil {
		t.Fatal(err)
	}
	path := log.file.Name()
	ctx, cancel := context.WithCancel(context.Background())
	trace := &networkTrace{cancel: cancel, done: make(chan struct{}), queue: make(chan networkTraceObservation, 4)}
	trace.dropped.Store(27)
	// Cancel before polling to avoid invoking optional DNS commands in this test.
	cancel()
	go trace.run(ctx, log, map[string]bool{"selected.exe": true})
	if err := trace.close(); err != nil {
		t.Fatal(err)
	}
	if err := trace.close(); err != nil {
		t.Fatal("close must be idempotent", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var stop bool
	scanner := bufio.NewScanner(strings.NewReader(string(b)))
	for scanner.Scan() {
		var e networkTraceEvent
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			t.Fatal(err)
		}
		if e.Kind == "stop" {
			stop = true
			if e.Dropped != 27 {
				t.Fatalf("shutdown overflow=%d", e.Dropped)
			}
		}
	}
	if !stop {
		t.Fatal("missing final stop record")
	}
}
