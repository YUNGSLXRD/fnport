package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/YUNGSLXRD/fnport/windows/internal/wnet"
)

type networkTraceSettings struct {
	Enabled   bool     `json:"enabled"`
	Processes []string `json:"processes,omitempty"`
}

func defaultNetworkTraceSettings() networkTraceSettings {
	return networkTraceSettings{Enabled: devTrace == "on", Processes: []string{
		"FortniteClient-Win64-Shipping.exe", "FortniteClient-Win64-Shipping_EAC_EOS.exe",
		"EpicGamesLauncher.exe", "EpicWebHelper.exe", "FortniteLauncher.exe",
	}}
}

const (
	networkTraceQueueSize = 1024
	networkTraceMaxBytes  = 32 * 1024 * 1024
	networkTraceKeepFiles = 8
	networkTracePoll      = time.Second
	networkTraceDNSPoll   = 10 * time.Second
)

// The trace owns no routes or packet capture handles. Endpoint polling continues
// independently of the engine. Events contain only endpoints, executable
// basenames, state, and domain names: never payloads, URLs or command lines.
type networkTrace struct {
	cancel  context.CancelFunc
	done    chan struct{}
	queue   chan networkTraceObservation
	dropped atomic.Uint64
	mu      sync.Mutex
	err     error
}

type networkTraceObservation struct {
	at             time.Time
	proto          uint8
	src, dst       netip.AddrPort
	domain, source string
}

type networkTraceEvent struct {
	Timestamp         time.Time `json:"timestamp"`
	Kind              string    `json:"kind"`
	Protocol          uint8     `json:"protocol,omitempty"`
	Local             string    `json:"local,omitempty"`
	Remote            string    `json:"remote,omitempty"`
	PID               uint32    `json:"pid,omitempty"`
	Process           string    `json:"process,omitempty"`
	TCPState          uint32    `json:"tcp_state,omitempty"`
	Domain            string    `json:"domain,omitempty"`
	DomainSource      string    `json:"domain_source,omitempty"`
	DNSNames          []string  `json:"dns_names,omitempty"`
	DNSCorrelation    string    `json:"dns_correlation,omitempty"`
	DNSCacheTimestamp string    `json:"dns_cache_timestamp,omitempty"`
	OwnerStatus       string    `json:"owner_status,omitempty"`
	Dropped           uint64    `json:"dropped,omitempty"`
	Note              string    `json:"note,omitempty"`
}

// startNetworkTrace returns nil,nil when disabled (no files, commands or workers).
// Caller owns cancellation and should call close to drain/close the log and
// inspect asynchronous I/O errors. Trace failures never affect forwarding.
func startNetworkTrace(ctx context.Context, s networkTraceSettings) (*networkTrace, error) {
	if !s.Enabled {
		return nil, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !networkTraceSupported() {
		return nil, wnet.ErrProcessUnsupported
	}
	names := make(map[string]bool)
	if len(s.Processes) == 0 {
		s.Processes = defaultNetworkTraceSettings().Processes
	}
	for _, name := range s.Processes {
		name = strings.TrimSpace(name)
		if name == "" || strings.ContainsAny(name, `/\`) {
			return nil, errors.New("trace processes must be executable basenames")
		}
		names[strings.ToLower(name)] = true
	}
	log, err := openNetworkTraceLog(filepath.Join(appDir(), "network-trace"), networkTraceMaxBytes, networkTraceKeepFiles)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	t := &networkTrace{cancel: cancel, done: make(chan struct{}), queue: make(chan networkTraceObservation, networkTraceQueueSize)}
	go t.run(ctx, log, names)
	return t, nil
}

// observe never enumerates processes, writes files or waits for queue capacity.
// Ownership is resolved later and may miss very short-lived flows. DNS table
// polls provide no UDP peers; these observations add peers actually seen by the
// engine. Pass only a hostname (e.g. TLS SNI), never an HTTP URL.
func (t *networkTrace) observe(proto uint8, src, dst netip.AddrPort, domain, domainSource string) {
	if t == nil || (proto != 6 && proto != 17) || !src.IsValid() || !dst.IsValid() {
		return
	}
	select {
	case <-t.done:
		return
	default:
	}
	o := networkTraceObservation{at: time.Now().UTC(), proto: proto, src: src, dst: dst, domain: traceDomain(domain), source: traceDomainSource(domainSource)}
	select {
	case t.queue <- o:
	default:
		t.dropped.Add(1)
	}
}

func (t *networkTrace) close() error {
	if t == nil {
		return nil
	}
	t.cancel()
	<-t.done
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.err
}

func (t *networkTrace) run(ctx context.Context, log *networkTraceLog, selected map[string]bool) {
	defer close(t.done)
	defer func() {
		if err := log.close(); err != nil {
			t.setError(err)
		}
	}()
	write := func(e networkTraceEvent) bool {
		if e.Timestamp.IsZero() {
			e.Timestamp = time.Now().UTC()
		}
		if err := log.write(e); err != nil {
			t.setError(err)
			return false
		}
		return true
	}
	if !write(networkTraceEvent{Kind: "start", Note: "Endpoint snapshots can miss short-lived connections. UDP tables show binds, not peers. DNS cache correlation is system-wide and cannot prove process ownership. No payloads, URLs, credentials or command lines are captured."}) {
		return
	}
	ticker := time.NewTicker(networkTracePoll)
	defer ticker.Stop()
	var dns map[netip.Addr][]string
	var dnsAt time.Time
	poll := func() bool {
		rows, err := wnet.ProcessConnections()
		if err != nil && !write(networkTraceEvent{Kind: "poll_error", Note: "Native endpoint enumeration failed or returned partial results."}) {
			return false
		}
		if dnsAt.IsZero() || time.Since(dnsAt) >= networkTraceDNSPoll {
			dnsAt = time.Now()
			var dnsErr error
			dns, dnsErr = readNetworkTraceDNS(ctx)
			if ctx.Err() != nil {
				return true
			}
			if dnsErr != nil && !write(networkTraceEvent{Kind: "dns_cache_error", Note: "System-wide DNS cache unavailable; no ownership inference is possible."}) {
				return false
			}
		}
		now := time.Now().UTC()
		for _, row := range rows {
			if !selected[strings.ToLower(row.Owner.Name)] {
				continue
			}
			e := networkTraceEvent{Timestamp: now, Kind: "endpoint", Protocol: row.Protocol, Local: row.Local.String(), PID: row.Owner.PID, Process: row.Owner.Name, TCPState: row.State, OwnerStatus: "native_table_snapshot"}
			if row.Remote.IsValid() && !row.Remote.Addr().IsUnspecified() {
				e.Remote = row.Remote.String()
				e.DNSNames = dns[row.Remote.Addr().Unmap().WithZone("")]
				if len(e.DNSNames) > 0 {
					e.DNSCorrelation = "system_wide_cache_not_process_ownership"
					e.DNSCacheTimestamp = dnsAt.UTC().Format(time.RFC3339Nano)
				}
			}
			if row.Protocol == 17 {
				e.Note = "UDP bound endpoint; peer and traffic unknown."
			}
			if !write(e) {
				return false
			}
		}
		if n := t.dropped.Swap(0); n > 0 {
			return write(networkTraceEvent{Kind: "overflow", Dropped: n})
		}
		return true
	}
	observation := func(o networkTraceObservation) bool {
		owner, err := wnet.ConnectionOwner(o.proto, o.src, o.dst)
		// Unknown ownership cannot establish membership in the chosen process set;
		// keep only an aggregate count, never unrelated endpoints or domain names.
		if err != nil {
			return write(networkTraceEvent{Timestamp: o.at, Kind: "owner_unresolved", OwnerStatus: traceOwnerStatus(err)})
		}
		if !selected[strings.ToLower(owner.Name)] {
			return true
		}
		e := networkTraceEvent{Timestamp: o.at, Kind: "observed", Protocol: o.proto, Local: o.src.String(), Remote: o.dst.String(), PID: owner.PID, Process: owner.Name, Domain: o.domain, OwnerStatus: "cached_table_lookup_after_observation"}
		if e.Domain != "" {
			e.DomainSource = o.source
		}
		e.DNSNames = dns[o.dst.Addr().Unmap().WithZone("")]
		if len(e.DNSNames) > 0 {
			e.DNSCorrelation = "system_wide_cache_not_process_ownership"
			e.DNSCacheTimestamp = dnsAt.UTC().Format(time.RFC3339Nano)
		}
		return write(e)
	}
	// Poll immediately, even if no engine traffic is observed.
	if !poll() {
		return
	}
	for {
		select {
		case <-ctx.Done():
			// Only drain the bounded queue present at cancellation; producers may still
			// call observe until the parent's engine shutdown completes.
			pending := len(t.queue)
			for i := 0; i < pending; i++ {
				if !observation(<-t.queue) {
					return
				}
			}
			write(networkTraceEvent{Kind: "stop", Dropped: t.dropped.Swap(0)})
			return
		case o := <-t.queue:
			if !observation(o) {
				return
			}
		case <-ticker.C:
			if !poll() {
				return
			}
		}
	}
}

func (t *networkTrace) setError(err error) {
	t.mu.Lock()
	t.err = errors.Join(t.err, err)
	t.mu.Unlock()
}

func traceOwnerStatus(err error) string {
	switch {
	case errors.Is(err, wnet.ErrOwnerAmbiguous):
		return "ambiguous"
	case errors.Is(err, wnet.ErrOwnerNotFound):
		return "not_found"
	default:
		return "unavailable"
	}
}

// Restrict caller-provided domain fields to hostnames. This deliberately drops
// URLs, IP literals, whitespace, control characters and arbitrary annotations.
func traceDomain(s string) string {
	s = strings.ToLower(strings.TrimSuffix(s, "."))
	if len(s) == 0 || len(s) > 253 {
		return ""
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return ""
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return ""
		}
		for _, c := range label {
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
				return ""
			}
		}
	}
	return s
}

func traceDomainSource(s string) string {
	switch strings.ToLower(s) {
	case "sni", "tls", "tls_sni", "tls-sni":
		return "tls_sni"
	case "dns", "dns_cache", "dns-cache", "system_dns_cache":
		return "system_wide_dns_cache_not_process_ownership"
	default:
		return "caller_supplied_hostname"
	}
}

type networkTraceLog struct {
	dir, session string
	file         *os.File
	size, limit  int64
	keep, part   int
}

func openNetworkTraceLog(dir string, limit int64, keep int) (*networkTraceLog, error) {
	if limit < 1024 || keep < 1 {
		return nil, errors.New("invalid trace log limits")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	l := &networkTraceLog{dir: dir, session: time.Now().UTC().Format("20060102T150405.000000000Z"), limit: limit, keep: keep}
	if err := l.rotate(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *networkTraceLog) rotate() error {
	if err := l.close(); err != nil {
		return err
	}
	l.part++
	path := filepath.Join(l.dir, fmt.Sprintf("trace-%s-%06d.jsonl", l.session, l.part))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	l.file, l.size = f, 0
	entries, err := os.ReadDir(l.dir)
	if err != nil {
		l.close()
		return err
	}
	var names []string
	for _, e := range entries {
		// Prune only filenames generated by this logger, not arbitrary user files.
		n := e.Name()
		if !e.IsDir() && traceLogFilename(n) {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for len(names) > l.keep {
		old := names[0]
		names = names[1:]
		if old == filepath.Base(path) {
			continue
		}
		if err := os.Remove(filepath.Join(l.dir, old)); err != nil {
			l.close()
			return err
		}
	}
	return nil
}

func traceLogFilename(s string) bool {
	// Timestamp has fixed nanosecond precision; segment is six digits.
	if len(s) != len("trace-20060102T150405.000000000Z-000001.jsonl") || !strings.HasPrefix(s, "trace-") || !strings.HasSuffix(s, ".jsonl") {
		return false
	}
	_, err := time.Parse("20060102T150405.000000000Z", s[6:32])
	if err != nil || s[32] != '-' {
		return false
	}
	for _, c := range s[33:39] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func (l *networkTraceLog) write(e networkTraceEvent) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if int64(len(b)) > l.limit {
		return errors.New("trace record exceeds rotation limit")
	}
	if l.size+int64(len(b)) > l.limit {
		if err := l.rotate(); err != nil {
			return err
		}
	}
	n, err := l.file.Write(b)
	l.size += int64(n)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	return err
}

func (l *networkTraceLog) close() error {
	if l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	return err
}

// Only A/AAAA records with positive remaining TTL are eligible. The cache is
// system-wide; a matching IP neither identifies the querying process nor proves
// that a connection used that hostname. Keep only sanitized hostnames.
func parseNetworkTraceDNS(b []byte) (map[netip.Addr][]string, error) {
	type record struct {
		Entry string `json:"Entry"`
		Data  string `json:"Data"`
		TTL   uint32 `json:"TimeToLive"`
	}
	b = []byte(strings.TrimSpace(strings.TrimPrefix(string(b), "\ufeff")))
	var records []record
	if len(b) == 0 {
		return map[netip.Addr][]string{}, nil
	}
	if b[0] == '{' {
		var r record
		if err := json.Unmarshal(b, &r); err != nil {
			return nil, err
		}
		records = append(records, r)
	} else if err := json.Unmarshal(b, &records); err != nil {
		return nil, err
	}
	out := make(map[netip.Addr][]string)
	for _, r := range records {
		name := traceDomain(r.Entry)
		ip, err := netip.ParseAddr(r.Data)
		if err != nil || name == "" || r.TTL == 0 {
			continue
		}
		ip = ip.Unmap().WithZone("")
		if ip.IsUnspecified() {
			continue
		}
		names := out[ip]
		duplicate := false
		for _, n := range names {
			if n == name {
				duplicate = true
				break
			}
		}
		// Bound per-record growth even on a machine with an unusually large cache.
		if !duplicate && len(names) < 32 {
			out[ip] = append(names, name)
		}
	}
	for ip := range out {
		sort.Strings(out[ip])
	}
	return out, nil
}
