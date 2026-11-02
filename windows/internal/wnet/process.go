package wnet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"time"
)

// ProcessOwner identifies an executable by basename, never command line or path.
type ProcessOwner struct {
	PID  uint32
	Name string
}

var (
	ErrProcessUnsupported = errors.New("process ownership is only supported on Windows")
	ErrOwnerNotFound      = errors.New("connection owner not found")
	ErrOwnerAmbiguous     = errors.New("connection ownership is ambiguous")
)

// ProcessConnection is a point-in-time native endpoint observation. UDP has no
// remote endpoint: its table proves a bind, not traffic to a particular peer.
type ProcessConnection struct {
	Protocol      uint8
	Local, Remote netip.AddrPort
	State         uint32 // Windows MIB_TCP_STATE; zero for UDP
	Owner         ProcessOwner
}

type processRow struct {
	proto         uint8
	local, remote netip.AddrPort
	state, pid    uint32
}

const processCacheTTL = 200 * time.Millisecond
const processMissRefreshInterval = 10 * time.Millisecond

type processCachedName struct {
	name string
	err  error
}

type processTableCache struct {
	mu     sync.Mutex
	at     time.Time
	missAt time.Time
	rows   []processRow
	err    error
	names  map[uint32]processCachedName
}

// Separate locks/caches prevent TCP requests from refreshing UDP or vice versa.
var processTables = map[uint8]*processTableCache{6: {}, 17: {}}

func (c *processTableCache) get(load func() ([]processRow, error)) ([]processRow, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.at.IsZero() || time.Since(c.at) >= processCacheTTL {
		// Timestamp before enumeration: a slow enumeration never extends staleness.
		c.at = time.Now()
		c.rows, c.err = load()
		c.names = make(map[uint32]processCachedName)
	}
	return c.rows, c.err
}

// A new socket may appear immediately after a cached snapshot. Retry a miss
// once against a fresh snapshot, sharing a 10ms throttle across callers. The
// ordinary 200ms cache alone would miss the first packet of new UDP sessions.
func (c *processTableCache) refreshOnMiss(load func() ([]processRow, error)) ([]processRow, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.missAt.IsZero() || time.Since(c.missAt) >= processMissRefreshInterval {
		c.missAt = time.Now()
		c.at = c.missAt
		c.rows, c.err = load()
		c.names = make(map[uint32]processCachedName)
	}
	return c.rows, c.err
}

func (c *processTableCache) executable(pid uint32) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Do not reuse a name past the table lifetime, including after lock contention.
	if time.Since(c.at) >= processCacheTTL {
		return processExecutable(pid)
	}
	if v, ok := c.names[pid]; ok {
		return v.name, v.err
	}
	name, err := processExecutable(pid)
	c.names[pid] = processCachedName{name, err}
	return name, err
}

// ConnectionOwner looks up an outbound local-to-remote tuple. Native tables are
// cached for at most 200ms; a result is a snapshot, not a security boundary (PIDs
// and ports can be reused). UDP cannot distinguish peers or competing owners.
func ConnectionOwner(proto uint8, src, dst netip.AddrPort) (ProcessOwner, error) {
	c, ok := processTables[proto]
	if !ok {
		return ProcessOwner{}, fmt.Errorf("unsupported IP protocol %d", proto)
	}
	if !src.IsValid() || !dst.IsValid() || src.Port() == 0 || dst.Port() == 0 || src.Addr().IsUnspecified() || dst.Addr().IsUnspecified() {
		return ProcessOwner{}, errors.New("ownership requires concrete local and remote endpoints")
	}
	src, dst = normalizeProcessEndpoint(src), normalizeProcessEndpoint(dst)
	if src.Addr().Is4() != dst.Addr().Is4() {
		return ProcessOwner{}, errors.New("ownership address families differ")
	}
	load := func() ([]processRow, error) { return readProcessRows(proto) }
	var lastErr error = ErrOwnerNotFound
	for attempt := 0; attempt < 2; attempt++ {
		var rows []processRow
		var err error
		if attempt == 0 {
			rows, err = c.get(load)
		} else {
			rows, err = c.refreshOnMiss(load)
		}
		if err != nil {
			return ProcessOwner{}, err
		}
		pid, err := matchProcessOwner(rows, proto, src, dst)
		if err != nil {
			if !errors.Is(err, ErrOwnerNotFound) {
				return ProcessOwner{}, err
			}
			lastErr = err
			continue
		}
		name, err := c.executable(pid)
		if err != nil {
			lastErr = fmt.Errorf("executable for PID %d: %w", pid, err)
			continue
		}
		return ProcessOwner{PID: pid, Name: name}, nil
	}
	return ProcessOwner{}, lastErr
}

func normalizeProcessEndpoint(ep netip.AddrPort) netip.AddrPort {
	a := ep.Addr().Unmap()
	if z := a.Zone(); z != "" {
		if _, err := strconv.ParseUint(z, 10, 32); err != nil {
			if iface, err := net.InterfaceByName(z); err == nil {
				a = a.WithZone(strconv.Itoa(iface.Index))
			}
		}
	}
	return netip.AddrPortFrom(a, ep.Port())
}

func processAddrMatches(bound, actual netip.Addr) bool {
	if bound.Is4() != actual.Is4() {
		return false
	}
	if bound.IsUnspecified() {
		return true
	}
	if bound.WithZone("") != actual.WithZone("") {
		return false
	}
	// Missing IPv6 scope is not enough to disambiguate interfaces. Include every
	// scope as a candidate rather than accidentally preferring the first row.
	return bound.Zone() == "" || actual.Zone() == "" || bound.Zone() == actual.Zone()
}

func matchProcessOwner(rows []processRow, proto uint8, src, dst netip.AddrPort) (uint32, error) {
	var pid uint32
	found, definite, unknown := false, false, false
	for _, r := range rows {
		r.local = normalizeProcessEndpoint(r.local)
		if r.remote.IsValid() {
			r.remote = normalizeProcessEndpoint(r.remote)
		}
		if r.proto != proto || r.local.Port() != src.Port() {
			continue
		}
		candidate := false
		certain := true
		if proto == 6 {
			candidate = r.state >= 3 && r.state <= 12 && r.local.Addr().WithZone("") == src.Addr().WithZone("") &&
				processAddrMatches(r.local.Addr(), src.Addr()) && r.remote.Port() == dst.Port() &&
				r.remote.Addr().WithZone("") == dst.Addr().WithZone("") && processAddrMatches(r.remote.Addr(), dst.Addr())
		} else {
			candidate = processAddrMatches(r.local.Addr(), src.Addr())
			// IPv6 wildcard sockets MAY be dual stack. IP Helper does not expose
			// IPV6_V6ONLY; they can veto an IPv4 attribution but cannot prove it.
			if src.Addr().Is4() && r.local.Addr().Is6() && r.local.Addr().IsUnspecified() {
				candidate, certain = true, false
			}
		}
		if !candidate {
			continue
		}
		if r.pid == 0 {
			unknown = true
			continue
		}
		if found && pid != r.pid {
			return 0, ErrOwnerAmbiguous
		}
		pid, found = r.pid, true
		definite = definite || certain
	}
	if unknown {
		return 0, ErrOwnerAmbiguous
	}
	if !found || !definite {
		return 0, ErrOwnerNotFound
	}
	return pid, nil
}

// parseProcessTable decodes the documented DWORD-aligned OWNER_PID layouts,
// without unsafe casts or assumptions about the Go host's struct alignment.
func parseProcessTable(b []byte, proto uint8, ipv6 bool) ([]processRow, error) {
	size := 0
	switch {
	case proto == 6 && !ipv6:
		size = 24
	case proto == 6 && ipv6:
		size = 56
	case proto == 17 && !ipv6:
		size = 12
	case proto == 17 && ipv6:
		size = 28
	default:
		return nil, errors.New("invalid process table protocol")
	}
	if len(b) < 4 {
		return nil, errors.New("short process table header")
	}
	count := uint64(binary.LittleEndian.Uint32(b))
	if count > uint64((len(b)-4)/size) {
		return nil, errors.New("truncated process table")
	}
	rows := make([]processRow, 0, int(count))
	u32 := binary.LittleEndian.Uint32
	port := func(b []byte) uint16 { return binary.BigEndian.Uint16(b[:2]) }
	addr6 := func(b []byte, scope []byte) netip.Addr {
		a := netip.AddrFrom16([16]byte(b[:16]))
		// IP Helper documents scope IDs in network byte order.
		if s := binary.BigEndian.Uint32(scope); s != 0 {
			a = a.WithZone(strconv.FormatUint(uint64(s), 10))
		}
		return a
	}
	for i := 0; i < int(count); i++ {
		p := b[4+i*size : 4+(i+1)*size]
		r := processRow{proto: proto}
		if ipv6 {
			r.local = netip.AddrPortFrom(addr6(p, p[16:20]), port(p[20:24]))
			if proto == 6 {
				r.remote = netip.AddrPortFrom(addr6(p[24:], p[40:44]), port(p[44:48]))
				r.state, r.pid = u32(p[48:52]), u32(p[52:56])
			} else {
				r.pid = u32(p[24:28])
			}
		} else if proto == 6 {
			r.state = u32(p[:4])
			r.local = netip.AddrPortFrom(netip.AddrFrom4([4]byte(p[4:8])), port(p[8:12]))
			r.remote = netip.AddrPortFrom(netip.AddrFrom4([4]byte(p[12:16])), port(p[16:20]))
			r.pid = u32(p[20:24])
		} else {
			r.local = netip.AddrPortFrom(netip.AddrFrom4([4]byte(p[:4])), port(p[4:8]))
			r.pid = u32(p[8:12])
		}
		rows = append(rows, r)
	}
	return rows, nil
}

// ProcessNames returns sorted, case-insensitively deduplicated executable
// basenames from a fresh process snapshot. No shell or command lines are used.
func ProcessNames() ([]string, error) {
	processes, err := processSnapshot()
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	names := make([]string, 0, len(processes))
	for _, name := range processes {
		key := processNameKey(name)
		if name != "" && !seen[key] {
			seen[key] = true
			names = append(names, name)
		}
	}
	sort.Slice(names, func(i, j int) bool { return processNameKey(names[i]) < processNameKey(names[j]) })
	return names, nil
}

// ProcessConnections independently polls TCP/UDP IPv4/IPv6 tables, bypassing
// the routing ownership cache. Partial results accompany enumeration errors.
func ProcessConnections() ([]ProcessConnection, error) {
	names, err := processSnapshot()
	if err != nil {
		return nil, err
	}
	var out []ProcessConnection
	var errs []error
	for _, proto := range []uint8{6, 17} {
		rows, err := readProcessRows(proto)
		if err != nil {
			errs = append(errs, err)
		}
		for _, r := range rows {
			out = append(out, ProcessConnection{Protocol: r.proto, Local: r.local, Remote: r.remote, State: r.state, Owner: ProcessOwner{PID: r.pid, Name: names[r.pid]}})
		}
	}
	return out, errors.Join(errs...)
}
