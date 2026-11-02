package wnet

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestProcessTableLayouts(t *testing.T) {
	for _, tc := range []struct {
		proto uint8
		ipv6  bool
		size  int
	}{{6, false, 24}, {6, true, 56}, {17, false, 12}, {17, true, 28}} {
		t.Run(map[uint8]string{6: "tcp", 17: "udp"}[tc.proto]+map[bool]string{false: "4", true: "6"}[tc.ipv6], func(t *testing.T) {
			b := make([]byte, 4+tc.size)
			binary.LittleEndian.PutUint32(b, 1)
			p := b[4:]
			local, remote := netip.MustParseAddrPort("192.0.2.1:54321"), netip.MustParseAddrPort("203.0.113.2:443")
			if tc.ipv6 {
				local = netip.MustParseAddrPort("[fe80::1%7]:54321")
				remote = netip.MustParseAddrPort("[fe80::2%7]:443")
			}
			if tc.ipv6 {
				a := local.Addr().As16()
				copy(p, a[:])
				binary.BigEndian.PutUint32(p[16:20], 7)
				binary.BigEndian.PutUint16(p[20:24], 54321)
				if tc.proto == 6 {
					a = remote.Addr().As16()
					copy(p[24:], a[:])
					binary.BigEndian.PutUint32(p[40:44], 7)
					binary.BigEndian.PutUint16(p[44:48], 443)
					binary.LittleEndian.PutUint32(p[48:52], 5)
					binary.LittleEndian.PutUint32(p[52:56], 12345)
				} else {
					binary.LittleEndian.PutUint32(p[24:28], 12345)
				}
			} else if tc.proto == 6 {
				binary.LittleEndian.PutUint32(p, 5)
				a := local.Addr().As4()
				copy(p[4:8], a[:])
				binary.BigEndian.PutUint16(p[8:12], 54321)
				a = remote.Addr().As4()
				copy(p[12:16], a[:])
				binary.BigEndian.PutUint16(p[16:20], 443)
				binary.LittleEndian.PutUint32(p[20:24], 12345)
			} else {
				a := local.Addr().As4()
				copy(p, a[:])
				binary.BigEndian.PutUint16(p[4:8], 54321)
				binary.LittleEndian.PutUint32(p[8:12], 12345)
			}
			rows, err := parseProcessTable(b, tc.proto, tc.ipv6)
			if err != nil || len(rows) != 1 {
				t.Fatalf("decode: %v %#v", err, rows)
			}
			r := rows[0]
			if r.local != local || r.pid != 12345 || r.proto != tc.proto {
				t.Fatalf("wrong row: %+v", r)
			}
			if tc.proto == 6 && (r.remote != remote || r.state != 5) {
				t.Fatalf("wrong TCP row: %+v", r)
			}
			if tc.proto == 17 && (r.remote.IsValid() || r.state != 0) {
				t.Fatalf("fabricated UDP remote: %+v", r)
			}
			if _, err := parseProcessTable(b[:len(b)-1], tc.proto, tc.ipv6); err == nil {
				t.Fatal("accepted truncated row")
			}
			binary.LittleEndian.PutUint32(b, ^uint32(0))
			if _, err := parseProcessTable(b, tc.proto, tc.ipv6); err == nil {
				t.Fatal("accepted overflowing count")
			}
		})
	}
	if _, err := parseProcessTable([]byte{0, 0}, 6, false); err == nil {
		t.Fatal("accepted short header")
	}
	if _, err := parseProcessTable([]byte{0, 0, 0, 0}, 1, false); err == nil {
		t.Fatal("accepted invalid protocol")
	}
}

func TestMatchProcessOwner(t *testing.T) {
	src, dst := netip.MustParseAddrPort("192.0.2.1:54321"), netip.MustParseAddrPort("203.0.113.2:443")
	udp := func(s string, pid uint32) processRow {
		return processRow{proto: 17, local: netip.MustParseAddrPort(s), pid: pid}
	}
	tcp := processRow{proto: 6, local: src, remote: dst, state: 5, pid: 42}
	tests := []struct {
		name  string
		proto uint8
		rows  []processRow
		pid   uint32
		err   error
	}{
		{"TCP exact tuple", 6, []processRow{tcp}, 42, nil},
		{"TCP duplicate other PID", 6, []processRow{tcp, {proto: 6, local: src, remote: dst, state: 5, pid: 43}}, 0, ErrOwnerAmbiguous},
		{"TCP listener not owner", 6, []processRow{{proto: 6, local: src, remote: dst, state: 2, pid: 42}}, 0, ErrOwnerNotFound},
		{"TCP wrong remote", 6, []processRow{{proto: 6, local: src, remote: netip.MustParseAddrPort("203.0.113.3:443"), state: 5, pid: 42}}, 0, ErrOwnerNotFound},
		{"UDP specific", 17, []processRow{udp(src.String(), 42)}, 42, nil},
		{"UDP wildcard", 17, []processRow{udp("0.0.0.0:54321", 42)}, 42, nil},
		{"UDP unrelated same port", 17, []processRow{udp("192.0.2.2:54321", 43), udp(src.String(), 42)}, 42, nil},
		{"UDP specific plus competing wildcard", 17, []processRow{udp(src.String(), 42), udp("0.0.0.0:54321", 43)}, 0, ErrOwnerAmbiguous},
		{"UDP duplicates same owner", 17, []processRow{udp(src.String(), 42), udp(src.String(), 42)}, 42, nil},
		{"UDP unknown PID veto", 17, []processRow{udp(src.String(), 42), udp("0.0.0.0:54321", 0)}, 0, ErrOwnerAmbiguous},
		{"UDP possible dual stack competitor", 17, []processRow{udp(src.String(), 42), udp("[::]:54321", 43)}, 0, ErrOwnerAmbiguous},
		{"UDP IPv6 wildcard alone cannot prove IPv4", 17, []processRow{udp("[::]:54321", 42)}, 0, ErrOwnerNotFound},
		{"UDP mapped IPv4", 17, []processRow{udp("[::ffff:192.0.2.1]:54321", 42)}, 42, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pid, err := matchProcessOwner(tt.rows, tt.proto, src, dst)
			if pid != tt.pid || !errors.Is(err, tt.err) {
				t.Fatalf("got (%d,%v), want (%d,%v)", pid, err, tt.pid, tt.err)
			}
		})
	}
	v6src, v6dst := netip.MustParseAddrPort("[fe80::1%7]:54321"), netip.MustParseAddrPort("[fe80::2%7]:443")
	rows := []processRow{udp("[fe80::1%7]:54321", 42), udp("[fe80::1%8]:54321", 43)}
	if pid, err := matchProcessOwner(rows, 17, v6src, v6dst); pid != 42 || err != nil {
		t.Fatalf("scoped IPv6: %d %v", pid, err)
	}
	v6src = netip.MustParseAddrPort("[fe80::1]:54321")
	if _, err := matchProcessOwner(rows, 17, v6src, v6dst); !errors.Is(err, ErrOwnerAmbiguous) {
		t.Fatalf("unscoped IPv6: %v", err)
	}
}

func TestProcessCacheBoundsAndConcurrency(t *testing.T) {
	var c processTableCache
	var calls atomic.Int32
	load := func() ([]processRow, error) { calls.Add(1); return []processRow{{pid: 42}}, nil }
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rows, err := c.get(load)
			if err != nil || len(rows) != 1 {
				t.Error("cache returned invalid snapshot")
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("cache calls = %d", calls.Load())
	}
	c.mu.Lock()
	c.at = time.Now().Add(-251 * time.Millisecond)
	c.mu.Unlock()
	if _, err := c.get(load); err != nil || calls.Load() != 2 {
		t.Fatal("stale table reused")
	}
	if processCacheTTL > 250*time.Millisecond {
		t.Fatal("cache exceeds requested lifetime")
	}
	// Failures replace stale successful rows and are also briefly cached.
	failure := errors.New("enumeration failed")
	c.mu.Lock()
	c.at = time.Time{}
	c.mu.Unlock()
	_, err := c.get(func() ([]processRow, error) { return nil, failure })
	if !errors.Is(err, failure) {
		t.Fatal(err)
	}
	rows, err := c.get(load)
	if rows != nil || !errors.Is(err, failure) {
		t.Fatal("stale ownership used after failure")
	}
}

func TestProcessAPIValidationAndStubs(t *testing.T) {
	src, dst := netip.MustParseAddrPort("192.0.2.1:1234"), netip.MustParseAddrPort("203.0.113.1:443")
	if _, err := ConnectionOwner(1, src, dst); err == nil {
		t.Fatal("accepted invalid protocol")
	}
	if _, err := ConnectionOwner(6, netip.AddrPort{}, dst); err == nil {
		t.Fatal("accepted invalid local endpoint")
	}
	if _, err := ConnectionOwner(6, src, netip.MustParseAddrPort("[::1]:443")); err == nil {
		t.Fatal("accepted mismatched families")
	}
	if runtime.GOOS != "windows" {
		if _, err := ConnectionOwner(6, src, dst); !errors.Is(err, ErrProcessUnsupported) {
			t.Fatal(err)
		}
		if names, err := ProcessNames(); !errors.Is(err, ErrProcessUnsupported) || !reflect.DeepEqual(names, []string(nil)) {
			t.Fatalf("stub: %v %v", names, err)
		}
	}
}

func TestProcessCacheRefreshOnMiss(t *testing.T) {
	var c processTableCache
	calls := 0
	load := func() ([]processRow, error) { calls++; return []processRow{{pid: uint32(calls)}}, nil }
	rows, err := c.get(load)
	if err != nil || rows[0].pid != 1 {
		t.Fatal("initial load failed")
	}
	// A newly created endpoint must not wait for the ordinary 200ms lifetime.
	rows, err = c.refreshOnMiss(load)
	if err != nil || calls != 2 || rows[0].pid != 2 {
		t.Fatal("first miss did not refresh immediately")
	}
	rows, err = c.refreshOnMiss(load)
	if err != nil || calls != 2 || rows[0].pid != 2 {
		t.Fatal("miss storm bypassed the refresh throttle")
	}
	c.mu.Lock()
	c.missAt = time.Now().Add(-11 * time.Millisecond)
	c.mu.Unlock()
	rows, err = c.refreshOnMiss(load)
	if err != nil || calls != 3 || rows[0].pid != 3 {
		t.Fatal("miss refresh did not recover after throttle")
	}
	if processMissRefreshInterval > 10*time.Millisecond {
		t.Fatal("miss refresh delay exceeds contract")
	}
}
