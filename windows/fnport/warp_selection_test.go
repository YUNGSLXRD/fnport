package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestWarpAllowedCountriesAndFallback(t *testing.T) {
	cases := []struct {
		colo string
		rtt  time.Duration
	}{
		{"HKG", 10 * time.Millisecond}, {"DME", 5 * time.Millisecond}, {"FRA", 20 * time.Millisecond},
		{"HEL", 90 * time.Millisecond}, {"RIX", 65 * time.Millisecond}, {"WAW", 80 * time.Millisecond}, {"TLL", 70 * time.Millisecond},
	}
	best := ""
	var rtt time.Duration
	for _, c := range cases {
		if betterWarpExit(c.colo, c.rtt, best, rtt) {
			best, rtt = c.colo, c.rtt
		}
	}
	if best != "RIX" {
		t.Fatalf("chose %s instead of lowest RTT in preferred countries", best)
	}
	if betterWarpExit("FRA", time.Millisecond, best, rtt) {
		t.Fatal("Germany displaced preferred country")
	}
	if betterWarpExit("HKG", time.Millisecond, "", 0) || betterWarpExit("XXX", time.Millisecond, "", 0) {
		t.Fatal("accepted excluded/unknown country")
	}
	best = ""
	rtt = 0
	for _, c := range []struct {
		colo string
		rtt  time.Duration
	}{{"DME", time.Millisecond}, {"MUC", 45 * time.Millisecond}, {"FRA", 60 * time.Millisecond}} {
		if betterWarpExit(c.colo, c.rtt, best, rtt) {
			best, rtt = c.colo, c.rtt
		}
	}
	if best != "MUC" {
		t.Fatal("Germany fallback not compared by RTT")
	}
}

func TestWarpProbeRequiresFullDownload(t *testing.T) {
	for _, size := range []int{256 << 10, warpProbeBytes} {
		t.Run(time.Duration(size).String(), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.CopyN(w, zeroReader{}, int64(size)) }))
			defer srv.Close()
			d, why := measureWarpDownload(context.Background(), srv.Client(), srv.URL+"/")
			if size < warpProbeBytes {
				if why == "" {
					t.Fatal("old small download still accepted")
				}
				return
			}
			if why != "" || d.Bytes != warpProbeBytes || d.mbps() <= 0 {
				t.Fatalf("full download rejected: %s", why)
			}
		})
	}
}

type zeroReader struct{}

func (zeroReader) Read(b []byte) (int, error) { clear(b); return len(b), nil }

func TestWarpProbeRejectsBurstThenStall(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.CopyN(w, zeroReader{}, 256<<10)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	d, why := measureWarpDownload(ctx, srv.Client(), srv.URL+"/")
	if why == "" || d.Bytes != 0 {
		t.Fatal("accepted burst followed by stalled tunnel")
	}
}
