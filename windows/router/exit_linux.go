//go:build linux

package main

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/YUNGSLXRD/fnport/windows/internal/fakes"
	"github.com/YUNGSLXRD/fnport/windows/internal/vpn"
)

const warpEndpointCachePath = privateConfigDir + "/warp-endpoint.txt"

func loadRememberedWarpEndpoint() string {
	b, err := readPrivate(warpEndpointCachePath, 256)
	if err != nil {
		return ""
	}
	ep := strings.TrimSpace(string(b))
	if a, err := netip.ParseAddrPort(ep); err == nil && a.Addr().Is4() {
		return a.String()
	}
	return ""
}

func saveRememberedWarpEndpoint(ep string) {
	if a, err := netip.ParseAddrPort(strings.TrimSpace(ep)); err == nil && a.Addr().Is4() {
		_ = writePrivate(warpEndpointCachePath, []byte(a.String()+"\n"))
	}
}

func routerWarpEndpoints(first string) []string {
	return vpn.WarpEndpoints(first, loadRememberedWarpEndpoint())
}

func traceExit(ctx context.Context, dial func(context.Context, string) (net.Conn, error)) (exitReport, error) {
	r, err := vpn.TraceExit(ctx, dial)
	if err != nil {
		return exitReport{}, err
	}
	return exitReport{
		Colo:    r.Colo,
		Country: r.Country,
		Address: r.Address,
		RTT:     r.RTT,
	}, nil
}

func (t *nativeTunnel) probeBulkDownload(ctx context.Context) (int64, error) {
	attempt, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return t.dial(ctx, "1.1.1.1:53")
		},
	}
	tr := &http.Transport{
		DisableKeepAlives:  true,
		DisableCompression: true,
		DialContext: func(_ context.Context, _, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			ips, err := resolver.LookupNetIP(attempt, "ip4", host)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				if ip.IsGlobalUnicast() && !ip.IsPrivate() {
					return t.dial(attempt, net.JoinHostPort(ip.String(), port))
				}
			}
			return nil, errors.New("warp_probe_dns_failed")
		},
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport: tr,
		Timeout:   8 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("warp_probe_redirect")
		},
	}
	probeURLs := []string{
		"https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js",
		"https://cachefly.cachefly.net/50mb.test",
	}
	for _, u := range probeURLs {
		req, err := http.NewRequestWithContext(attempt, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		response, err := client.Do(req)
		if err != nil {
			continue
		}
		n, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
		_ = response.Body.Close()
		if response.StatusCode == http.StatusOK && n == 1<<20 && readErr == nil {
			return n, nil
		}
	}
	return 0, errors.New("warp_control_download_failed")
}

// probeExit tests up to two ephemeral UDP source ports per endpoint: when an ISP TSPU
// freezes the first UDP flow after ~25 packets, rebinding the socket often succeeds immediately.
func (t *nativeTunnel) probeExit(ctx context.Context, endpoint string) (exitReport, error) {
	for try := 0; try < 2; try++ {
		if ctx.Err() != nil {
			return exitReport{}, ctx.Err()
		}
		if try > 0 {
			if err := t.rebind(); err != nil {
				return exitReport{}, err
			}
		}
		if err := t.setEndpoint(endpoint); err != nil {
			return exitReport{}, err
		}
		attempt, cancel := context.WithTimeout(ctx, 7*time.Second)
		out, err := traceExit(attempt, t.dial)
		cancel()
		if err != nil {
			// No WireGuard handshake at all: endpoint IP/port is blocked, skip second port try.
			return out, err
		}
		if exitTier(out.Colo) < 0 {
			return out, errors.New("warp_exit_region_excluded")
		}
		n, dlErr := t.probeBulkDownload(ctx)
		if dlErr == nil {
			out.Bytes = n
			return out, nil
		}
	}
	return exitReport{}, errors.New("warp_control_download_failed")
}

func selectNativeExit(ctx context.Context, t *nativeTunnel, first string) (exitReport, error) {
	endpoint, report, err := chooseExit(ctx, routerWarpEndpoints(first), 4*time.Second, t.probeExit)
	if err != nil && ctx.Err() == nil && t.profile.I1 == "" {
		var decoy []byte
		if list := fakes.Load(); len(list) > 0 {
			decoy = list[0].Data
		} else if t.bind != nil {
			decoy = t.bind.fake
		}
		if len(decoy) > 0 && len(decoy) <= 1500 {
			if t.setDecoyI1("<b 0x"+hex.EncodeToString(decoy)+">") == nil {
				endpoint, report, err = chooseExit(ctx, routerWarpEndpoints(first), 4*time.Second, t.probeExit)
			}
		}
	}
	if err != nil {
		return report, err
	}
	// Restore and verify the selected endpoint before enabling LAN interception.
	if err = t.setEndpoint(endpoint); err != nil {
		return report, err
	}
	verify, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	current, err := traceExit(verify, t.dial)
	if err != nil || exitTier(current.Colo) < 0 || exitTier(current.Colo) > exitTier(report.Colo) {
		return report, errors.New("warp_selected_exit_changed")
	}
	saveRememberedWarpEndpoint(endpoint)
	current.Bytes = report.Bytes
	return current, nil
}
