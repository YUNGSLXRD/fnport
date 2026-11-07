//go:build linux

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

func routerWarpEndpoints(first string) []string {
	out := []string{}
	if first != "" {
		out = append(out, first)
	}
	ranges := []string{"188.114.96", "188.114.97", "188.114.98", "188.114.99", "162.159.192"}
	for _, port := range []int{2408, 500, 1701, 4500, 854, 878, 894} {
		for _, prefix := range ranges {
			out = append(out, fmt.Sprintf("%s.%d:%d", prefix, 1+rand.IntN(254), port))
		}
	}
	return out
}
func traceExit(ctx context.Context, dial func(context.Context, string) (net.Conn, error)) (exitReport, error) {
	var out exitReport
	start := time.Now()
	tr := &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{ServerName: "one.one.one.one", MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return dial(ctx, "1.1.1.1:443") }}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 6 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("exit_redirect_rejected") }}
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://one.one.one.one/cdn-cgi/trace", nil)
	response, err := client.Do(req)
	if err != nil {
		return out, errors.New("exit_trace_failed")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return out, errors.New("exit_trace_failed")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 8193))
	if err != nil || len(body) > 8192 {
		return out, errors.New("exit_trace_failed")
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(body), "\n") {
		if key, value, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			values[key] = value
		}
	}
	if len(values["colo"]) != 3 {
		return out, errors.New("exit_trace_invalid")
	}
	ip, err := netip.ParseAddr(values["ip"])
	if err != nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return out, errors.New("exit_trace_invalid")
	}
	out.Colo, out.Country, out.Address, out.RTT = values["colo"], preferredColos[values["colo"]], ip.String(), time.Since(start)
	return out, nil
}
func (t *nativeTunnel) probeExit(ctx context.Context, endpoint string) (exitReport, error) {
	if err := t.setEndpoint(endpoint); err != nil {
		return exitReport{}, err
	}
	attempt, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	out, err := traceExit(attempt, t.dial)
	if err != nil {
		return out, err
	}
	if exitTier(out.Colo) < 0 {
		return out, errors.New("warp_exit_region_excluded")
	}
	// DNS for the control download goes through the tunnel as well.
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) { return t.dial(ctx, "1.1.1.1:53") }}
	tr := &http.Transport{DisableKeepAlives: true, DisableCompression: true, DialContext: func(_ context.Context, _, address string) (net.Conn, error) {
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
	}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("warp_probe_redirect") }}
	for _, url := range []string{"https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js", "https://cachefly.cachefly.net/50mb.test"} {
		req, _ := http.NewRequestWithContext(attempt, "GET", url, nil)
		response, err := client.Do(req)
		if err != nil {
			continue
		}
		n, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
		response.Body.Close()
		if response.StatusCode == 200 && n == 1<<20 && readErr == nil {
			out.Bytes = n
			return out, nil
		}
	}
	return out, errors.New("warp_control_download_failed")
}
func selectNativeExit(ctx context.Context, t *nativeTunnel, first string) (exitReport, error) {
	endpoint, report, err := chooseExit(ctx, routerWarpEndpoints(first), 4*time.Second, t.probeExit)
	if err != nil {
		return report, err
	}
	// The kernel tunnel is reused while comparing candidates. Restore and verify
	// the selected candidate before enabling any LAN interception.
	if err = t.setEndpoint(endpoint); err != nil {
		return report, err
	}
	verify, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	current, err := traceExit(verify, t.dial)
	if err != nil || exitTier(current.Colo) < 0 || exitTier(current.Colo) > exitTier(report.Colo) {
		return report, errors.New("warp_selected_exit_changed")
	}
	current.Bytes = report.Bytes
	return current, nil
}
