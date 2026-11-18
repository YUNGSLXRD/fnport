package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/YUNGSLXRD/fnport/windows/internal/wnet"
)

const releasesURL = "https://github.com/YUNGSLXRD/fnport/releases/latest"

var (
	updateOnce sync.Once
	updateTag  atomic.Value // string: "0.8.0" when a newer release exists
)

func latestUpdate() string {
	s, _ := updateTag.Load().(string)
	return s
}

// checkUpdateOnce performs at most one silent background release check per session.
// Network errors or dev builds produce zero log noise.
func checkUpdateOnce() {
	if version == "" || version == "dev" || strings.Contains(version, "-") {
		return
	}
	updateOnce.Do(func() {
		go func() {
			time.Sleep(2 * time.Second)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			tr := &http.Transport{
				Proxy:           nil,
				TLSClientConfig: &tls.Config{ServerName: "api.github.com", MinVersion: tls.VersionTLS12},
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					ips := lookupAllContext(ctx, "api.github.com")
					if len(ips) == 0 {
						return nil, io.EOF
					}
					return wnet.DialTCP(ctx, netip.AddrPortFrom(ips[0], 443))
				},
			}
			defer tr.CloseIdleConnections()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/repos/YUNGSLXRD/fnport/releases/latest", nil)
			if err != nil {
				return
			}
			req.Header.Set("Accept", "application/vnd.github+json")
			req.Header.Set("User-Agent", "fnport/"+version)
			resp, err := (&http.Client{Transport: tr, Timeout: 3 * time.Second}).Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return
			}
			var release struct {
				TagName string `json:"tag_name"`
				Draft   bool   `json:"draft"`
				Pre     bool   `json:"prerelease"`
			}
			if json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&release) != nil || release.Draft || release.Pre {
				return
			}
			remote := strings.TrimPrefix(strings.TrimSpace(release.TagName), "v")
			if newerSemver(remote, strings.TrimPrefix(version, "v")) {
				updateTag.Store(remote)
				changes.Add(1)
			}
		}()
	})
}

func newerSemver(candidate, current string) bool {
	parse := func(s string) ([3]int, bool) {
		var out [3]int
		parts := strings.Split(s, ".")
		if len(parts) != 3 {
			return out, false
		}
		for i, p := range parts {
			n, err := strconv.Atoi(p)
			if err != nil || n < 0 {
				return out, false
			}
			out[i] = n
		}
		return out, true
	}
	a, ok1 := parse(candidate)
	b, ok2 := parse(current)
	if !ok1 || !ok2 {
		return false
	}
	for i := 0; i < 3; i++ {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return false
}
