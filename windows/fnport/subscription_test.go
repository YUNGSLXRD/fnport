package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testSubLinks = "vless://00000000-0000-4000-8000-000000000001@server.example:443?security=tls#Finland\nvless://00000000-0000-4000-8000-000000000002@other.example:443?security=tls#Poland"
const testSubID = "0123456789abcdef0123456789abcdef"

func TestSubscriptionFormatsAndSelection(t *testing.T) {
	for _, body := range []string{testSubLinks, base64.StdEncoding.EncodeToString([]byte(testSubLinks)), base64.RawURLEncoding.EncodeToString([]byte(testSubLinks))} {
		nodes, skipped, err := parseSubscription([]byte(body))
		if err != nil || len(nodes) != 2 || skipped != 0 {
			t.Fatal("subscription not parsed", err)
		}
		s := &connectionSubscription{URL: "https://sub.example/private-token", Nodes: nodes, Selected: nodes[1].ID}
		settings := defaultSettings()
		settings.Connection = connectionSettings{Enabled: true, Protocol: "vless", Config: nodes[1].Config, Subscription: s}
		var cv connectionView
		cv.load(settings)
		conn, _, err := cv.draft()
		if err != nil || !bytes.Equal(conn.Config, nodes[1].Config) || conn.Subscription.Selected != nodes[1].ID {
			t.Fatal("selection not retained", err)
		}
		copy := cloneSubscription(conn.Subscription)
		copy.Nodes[0].Config[0] = '!'
		if conn.Subscription.Nodes[0].Config[0] == '!' {
			t.Fatal("subscription cache alias")
		}
		cv.enabled.Value = false
		cv.protocol = "off"
		if conn, _, err = cv.draft(); err != nil || conn.Enabled || conn.Subscription == nil {
			t.Fatal("cannot disable cached subscription", err)
		}
		cv.enabled.Value = true
		cv.protocol = "warp"
		if conn, _, err = cv.draft(); err != nil || conn.Protocol != "warp" || conn.Subscription == nil {
			t.Fatal("switch to WARP loses subscription", err)
		}
	}
	raw := `{"outbounds":[{"type":"direct","tag":"direct"},{"type":"selector","tag":"select"},{"type":"vless","tag":"Finland","server":"test.example","server_port":443,"uuid":"test"}]}`
	nodes, skipped, err := parseSubscription([]byte(raw))
	if err != nil || len(nodes) != 1 || skipped != 2 {
		t.Fatal("sing-box subscription not filtered", err)
	}
	old := &connectionSubscription{Nodes: nodes, Selected: nodes[0].ID}
	next := cloneSubscription(old)
	next.Selected = ""
	retainSubscriptionSelection(next, old)
	if next.Selected != old.Selected {
		t.Fatal("refresh changed chosen server")
	}
}
func TestSubscriptionHTTPAndHWID(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("x-hwid") != testSubID || r.Header.Get("User-Agent") != "fnport/dev9/"+testSubID || r.Header.Get("x-device-os") == "" {
			t.Error("missing identity headers")
		}
		w.Header().Set("profile-title", "base64:"+base64.StdEncoding.EncodeToString([]byte("Test subscription")))
		w.Write([]byte(base64.StdEncoding.EncodeToString([]byte(testSubLinks))))
	}))
	defer server.Close()
	for i := 0; i < 2; i++ {
		s, err := fetchSubscription(context.Background(), server.URL+"/private-token", testSubID, "dev9", server.Client())
		if err != nil || len(s.Nodes) != 2 || s.Title != "Test subscription" {
			t.Fatal("fetch failed", err)
		}
	}
	if requests.Load() != 2 {
		t.Fatal("unexpected retries")
	}
}
func TestSubscriptionHWIDDenialAndPrivacy(t *testing.T) {
	for _, header := range []string{"x-hwid-max-devices-reached", "x-hwid-limit", "x-hwid-not-supported"} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(header, "true")
			w.Write([]byte(testSubLinks))
		}))
		s, err := fetchSubscription(context.Background(), server.URL+"/private-token", testSubID, "dev9", server.Client())
		server.Close()
		if err == nil || s != nil || strings.Contains(err.Error(), "private-token") {
			t.Fatal("denied profile accepted or URL leaked")
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "private-secret", 403) }))
	defer server.Close()
	_, err := fetchSubscription(context.Background(), server.URL+"/private-token", testSubID, "dev9", server.Client())
	if err == nil || strings.Contains(err.Error(), "private-") {
		t.Fatal("response body/URL leaked")
	}
}
func TestSubscriptionIdentityPersistsAcrossUpdates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device-id")
	var wg sync.WaitGroup
	ids := make(chan string, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, err := subscriptionDeviceIDAt(path)
			if err != nil {
				t.Error(err)
			}
			ids <- id
		}()
	}
	wg.Wait()
	close(ids)
	first := ""
	for id := range ids {
		if first == "" {
			first = id
		}
		if id != first || !regexp.MustCompile(`^[a-zA-Z0-9=-]{10,64}$`).MatchString(id) {
			t.Fatal("unstable or invalid HWID")
		}
	}
	second, err := subscriptionDeviceIDAt(path)
	if err != nil || second != first {
		t.Fatal("HWID rotated")
	}
	if !strings.HasSuffix(subscriptionUA("0.6.4", first), "/"+first) || !strings.HasSuffix(subscriptionUA("0.7.0", second), "/"+first) {
		t.Fatal("update changes HWID")
	}
	if os.WriteFile(path, []byte("broken"), 0600) != nil {
		t.Fatal("test write")
	}
	if _, err = subscriptionDeviceIDAt(path); err == nil {
		t.Fatal("corrupt identity silently reset")
	}
}
func TestSubscriptionRedirectDoesNotLeakIdentity(t *testing.T) {
	var reached atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Add(1); w.Write([]byte(testSubLinks)) }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL+"/private-token", 302) }))
	defer source.Close()
	_, err := fetchSubscription(context.Background(), source.URL, testSubID, "dev9", source.Client())
	if err == nil || reached.Load() != 0 {
		t.Fatal("HWID forwarded to a different origin")
	}
}
func TestSubscriptionReadLimitAndUnsupportedContent(t *testing.T) {
	for _, body := range []string{"<html>private-secret</html>", "not-a-subscription", strings.Repeat("A", subscriptionMaxBytes+1)} {
		_, _, err := parseSubscription([]byte(body))
		if err == nil || strings.Contains(err.Error(), "private-secret") {
			t.Fatal("invalid subscription accepted or leaked")
		}
	}
	settings := defaultSettings()
	settings.Connection.Enabled = true
	settings.Connection.Protocol = "vless"
	var cv connectionView
	cv.load(settings)
	cv.config.SetText("https://sub.example/private-token")
	if _, _, err := cv.draft(); err == nil || strings.Contains(err.Error(), "private-token") {
		t.Fatal("unloaded subscription can be applied")
	}
}
func TestSubscriptionRoundTripJSON(t *testing.T) {
	nodes, _, _ := parseSubscription([]byte(testSubLinks))
	s := defaultSettings()
	s.Connection.Subscription = &connectionSubscription{URL: "https://sub.example/token", Nodes: nodes, Selected: nodes[1].ID, Updated: time.Now()}
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var loaded settings
	if json.Unmarshal(data, &loaded) != nil || loaded.Connection.Subscription.node().ID != nodes[1].ID {
		t.Fatal("cached selection lost")
	}
}
