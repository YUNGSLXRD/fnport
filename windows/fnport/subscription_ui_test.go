package main

import (
	"context"
	"encoding/json"
	"fmt"
	"image"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gioui.org/f32"
	"gioui.org/io/input"
	"gioui.org/io/pointer"
	"gioui.org/layout"
	"gioui.org/op"
)

func TestSubscriptionInlineServerListScrollAndSelect(t *testing.T) {
	var lines []string
	for i := 0; i < 40; i++ {
		lines = append(lines, fmt.Sprintf("vless://00000000-0000-4000-8000-%012d@server.example:443?security=tls#Server%%20%02d", i+1, i+1))
	}
	nodes, _, err := parseSubscription([]byte(strings.Join(lines, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	v := newView(newController(defaultSettings()), &pinger{}, &checker{}, nil, func() {})
	v.connections.load(defaultSettings())
	v.connections.setMode("vpn", time.Now())
	v.connections.config.SetText("https://sub.example/token")
	v.connections.loadSubscriptionView(&connectionSubscription{URL: "https://sub.example/token", Nodes: nodes, Selected: nodes[0].ID})
	router := new(input.Router)
	now := time.Now()
	frame := func() {
		ops := new(op.Ops)
		gtx := connectionTestContext(router, ops)
		gtx.Now = now
		now = now.Add(16 * time.Millisecond)
		gtx.Constraints = layout.Exact(image.Pt(600, 320))
		v.updateConnectionImports(gtx)
		v.subscriptionServerList(gtx)
		router.Frame(ops)
	}
	click := func(x, y float32) {
		at := f32.Pt(x, y)
		router.Queue(
			pointer.Event{Kind: pointer.Press, Source: pointer.Mouse, Buttons: pointer.ButtonPrimary, Position: at},
			pointer.Event{Kind: pointer.Release, Source: pointer.Mouse, Position: at},
		)
	}
	frame()
	router.Queue(pointer.Event{Kind: pointer.Scroll, Source: pointer.Mouse, Position: f32.Pt(70, 90), Scroll: f32.Pt(0, 180)})
	for i := 0; i < 40; i++ {
		frame()
	}
	click(60, 65)
	frame()
	sub := v.connections.imports.subscription
	if sub.Selected == nodes[0].ID || sub.ActiveNode() == nil {
		t.Fatal("scrolled server could not be selected")
	}
	conn, _, err := v.connections.draft()
	if err != nil || string(conn.Config) != string(sub.ActiveNode().Config) {
		t.Fatal("selection is not the applied config", err)
	}
}

func TestAWGFileButtonLoadsContentOnlyForAmnezia(t *testing.T) {
	cfgFile := filepath.Join(t.TempDir(), "config.conf")
	if os.WriteFile(cfgFile, []byte(sampleAWGConf), 0o600) != nil {
		t.Fatal("write fixture")
	}
	v := newView(newController(defaultSettings()), &pinger{}, &checker{}, nil, func() {})
	v.connections.load(defaultSettings())
	v.connections.setMode("vpn", time.Now())
	picked := make(chan struct{}, 1)
	v.pickAWGFile = func() (string, error) { picked <- struct{}{}; return cfgFile, nil }
	gtx := connectionTestContext(new(input.Router), new(op.Ops))
	v.connections.imports.importFile.Click()
	v.updateConnectionImports(gtx)
	select {
	case <-picked:
		t.Fatal("file import exposed for non-AWG mode")
	default:
	}
	v.connections.setMode("amneziawg", time.Now())
	v.connections.imports.importFile.Click()
	v.updateConnectionImports(gtx)
	deadline := time.Now().Add(2 * time.Second)
	for v.connections.imports.fileDone != nil && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
		v.updateConnectionImports(gtx)
	}
	if v.connections.config.Text() != sampleAWGConf || v.connections.failed {
		t.Fatal("file import did not populate the editor")
	}
	select {
	case <-picked:
	default:
		t.Fatal("file picker not called")
	}
}

func TestSubscriptionSelectionPersistsOnApply(t *testing.T) {
	s := defaultSettings()
	s.Fake = ""
	ctl := newController(s)
	saved := make(chan settings, 1)
	ctl.persist = func(s settings) error { saved <- s; return nil }
	v := newView(ctl, &pinger{}, &checker{}, nil, func() {})
	v.connections.load(s)
	v.connections.setMode("vpn", time.Now())
	v.connections.config.SetText("https://sub.example/token")
	nodes, _, _ := parseSubscription([]byte(testSubLinks))
	v.connections.loadSubscriptionView(&connectionSubscription{URL: "https://sub.example/token", Nodes: nodes, Selected: nodes[0].ID})
	v.connections.imports.serverChoices[1].Click()
	v.connections.saveTop.Click()
	v.warpTab(connectionTestContext(new(input.Router), new(op.Ops)))
	select {
	case got := <-saved:
		if got.Connection.Subscription.Selected != nodes[1].ID || string(got.Connection.Config) != string(nodes[1].Config) {
			t.Fatal("applied a different server")
		}
	case <-time.After(time.Second):
		t.Fatal("subscription selection not saved")
	}
}

func TestSubscriptionPingRunsOnceOnLoadAndByButton(t *testing.T) {
	var calls atomic.Int32
	oldFn := measureProfilePingFunc
	measureProfilePingFunc = func(_ context.Context, _ string, _ json.RawMessage, _ string) (time.Duration, error) {
		calls.Add(1)
		return 37 * time.Millisecond, nil
	}
	defer func() { measureProfilePingFunc = oldFn }()

	nodes, _, err := parseSubscription([]byte(testSubLinks))
	if err != nil || len(nodes) == 0 {
		t.Fatalf("parseSubscription: %v", err)
	}
	s := defaultSettings()
	s.Connection.Enabled = true
	s.Connection.Protocol = nodes[0].Protocol
	s.Connection.Subscription = &connectionSubscription{
		URL:      "https://sub.example/token",
		Nodes:    nodes,
		Selected: nodes[0].ID,
	}

	v := newView(newController(s), &pinger{}, &checker{}, nil, func() {})
	v.autoPingConnections = true
	v.connections.load(s)

	router := new(input.Router)
	frame := func() {
		ops := new(op.Ops)
		gtx := connectionTestContext(router, ops)
		v.updateConnectionImports(gtx)
		v.vpnModePanel(gtx)
		router.Frame(ops)
	}

	// Initial frame triggers auto-ping once for all nodes in the subscription.
	frame()
	deadline := time.Now().Add(time.Second)
	for v.connections.imports.pinging && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
		frame()
	}
	wantFirst := int32(len(nodes))
	if got := calls.Load(); got != wantFirst {
		t.Fatalf("initial auto-ping calls = %d, want %d", got, wantFirst)
	}
	if st := v.connections.imports.nodePings[nodes[0].ID]; !st.Checked || !st.OK || st.RTT != 37*time.Millisecond {
		t.Fatalf("unexpected stored node ping: %+v", st)
	}

	// Subsequent frames must NOT re-trigger background pings.
	for i := 0; i < 10; i++ {
		frame()
	}
	if got := calls.Load(); got != wantFirst {
		t.Fatalf("idle frames triggered extra pings: got %d, want %d", got, wantFirst)
	}

	// Clicking «Пинг» button triggers exactly one more round.
	v.connections.imports.pingBtn.Click()
	frame()
	deadline = time.Now().Add(time.Second)
	for v.connections.imports.pinging && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
		frame()
	}
	if got := calls.Load(); got != wantFirst*2 {
		t.Fatalf("button ping calls = %d, want %d", got, wantFirst*2)
	}
}
