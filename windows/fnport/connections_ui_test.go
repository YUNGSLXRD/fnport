package main

import (
	"encoding/json"
	"errors"
	"image"
	"reflect"
	"strings"
	"testing"
	"time"

	"gioui.org/f32"
	"gioui.org/io/input"
	"gioui.org/io/pointer"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/unit"
	"gioui.org/widget"
)

func TestConnectionDraftSeparatesTraceProcesses(t *testing.T) {
	s := defaultSettings()
	s.Connection.Protocol = "vless"
	s.Connection.Enabled = true
	s.Connection.Config = json.RawMessage(`{"type":"vless","server":"example.org","uuid":"secret"}`)
	s.Connection.Processes = []string{"Discord.exe"}
	s.Trace = networkTraceSettings{Enabled: true, Processes: []string{"FortniteClient-Win64-Shipping.exe"}}
	var cv connectionView
	cv.load(s)
	if cv.showConfig.Value || cv.config.Mask == 0 {
		t.Fatal("configuration must be masked on initial load")
	}
	cv.processes.SetText(" Discord.exe\r\nDISCORD.EXE\n EpicWebHelper.exe \n\n")
	connection, trace, err := cv.draft()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(connection.Processes, []string{"Discord.exe", "EpicWebHelper.exe"}) {
		t.Fatalf("tunnel processes = %v", connection.Processes)
	}
	if !reflect.DeepEqual(trace.Processes, s.Trace.Processes) || !trace.Enabled {
		t.Fatalf("diagnostic settings changed: %+v", trace)
	}
	if string(connection.Config) != string(s.Connection.Config) {
		t.Fatal("outbound JSON changed")
	}
	cv.traceProcesses.SetText("AnotherGame.exe")
	if strings.Contains(cv.processes.Text(), "AnotherGame") {
		t.Fatal("trace editor aliases tunnel editor")
	}
}

func TestConnectionConfigJSON(t *testing.T) {
	full := `{"outbounds":[{"type":"trojan","tag":"vpn","password":"secret"}],"route":{"final":"vpn"}}`
	for _, raw := range []string{full, `{"type":"socks","server":"localhost","server_port":1080}`} {
		got, err := connectionConfigJSON(raw, true)
		if err != nil || string(got) != raw {
			t.Fatalf("JSON did not round trip: %q, %v", got, err)
		}
	}
	for _, raw := range []string{"", "null", "[]", `"secret"`, `{"password":"secret"`} {
		_, err := connectionConfigJSON(raw, true)
		if err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatalf("invalid JSON must fail without exposing secrets: %q, %v", raw, err)
		}
	}
	if raw, err := connectionConfigJSON("", false); err != nil || raw != nil {
		t.Fatalf("optional empty config = %q, %v", raw, err)
	}
}

func TestConnectionPickerPreservesManualAndStoppedProcesses(t *testing.T) {
	var editor widget.Editor
	editor.SetText("Stopped.exe\nDiscord.exe\nManual.exe")
	p := connectionProcessPicker{rows: []*connectionProcessChoice{
		{name: "discord.EXE"},
		{name: "EpicWebHelper.exe", checked: widget.Bool{Value: true}},
	}}
	p.merge(&editor)
	if got := editor.Text(); got != "Stopped.exe\nManual.exe\nEpicWebHelper.exe" {
		t.Fatalf("selection discarded manual names or ignored checkbox: %q", got)
	}
	p.done = make(chan connectionProcessResult, 1)
	p.done <- connectionProcessResult{names: []string{" Z.exe ", "EpicWebHelper.exe", "z.EXE"}}
	p.receive(&editor)
	if p.done != nil || len(p.rows) != 2 || p.rows[0].name != "EpicWebHelper.exe" || !p.rows[0].checked.Value {
		t.Fatalf("refresh did not sort/deduplicate/restore selection: %+v", p)
	}
	p.done = make(chan connectionProcessResult, 1)
	p.done <- connectionProcessResult{err: errors.New("access denied")}
	p.receive(&editor)
	if p.done != nil || p.errorMessage == "" || len(p.rows) != 2 {
		t.Fatal("picker error lost previous rows or stayed busy")
	}
}

func connectionTestContext(router *input.Router, ops *op.Ops) C {
	return layout.Context{Ops: ops, Source: router.Source(), Now: time.Now(),
		Metric:      unit.Metric{PxPerDp: 1, PxPerSp: 1},
		Constraints: layout.Constraints{Max: image.Pt(680, 4000)}}
}

func TestConnectionProtocolDropdownCollapsesAndSelects(t *testing.T) {
	v := newView(newController(defaultSettings()), &pinger{}, &checker{}, nil, func() {})
	v.connections.load(defaultSettings())
	router := new(input.Router)
	frame := func() D {
		ops := new(op.Ops)
		d := v.connectionProtocolDropdown(connectionTestContext(router, ops))
		router.Frame(ops)
		return d
	}
	closed := frame()
	click := func(y float32) {
		at := f32.Pt(25, y)
		router.Queue(pointer.Event{Kind: pointer.Press, Source: pointer.Mouse, Buttons: pointer.ButtonPrimary, Position: at},
			pointer.Event{Kind: pointer.Release, Source: pointer.Mouse, Position: at})
	}
	click(15)
	opened := frame()
	if !v.connections.protocolOpen || opened.Size.Y != closed.Size.Y {
		t.Fatalf("dropdown must expand into a bounded list: closed=%v open=%v", closed.Size, opened.Size)
	}
	click(float32(closed.Size.Y + 55))
	selected := frame()
	if v.connections.protocolOpen || v.connections.protocol != "warp" || selected.Size.Y != closed.Size.Y {
		t.Fatalf("selection did not collapse dropdown: protocol=%q size=%v", v.connections.protocol, selected.Size)
	}
}

func TestConnectionApplyResultConsumedOnUIThread(t *testing.T) {
	v := newView(newController(defaultSettings()), &pinger{}, &checker{}, nil, func() {})
	v.connections.load(defaultSettings())
	v.connections.applyDone = make(chan error, 1)
	done := v.connections.applyDone
	finished := make(chan struct{})
	go func() { done <- errors.New("проверка не пройдена"); close(finished) }()
	<-finished
	if v.connections.failed || v.connections.message != "" {
		t.Fatal("worker mutated UI state")
	}
	router := new(input.Router)
	v.connectionsCard(connectionTestContext(router, new(op.Ops)))
	if v.connections.applyDone != nil || !v.connections.failed || !strings.Contains(v.connections.message, "проверка не пройдена") {
		t.Fatalf("UI did not consume apply error: %q", v.connections.message)
	}
}

func TestConnectionCatalogMatchesBackendAndNativeProtocols(t *testing.T) {
	ids := map[string]bool{}
	for _, p := range connectionUIProtocols {
		if ids[p.id] {
			t.Fatalf("duplicate protocol %q", p.id)
		}
		ids[p.id] = true
	}
	if !ids["warp"] || !ids["amneziawg"] || connectionProtocolLabel("warp") != "WARP" {
		t.Fatal("missing native protocol or raw JSON option")
	}
	for _, id := range []string{"selector", "urltest", "custom", "bridge", "direct", "block", "dns"} {
		if ids[id] {
			t.Fatalf("internal protocol exposed: %s", id)
		}
	}

	s := defaultSettings()
	s.Connection.Protocol = "amneziawg"
	s.Connection.Enabled = true
	s.Connection.Config = json.RawMessage(`{"endpoint":"example.org:51820","jc":4}`)
	var cv connectionView
	cv.load(s)
	connection, _, err := cv.draft()
	if err != nil || connection.Protocol != "amneziawg" || string(connection.Config) != string(s.Connection.Config) {
		t.Fatalf("native AWG JSON changed: %v", err)
	}
}

func TestConnectionOptionalNullConfigAfterReload(t *testing.T) {
	for _, protocol := range []string{"warp", "custom"} {
		t.Run(protocol, func(t *testing.T) {
			s := defaultSettings()
			s.Connection.Protocol = protocol
			s.Connection.Enabled = protocol == "warp"
			s.Trace.Enabled = true
			s.Trace.Processes = []string{"FortniteClient-Win64-Shipping.exe"}
			data, err := json.Marshal(s)
			if err != nil {
				t.Fatal(err)
			}
			var reloaded settings
			if err := json.Unmarshal(data, &reloaded); err != nil {
				t.Fatal(err)
			}
			if string(reloaded.Connection.Config) != "null" {
				t.Fatal("test must exercise persisted null")
			}
			var cv connectionView
			cv.load(reloaded)
			connection, trace, err := cv.draft()
			if err != nil || connection.Config != nil {
				t.Fatalf("optional null failed after reload: %q, %v", connection.Config, err)
			}
			if !reflect.DeepEqual(trace, s.Trace) {
				t.Fatalf("trace changed: %+v", trace)
			}
		})
	}
	for _, raw := range []string{"null", " \nnull\t"} {
		if got, err := connectionConfigJSON(raw, false); err != nil || got != nil {
			t.Fatalf("optional null = %q, %v", got, err)
		}
		if _, err := connectionConfigJSON(raw, true); err == nil {
			t.Fatal("required null was accepted")
		}
	}
}

func TestConnectionPickerRefreshKeepsWidgetIdentity(t *testing.T) {
	var editor widget.Editor
	editor.SetText("Discord.exe\nStopped.exe")
	original := &connectionProcessChoice{name: "Discord.exe"}
	p := connectionProcessPicker{rows: []*connectionProcessChoice{original}, done: make(chan connectionProcessResult, 1)}
	p.done <- connectionProcessResult{names: []string{"DISCORD.EXE", "New.exe"}}
	p.receive(&editor)
	if len(p.rows) != 2 || p.rows[0] != original || original.name != "DISCORD.EXE" || !original.checked.Value {
		t.Fatal("refresh must reuse the case-insensitive widget and sync its selection")
	}
	if editor.Text() != "Discord.exe\nStopped.exe" {
		t.Fatal("refresh changed editor selections")
	}
}

func TestConnectionPickerConsumesClickBeforeRefresh(t *testing.T) {
	for _, tc := range []struct {
		name                              string
		initiallySelected, remainsRunning bool
	}{
		{"check retained row", false, true},
		{"uncheck retained row", true, true},
		{"check disappearing row", false, false},
		{"uncheck disappearing row", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := newView(newController(defaultSettings()), &pinger{}, &checker{}, nil, func() {})
			var editor widget.Editor
			editor.SetText("Stopped.exe")
			if tc.initiallySelected {
				editor.SetText("Stopped.exe\nDiscord.exe")
			}
			row := &connectionProcessChoice{name: "Discord.exe", checked: widget.Bool{Value: tc.initiallySelected}}
			p := connectionProcessPicker{rows: []*connectionProcessChoice{row}}
			router := new(input.Router)
			ops := new(op.Ops)
			v.connectionCheck(connectionTestContext(router, ops), &row.checked, row.name)
			router.Frame(ops)
			at := f32.Pt(10, 10)
			router.Queue(pointer.Event{Kind: pointer.Press, Source: pointer.Mouse, Buttons: pointer.ButtonPrimary, Position: at},
				pointer.Event{Kind: pointer.Release, Source: pointer.Mouse, Position: at})
			p.done = make(chan connectionProcessResult, 1)
			names := []string{"Other.exe"}
			if tc.remainsRunning {
				names = append(names, "DISCORD.EXE")
			}
			p.done <- connectionProcessResult{names: names}
			v.connectionProcessEditor(connectionTestContext(router, new(op.Ops)), &editor, &p)
			selected := strings.Contains(strings.ToLower(editor.Text()), "discord.exe")
			if selected == tc.initiallySelected {
				t.Fatalf("click was lost during refresh: %q", editor.Text())
			}
			if !strings.Contains(editor.Text(), "Stopped.exe") {
				t.Fatal("manual selection was lost")
			}
			if tc.remainsRunning && (p.rows[0] != row || row.checked.Value != selected) {
				t.Fatal("refreshed row lost identity or selection")
			}
		})
	}
}

func TestConnectionMenuApplyPersistsVLESS(t *testing.T) {
	s := defaultSettings()
	s.Fake = ""
	ctl := newController(s)
	saved := make(chan settings, 1)
	ctl.persist = func(s settings) error { saved <- s; return nil }
	v := newView(ctl, &pinger{}, &checker{}, nil, func() {})
	router := new(input.Router)
	frame := func() {
		ops := new(op.Ops)
		gtx := connectionTestContext(router, ops)
		gtx.Constraints = layout.Exact(image.Pt(680, 800))
		v.warpTab(gtx)
		router.Frame(ops)
	}
	frame()
	v.connections.protocolButton.Click()
	frame()
	for i, p := range connectionUIProtocols {
		if p.id == "vless" {
			v.connections.protocolChoices[i].Click()
		}
	}
	frame()
	if !v.connections.enabled.Value || v.connections.protocol != "vless" {
		t.Fatal("menu did not enable chosen connection")
	}
	v.connections.config.SetText("vless://00000000-0000-4000-8000-000000000001@127.0.0.1:443?security=tls&sni=example.org")
	v.connections.epic.Value = true
	v.connections.discord.Value = true
	at := f32.Pt(50, 775)
	router.Queue(pointer.Event{Kind: pointer.Press, Source: pointer.Mouse, Buttons: pointer.ButtonPrimary, Position: at}, pointer.Event{Kind: pointer.Release, Source: pointer.Mouse, Position: at})
	frame()
	select {
	case result := <-saved:
		c := result.Connection
		if !c.Enabled || c.Protocol != "vless" || !c.Epic || !c.Discord || len(c.Config) == 0 || result.Warp.Enabled {
			t.Fatal("chosen VPN was not persisted for both services")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("save was not submitted: %s", v.connections.message)
	}
}
