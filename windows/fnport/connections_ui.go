package main

import (
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"

	"github.com/YUNGSLXRD/fnport/windows/internal/fonts"
	"github.com/YUNGSLXRD/fnport/windows/internal/vpn"
	"github.com/YUNGSLXRD/fnport/windows/internal/wnet"
)

var connectionModes = []struct {
	id    string
	label string
}{
	{"off", "Выключено"},
	{"warp", "WARP"},
	{"amneziawg", "AmneziaWG"},
	{"vpn", "VPN и подписки"},
}

var connectionUIProtocols = []struct{ id, label string }{
	{"off", "Выключено"},
	{"warp", "WARP"},
	{"amneziawg", "AmneziaWG / WireGuard"},
	{"vless", "VLESS"},
	{"hysteria2", "Hysteria 2"},
	{"shadowsocks", "Shadowsocks"},
	{"trojan", "Trojan"},
	{"socks", "SOCKS5"},
}

func modeOfProtocol(proto string, enabled bool) string {
	if !enabled || proto == "" || proto == "off" {
		return "off"
	}
	switch proto {
	case "warp":
		return "warp"
	case "amneziawg", "wireguard":
		return "amneziawg"
	default:
		return "vpn"
	}
}

func modeIndex(mode string) int {
	for i, m := range connectionModes {
		if m.id == mode {
			return i
		}
	}
	return 0
}

func connectionProtocolLabel(protocol string) string {
	return vpn.ProtocolLabel(protocol)
}

func connectionConfigJSON(text string, required bool) (json.RawMessage, error) {
	text = strings.TrimSpace(text)
	if text == "" || text == "null" {
		if required {
			return nil, fmt.Errorf("вставьте конфигурацию JSON")
		}
		return nil, nil
	}
	var object map[string]json.RawMessage
	if json.Unmarshal([]byte(text), &object) != nil || object == nil {
		return nil, fmt.Errorf("конфигурация должна быть объектом JSON")
	}
	return json.RawMessage(text), nil
}

type connectionProcessChoice struct {
	name    string
	checked widget.Bool
}

type connectionProcessResult struct {
	names []string
	err   error
}

type connectionProcessPicker struct {
	search       widget.Editor
	manual       widget.Clickable
	manualOpen   bool
	open         bool
	button       widget.Clickable
	refresh      widget.Clickable
	list         widget.List
	rows         []*connectionProcessChoice
	done         chan connectionProcessResult
	errorMessage string
}

// connectionView holds UI-thread-only state for the «Подключения» tab.
type connectionView struct {
	imports       connectionImportView
	loaded        bool
	registering   bool
	speedRunning  bool
	speedDone     chan string
	warpConfOpen  bool
	warpConfBtn   widget.Clickable
	warpApplyConf widget.Clickable
	warpImportBtn widget.Clickable
	warpConf      widget.Editor

	mode          string
	prevMode      string
	modeSince     time.Time
	modeButtons   [4]widget.Clickable
	enabled       widget.Bool
	protocol      string
	epic          widget.Bool
	epicRouting   widget.Enum // "auto" or "always"
	discord       widget.Bool
	showConfig    widget.Bool
	trace         widget.Bool
	traceOpen     widget.Clickable
	traceExpanded bool

	config         widget.Editor
	awgSavedText   string
	vpnSavedText   string
	domains        widget.Editor
	processes      widget.Editor
	traceProcesses widget.Editor
	final          widget.Editor

	picker      connectionProcessPicker
	tracePicker connectionProcessPicker
	save        widget.Clickable
	saveTop     widget.Clickable
	reset       widget.Clickable
	openTrace   widget.Clickable

	applyDone chan error
	message   string
	failed    bool
}

func connectionProcessLines(text string) []string {
	var names []string
	seen := make(map[string]bool)
	for _, line := range strings.Split(text, "\n") {
		name := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if name == "" || seen[strings.ToLower(name)] {
			continue
		}
		seen[strings.ToLower(name)] = true
		names = append(names, name)
	}
	return names
}

func (cv *connectionView) setMode(next string, now time.Time) {
	if cv.mode == next {
		return
	}
	switch cv.mode {
	case "amneziawg":
		cv.awgSavedText = cv.config.Text()
	case "vpn":
		cv.vpnSavedText = cv.config.Text()
	}
	cv.prevMode = cv.mode
	cv.mode = next
	cv.modeSince = now
	cv.enabled.Value = next != "off"

	switch next {
	case "off":
		cv.protocol = "off"
	case "warp":
		cv.protocol = "warp"
	case "amneziawg":
		cv.protocol = "amneziawg"
		cv.config.SingleLine = false
		cv.config.SetText(cv.awgSavedText)
	case "vpn":
		if cv.protocol == "" || cv.protocol == "off" || cv.protocol == "warp" || cv.protocol == "amneziawg" {
			if sub := cv.imports.subscription; sub != nil && sub.ActiveNode() != nil {
				cv.protocol = sub.ActiveNode().Protocol
			} else {
				cv.protocol = "vless"
			}
		}
		cv.config.SingleLine = true
		cv.config.SetText(cv.vpnSavedText)
	}
}

func (cv *connectionView) load(s settings) {
	migrateLegacyWarp(&s)
	cv.enabled.Value = s.Connection.Enabled
	cv.epic.Value = s.Connection.Epic
	if s.Connection.EpicAlways {
		cv.epicRouting.Value = "always"
	} else {
		cv.epicRouting.Value = "auto"
	}
	cv.discord.Value = s.Connection.Discord

	proto := s.Connection.Protocol
	if proto == "" {
		proto = "warp"
	}
	cv.protocol = proto
	if !cv.enabled.Value {
		cv.protocol = "off"
	}
	cv.mode = modeOfProtocol(proto, cv.enabled.Value)
	cv.prevMode = cv.mode
	cv.modeSince = time.Time{}

	cv.awgSavedText = ""
	cv.vpnSavedText = ""
	rawStr := strings.TrimSpace(string(s.Connection.Config))
	if rawStr == "null" {
		rawStr = ""
	}
	displayText := s.Connection.SourceText
	if displayText == "" {
		if proto == "amneziawg" && rawStr != "" {
			if cfg, err := vpn.ParseAWGJSON(s.Connection.Config); err == nil {
				displayText = vpn.FormatWGConf(cfg)
			} else {
				displayText = rawStr
			}
		} else {
			displayText = rawStr
		}
	}

	cv.loadSubscriptionView(s.Connection.Subscription)
	if sub := cv.imports.subscription; sub != nil && sub.URL != "" {
		cv.vpnSavedText = sub.URL
		if proto != "amneziawg" {
			displayText = sub.URL
		}
	}
	if proto == "amneziawg" {
		cv.awgSavedText = displayText
	} else if proto != "warp" && proto != "off" {
		cv.vpnSavedText = displayText
	}

	cv.config.SingleLine = cv.mode != "amneziawg"
	cv.config.SetText(displayText)
	cv.config.Mask = '•'
	cv.showConfig.Value = false

	cv.warpConf.SingleLine = false
	cv.domains.SingleLine = false
	cv.domains.SetText(strings.Join(s.Connection.Domains, "\n"))
	cv.processes.SetText(strings.Join(s.Connection.Processes, "\n"))
	cv.final.SingleLine = true
	cv.final.SetText(s.Connection.Final)
	cv.trace.Value = s.Trace.Enabled
	cv.traceProcesses.SetText(strings.Join(s.Trace.Processes, "\n"))
	cv.picker.open, cv.tracePicker.open = false, false
	cv.picker.list.Axis, cv.tracePicker.list.Axis = layout.Vertical, layout.Vertical
	cv.imports.initialPingPending = true
	cv.loaded = true
}

func (cv *connectionView) syncLegacyModeFromProtocol() {
	if !cv.enabled.Value || cv.protocol == "off" {
		cv.mode = "off"
	} else {
		cv.mode = modeOfProtocol(cv.protocol, true)
	}
}

func (cv *connectionView) draft() (connectionSettings, networkTraceSettings, error) {
	cv.syncLegacyModeFromProtocol()
	var raw json.RawMessage
	var subscription *connectionSubscription
	protocol := cv.protocol
	sourceText := ""
	final := strings.TrimSpace(cv.final.Text())
	text := strings.TrimSpace(cv.config.Text())

	domains := vpn.ParseDomainList(cv.domains.Text())
	rawDomainLines := strings.Split(cv.domains.Text(), "\n")
	for _, dl := range rawDomainLines {
		dl, _, _ = strings.Cut(dl, "#")
		dl = strings.TrimSpace(dl)
		if dl != "" && vpn.CleanDomain(dl) == "" {
			return connectionSettings{}, networkTraceSettings{}, fmt.Errorf("некорректный домен «%s»", dl)
		}
	}

	switch cv.mode {
	case "off":
		subscription = cloneSubscription(cv.imports.subscription)
		if protocol == "off" || protocol == "" {
			protocol = "warp"
		}
		if text != "" && text != "null" && !subscriptionURL(text) {
			if b, det, _, err := vpn.ImportProfile(text, false); err == nil && b != nil {
				raw = b
				if det != "" {
					protocol = det
				}
			}
		} else if n := subscription.ActiveNode(); n != nil {
			raw = n.Config
		}
	case "warp":
		protocol = "warp"
		subscription = cloneSubscription(cv.imports.subscription)
		if n := subscription.ActiveNode(); n != nil {
			raw = n.Config
		}
	case "amneziawg":
		protocol = "amneziawg"
		subscription = cloneSubscription(cv.imports.subscription)
		if text == "" || text == "null" {
			if cv.enabled.Value {
				return connectionSettings{}, networkTraceSettings{}, fmt.Errorf("вставьте конфигурацию .conf или импортируйте файл")
			}
		} else if looksLikeAWGConf(text) {
			_, b, err := vpn.ImportAWG(text)
			if err != nil {
				return connectionSettings{}, networkTraceSettings{}, err
			}
			raw = b
			sourceText = text
		} else {
			b, err := connectionConfigJSON(text, cv.enabled.Value)
			if err != nil {
				return connectionSettings{}, networkTraceSettings{}, err
			}
			raw = b
		}
	default: // "vpn"
		if subscriptionURL(text) {
			sub := cv.imports.subscription
			if sub == nil || sub.URL != text || sub.ActiveNode() == nil {
				if cv.enabled.Value {
					return connectionSettings{}, networkTraceSettings{}, fmt.Errorf("сначала нажмите «Загрузить» и выберите сервер подписки")
				}
			} else {
				n := sub.ActiveNode()
				raw, protocol = n.Config, n.Protocol
				subscription = cloneSubscription(sub)
				sourceText = text
				final = ""
			}
		} else if strings.Contains(text, "://") {
			b, detected, _, err := vpn.ImportProfile(text, cv.enabled.Value)
			if err != nil {
				return connectionSettings{}, networkTraceSettings{}, err
			}
			raw = b
			if detected != "" {
				protocol = detected
			}
			sourceText = text
			final = ""
		} else {
			b, err := connectionConfigJSON(text, cv.enabled.Value)
			if err != nil {
				return connectionSettings{}, networkTraceSettings{}, err
			}
			raw = b
			if b != nil {
				var obj map[string]any
				if json.Unmarshal(b, &obj) == nil {
					if typ, ok := obj["type"].(string); ok && vpn.CoreOutbounds[typ] {
						protocol = typ
					} else if _, hasOut := obj["outbounds"]; hasOut || obj["endpoints"] != nil {
						protocol = "custom"
					} else if protocol == "vless" || protocol == "warp" || protocol == "off" {
						if typ, ok := obj["type"].(string); ok && typ != "" {
							protocol = "custom"
						}
					}
				}
			}
		}
	}

	cs := connectionSettings{
		Enabled:      cv.enabled.Value,
		Protocol:     protocol,
		Config:       raw,
		SourceText:   sourceText,
		Epic:         cv.epic.Value,
		EpicAlways:   cv.epicRouting.Value == "always",
		Discord:      cv.discord.Value,
		Domains:      domains,
		Processes:    connectionProcessLines(cv.processes.Text()),
		Final:        final,
		Subscription: subscription,
	}
	ts := networkTraceSettings{
		Enabled:   cv.trace.Value,
		Processes: connectionProcessLines(cv.traceProcesses.Text()),
	}
	return cs, ts, nil
}

func (p *connectionProcessPicker) fetch() {
	if p.done != nil {
		return
	}
	p.errorMessage = ""
	p.done = make(chan connectionProcessResult, 1)
	done := p.done
	go func() {
		names, err := wnet.ProcessNames()
		done <- connectionProcessResult{names: names, err: err}
		changes.Add(1)
	}()
}

func (p *connectionProcessPicker) receive(editor *widget.Editor) {
	if p.done == nil {
		return
	}
	select {
	case result := <-p.done:
		p.done = nil
		if result.err != nil {
			p.errorMessage = "Не удалось получить список процессов: " + result.err.Error()
			return
		}
		names := connectionProcessLines(strings.Join(result.names, "\n"))
		sort.Slice(names, func(i, j int) bool { return strings.ToLower(names[i]) < strings.ToLower(names[j]) })
		selected := make(map[string]bool)
		for _, name := range connectionProcessLines(editor.Text()) {
			selected[strings.ToLower(name)] = true
		}
		existing := make(map[string]*connectionProcessChoice, len(p.rows))
		for _, row := range p.rows {
			existing[strings.ToLower(row.name)] = row
		}
		p.rows = nil
		p.list.Position = layout.Position{}
		for _, name := range names {
			key := strings.ToLower(name)
			row := existing[key]
			if row == nil {
				row = &connectionProcessChoice{}
			}
			row.name, row.checked.Value = name, selected[key]
			p.rows = append(p.rows, row)
		}
	default:
	}
}

func (p *connectionProcessPicker) merge(editor *widget.Editor) {
	known := make(map[string]bool)
	for _, row := range p.rows {
		known[strings.ToLower(row.name)] = row.checked.Value
	}
	var selected []string
	seen := make(map[string]bool)
	for _, name := range connectionProcessLines(editor.Text()) {
		key := strings.ToLower(name)
		if checked, ok := known[key]; ok && !checked {
			continue
		}
		selected = append(selected, name)
		seen[key] = true
	}
	for _, row := range p.rows {
		key := strings.ToLower(row.name)
		if row.checked.Value && !seen[key] {
			selected = append(selected, row.name)
			seen[key] = true
		}
	}
	editor.SetText(strings.Join(selected, "\n"))
}

func (v *view) connectionCheck(gtx C, state *widget.Bool, label string) D {
	cb := material.CheckBox(v.th, state, label)
	cb.Color, cb.IconColor, cb.Size = colText, colGreen, unit.Dp(18)
	cb.TextSize = unit.Sp(13)
	return cb.Layout(gtx)
}

func (v *view) compactButton(gtx C, b *widget.Clickable, label string, primary, enabled bool) D {
	gtx.Constraints.Min.X = 0
	return v.button(gtx, b, label, primary, enabled)
}

func (v *view) smallButton(gtx C, c *widget.Clickable, s string, enabled bool) D {
	gtx.Constraints.Min.X = 0
	bg, fg := colLine, colText
	if !enabled {
		gtx = gtx.Disabled()
		bg, fg = colLine, colGray
	} else if c.Hovered() {
		bg = colBtnHover
	}
	return c.Layout(gtx, func(gtx C) D {
		return layout.Background{}.Layout(gtx,
			func(gtx C) D { return fill(gtx, bg, gtx.Dp(7)) },
			func(gtx C) D {
				return layout.Inset{Top: 6, Bottom: 6, Left: 12, Right: 12}.Layout(gtx, bold(v.label(12, fg, s)).Layout)
			})
	})
}

func (v *view) divider(gtx C) D {
	h := max(1, gtx.Dp(1))
	sz := image.Pt(gtx.Constraints.Max.X, h)
	paint.FillShape(gtx.Ops, colLine, clip.Rect{Max: sz}.Op())
	return D{Size: sz}
}

// connectionModeSelector renders a 4-way segmented pill selector matching Opus's sliding sidebar nav.
func (v *view) connectionModeSelector(gtx C) D {
	cv := &v.connections
	cv.syncLegacyModeFromProtocol()
	for i, m := range connectionModes {
		if cv.modeButtons[i].Clicked(gtx) {
			cv.setMode(m.id, gtx.Now)
		}
	}

	pad := gtx.Dp(4)
	totalW := gtx.Constraints.Max.X
	itemH := gtx.Dp(36)
	totalH := itemH + pad*2
	innerW := max(0, totalW-pad*2)
	segW := innerW / len(connectionModes)

	paint.FillShape(gtx.Ops, colField, clip.UniformRRect(image.Rect(0, 0, totalW, totalH), gtx.Dp(10)).Op(gtx.Ops))

	fromIdx := modeIndex(cv.prevMode)
	toIdx := modeIndex(cv.mode)
	t := 1.0
	if !cv.modeSince.IsZero() {
		t = easeOut(float64(gtx.Now.Sub(cv.modeSince)) / float64(tabAnim))
		if t < 1 {
			v.animating = true
		}
	}
	pillX := pad + int(float64(fromIdx*segW)*(1-t)+float64(toIdx*segW)*t)
	pillW := segW
	if toIdx == len(connectionModes)-1 && t == 1 {
		pillW = totalW - pad - pillX
	}
	pillRect := image.Rect(pillX, pad, pillX+pillW, pad+itemH)
	pillRRect := clip.UniformRRect(pillRect, gtx.Dp(8))
	paint.FillShape(gtx.Ops, colCard, pillRRect.Op(gtx.Ops))
	paint.FillShape(gtx.Ops, colLine, clip.Stroke{Path: pillRRect.Path(gtx.Ops), Width: 1}.Op())

	off := pushOffset(gtx, pad, pad)
	var kids []layout.FlexChild
	for i, m := range connectionModes {
		i, m := i, m
		kids = append(kids, layout.Flexed(1, func(gtx C) D {
			active := cv.mode == m.id
			gtx.Constraints = layout.Exact(image.Pt(gtx.Constraints.Max.X, itemH))
			return cv.modeButtons[i].Layout(gtx, func(gtx C) D {
				return layout.Stack{Alignment: layout.Center}.Layout(gtx,
					layout.Expanded(func(gtx C) D {
						if cv.modeButtons[i].Hovered() && !active {
							return fill(gtx, colHover, gtx.Dp(8))
						}
						return D{Size: gtx.Constraints.Min}
					}),
					layout.Stacked(func(gtx C) D {
						fg := colMuted
						if active {
							fg = colText
						}
						lbl := v.label(13, fg, m.label)
						if active {
							lbl = bold(lbl)
						}
						lbl.MaxLines = 1
						if active && m.id != "off" {
							return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
								layout.Rigid(func(gtx C) D { return dot(gtx, colGreen, 6) }),
								hspace(6),
								layout.Rigid(lbl.Layout))
						}
						return lbl.Layout(gtx)
					}),
				)
			})
		}))
	}
	innerGtx := gtx
	innerGtx.Constraints = layout.Exact(image.Pt(innerW, itemH))
	layout.Flex{}.Layout(innerGtx, kids...)
	off.Pop()

	return D{Size: image.Pt(totalW, totalH)}
}

func (v *view) connectionProcessEditor(gtx C, editor *widget.Editor, p *connectionProcessPicker) D {
	changed := false
	for _, row := range p.rows {
		if row.checked.Update(gtx) {
			changed = true
		}
	}
	if changed {
		p.merge(editor)
	}
	p.receive(editor)
	if p.button.Clicked(gtx) {
		p.open = !p.open
		if p.open {
			p.fetch()
		}
	}
	if p.refresh.Clicked(gtx) && p.done == nil {
		p.fetch()
	}
	selected := make(map[string]bool)
	for _, name := range connectionProcessLines(editor.Text()) {
		selected[strings.ToLower(name)] = true
	}
	for _, row := range p.rows {
		row.checked.Value = selected[strings.ToLower(row.name)]
	}
	if p.manual.Clicked(gtx) {
		p.manualOpen = !p.manualOpen
	}
	p.search.SingleLine = true

	selectedNames := connectionProcessLines(editor.Text())
	if !p.open {
		summary := "Не выбраны: остальные программы идут напрямую мимо адаптера"
		summaryColor := colMuted
		if len(selectedNames) > 0 {
			summary = fmt.Sprintf("Выбрано (%d): %s", len(selectedNames), strings.Join(selectedNames, ", "))
			summaryColor = colGreen
		}
		return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
			layout.Flexed(1, func(gtx C) D {
				l := v.label(12, summaryColor, summary)
				l.MaxLines = 2
				return l.Layout(gtx)
			}),
			hspace(12),
			layout.Rigid(func(gtx C) D {
				return v.smallButton(gtx, &p.button, "Выбрать .exe", true)
			}))
	}

	query := strings.ToLower(strings.TrimSpace(p.search.Text()))
	var rows []*connectionProcessChoice
	for _, row := range p.rows {
		if query == "" || strings.Contains(strings.ToLower(row.name), query) {
			rows = append(rows, row)
		}
	}

	kids := []layout.FlexChild{
		layout.Rigid(func(gtx C) D {
			return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
				layout.Flexed(1, v.label(12, colMuted, fmt.Sprintf("Выбрано приложений: %d", len(selectedNames))).Layout),
				layout.Rigid(func(gtx C) D { return v.smallButton(gtx, &p.refresh, "Обновить", p.done == nil) }),
				hspace(8),
				layout.Rigid(func(gtx C) D { return v.smallButton(gtx, &p.button, "Свернуть", true) }))
		}),
		vspace(8),
		layout.Rigid(func(gtx C) D {
			return v.field(gtx, &p.search, "Поиск запущенного процесса…", 1)
		}),
		vspace(8),
	}
	if len(selectedNames) > 0 {
		kids = append(kids, layout.Rigid(v.label(12, colGreen, strings.Join(selectedNames, ", ")).Layout), vspace(8))
	}
	kids = append(kids,
		layout.Rigid(func(gtx C) D {
			return layout.Background{}.Layout(gtx,
				func(gtx C) D { return fill(gtx, colField, gtx.Dp(8)) },
				func(gtx C) D {
					return layout.UniformInset(unit.Dp(6)).Layout(gtx, func(gtx C) D {
						gtx.Constraints.Min.Y = 0
						gtx.Constraints.Max.Y = min(gtx.Constraints.Max.Y, gtx.Dp(190))
						if len(rows) == 0 {
							msg := "Загружаю процессы…"
							if p.done == nil {
								msg = "Процессы не найдены"
							}
							return layout.UniformInset(unit.Dp(8)).Layout(gtx, v.label(12, colMuted, msg).Layout)
						}
						return v.list(gtx, &p.list, len(rows), func(gtx C, i int) D {
							return layout.Inset{Top: 4, Bottom: 4, Left: 6, Right: 6}.Layout(gtx, func(gtx C) D {
								return v.connectionCheck(gtx, &rows[i].checked, rows[i].name)
							})
						})
					})
				})
		}),
		vspace(8),
		layout.Rigid(func(gtx C) D {
			return v.smallButton(gtx, &p.manual, "Вписать имена .exe вручную", true)
		}))
	if p.manualOpen {
		kids = append(kids, vspace(8), layout.Rigid(func(gtx C) D {
			return v.field(gtx, editor, "browser.exe (по одному имени файла в строке)", 2)
		}))
	}
	if p.errorMessage != "" {
		kids = append(kids, vspace(6), layout.Rigid(v.label(12, colRed, p.errorMessage).Layout))
	}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx, kids...)
}

func (v *view) updateConnections(gtx C) {
	cv := &v.connections
	if !cv.loaded {
		cv.load(v.ctl.settings())
	}
	v.updateConnectionImports(gtx)

	if cv.speedDone != nil {
		select {
		case res := <-cv.speedDone:
			cv.speedDone = nil
			cv.speedRunning = false
			cv.failed = false
			cv.message = "Скорость: " + res
		default:
		}
	}

	if cv.applyDone != nil {
		select {
		case err := <-cv.applyDone:
			cv.applyDone = nil
			cv.failed = err != nil
			if err != nil {
				cv.message = "Не применено: " + err.Error()
			} else if cv.registering {
				cv.message = "Ключ WARP получен и сохранён. Нажмите «Применить», чтобы включить."
			} else {
				cv.message = "Настройки сохранены."
				cv.loaded = false
			}
			cv.registering = false
			v.draftFor = 0
		default:
		}
	}

	busy := cv.applyDone != nil || cv.importing() || cv.speedRunning
	if cv.reset.Clicked(gtx) && !busy {
		cv.load(v.ctl.settings())
		cv.message, cv.failed = "", false
	}
	if cv.openTrace.Clicked(gtx) && v.open != nil {
		v.open(filepath.Join(appDir(), "network-trace"))
	}
	if cv.traceOpen.Clicked(gtx) {
		cv.traceExpanded = !cv.traceExpanded
	}
	if cv.warpConfBtn.Clicked(gtx) {
		cv.warpConfOpen = !cv.warpConfOpen
	}

	if v.warpReg.Clicked(gtx) && !busy {
		cv.registering = true
		cv.failed = false
		cv.message = "Получаю ключ WARP у Cloudflare…"
		cv.applyDone = make(chan error, 1)
		done, ctl := cv.applyDone, v.ctl
		go func() {
			old := ctl.settings()
			ws, err := registerWarp(old.Warp)
			if err == nil {
				err = ctl.update(func(s *settings) error {
					s.Warp = ws
					s.Warp.Enabled = false
					return nil
				})
			}
			done <- err
			changes.Add(1)
		}()
	}

	if v.warpSpeed.Clicked(gtx) && !busy && !v.ctl.nativeAWGActive() {
		cv.speedRunning = true
		cv.failed = false
		cv.message = "Проверяю скорость напрямую и через WARP (~15–30 с)…"
		done := make(chan string, 1)
		cv.speedDone = done
		ctl := v.ctl
		go func() {
			s := ctl.settings()
			done <- speedTest(ctl.warpTunnel(), s.Warp.withFake(s))
			changes.Add(1)
		}()
	}

	if cv.warpApplyConf.Clicked(gtx) && !busy {
		confText := strings.TrimSpace(cv.warpConf.Text())
		if confText == "" {
			cv.failed = true
			cv.message = "Вставьте содержимое конфига WARP (.conf) или импортируйте файл."
		} else {
			cv.registering = true
			cv.failed = false
			cv.message = "Проверяю и сохраняю конфиг WARP…"
			cv.applyDone = make(chan error, 1)
			done, ctl := cv.applyDone, v.ctl
			go func() {
				old := ctl.settings()
				ws, err := parseWarpConf(confText, old.Warp)
				if err == nil {
					err = ctl.update(func(s *settings) error {
						s.Warp = ws
						s.Warp.Enabled = false
						return nil
					})
				}
				done <- err
				changes.Add(1)
			}()
			cv.warpConf.SetText("")
			cv.warpConfOpen = false
		}
	}

	if (cv.save.Clicked(gtx) || cv.saveTop.Clicked(gtx)) && !busy {
		connection, trace, err := cv.draft()
		cv.failed = err != nil
		if err != nil {
			cv.message = err.Error()
		} else {
			cv.message = "Сохраняю…"
			cv.applyDone = make(chan error, 1)
			done, ctl := cv.applyDone, v.ctl
			go func() {
				done <- ctl.update(func(s *settings) error {
					s.Connection, s.Trace = connection, trace
					s.Warp.Enabled = false
					return nil
				})
				changes.Add(1)
			}()
		}
	}

	if cv.applyDone != nil || cv.speedDone != nil || cv.picker.done != nil || cv.tracePicker.done != nil {
		gtx.Execute(op.InvalidateCmd{At: gtx.Now.Add(100 * time.Millisecond)})
	}
}

func (v *view) connectionsCard(gtx C) D {
	v.updateConnections(gtx)
	return v.connectionsBody(gtx)
}

func (v *view) statusBanner(gtx C, dotColor color.NRGBA, headline string, exit *vpn.ExitReport) D {
	return layout.Background{}.Layout(gtx,
		func(gtx C) D { return fill(gtx, colField, gtx.Dp(8)) },
		func(gtx C) D {
			return layout.UniformInset(unit.Dp(12)).Layout(gtx, func(gtx C) D {
				kids := []layout.FlexChild{
					layout.Rigid(func(gtx C) D {
						return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
							layout.Rigid(func(gtx C) D { return dot(gtx, dotColor, 8) }),
							hspace(10),
							layout.Flexed(1, v.label(13, colText, headline).Layout))
					}),
				}
				if exit != nil {
					loc := vpn.FormatExitLocation(*exit, v.connections.mode == "warp")
					cc := exit.Country
					if cc == "" && exit.Colo != "" {
						cc = vpn.ColoCountry[exit.Colo]
					}
					if loc != "" {
						kids = append(kids, vspace(8), layout.Rigid(func(gtx C) D {
							return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
								hspace(18),
								layout.Rigid(v.label(12, colMuted, "Выход:").Layout),
								hspace(7),
								layout.Rigid(func(gtx C) D { return drawFlag(gtx, cc, 12) }),
								hspace(7),
								layout.Rigid(v.label(12, colText, loc).Layout),
								hspace(8),
								layout.Rigid(mono(v.label(12, colMuted, exit.Address)).Layout))
						}))
					}
				}
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx, kids...)
			})
		})
}

func (v *view) warpModePanel(gtx C) D {
	cv := &v.connections
	s := v.ctl.settings()
	st, _ := v.ctl.state()

	dotColor := colMuted
	headline := "Ключ WARP ещё не получен: нажмите «Получить ключ WARP»."
	if s.Warp.ready() {
		headline = "Ключ WARP сохранён. Туннель подключится, когда вы включите fnport."
	}
	if st == stateOn {
		if ws := v.ctl.warpStatus(false); ws != "" {
			headline = "WARP " + ws
			if v.ctl.warpTunnel() != nil {
				dotColor = colGreen
			} else if strings.HasPrefix(ws, "не подключился") {
				dotColor = colRed
			} else {
				dotColor = colYellow
			}
		}
	}

	keyLabel := "Получить ключ WARP"
	if s.Warp.ready() {
		keyLabel = "Обновить ключ"
	}
	confBtnLabel := "Свой .conf"
	if cv.warpConfOpen {
		confBtnLabel = "Скрыть .conf"
	}

	kids := []layout.FlexChild{
		layout.Rigid(func(gtx C) D {
			return v.statusBanner(gtx, dotColor, headline, v.ctl.connectionExit())
		}),
		vspace(12),
		layout.Rigid(func(gtx C) D {
			return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
				layout.Rigid(func(gtx C) D {
					return v.compactButton(gtx, &v.warpReg, keyLabel, !s.Warp.ready(), cv.applyDone == nil && !cv.speedRunning)
				}),
				hspace(10),
				layout.Rigid(func(gtx C) D {
					return v.compactButton(gtx, &v.warpSpeed, "Проверить скорость", false, !cv.speedRunning && cv.applyDone == nil && !v.ctl.nativeAWGActive())
				}),
				hspace(10),
				layout.Rigid(func(gtx C) D {
					return v.compactButton(gtx, &cv.warpConfBtn, confBtnLabel, false, true)
				}))
		}),
	}

	if cv.warpConfOpen {
		kids = append(kids,
			vspace(12),
			layout.Rigid(func(gtx C) D {
				return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
					layout.Flexed(1, v.label(12, colMuted, "Если провайдер блокирует регистрацию WARP, импортируйте или вставьте готовый .conf:").Layout),
					hspace(8),
					layout.Rigid(func(gtx C) D {
						if v.pickAWGFile == nil {
							return D{}
						}
						return v.smallButton(gtx, &cv.warpImportBtn, "Выбрать .conf", !cv.importing())
					}))
			}),
			vspace(6),
			layout.Rigid(func(gtx C) D {
				return v.field(gtx, &cv.warpConf, "[Interface]\nPrivateKey = …", 3)
			}),
			vspace(8),
			layout.Rigid(func(gtx C) D {
				return v.compactButton(gtx, &cv.warpApplyConf, "Сохранить конфиг WARP", false, cv.applyDone == nil)
			}))
	}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx, kids...)
}

func (v *view) awgModePanel(gtx C) D {
	cv := &v.connections
	cv.config.SingleLine = false
	cv.config.Mask = '•'
	if cv.showConfig.Value {
		cv.config.Mask = 0
	}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx C) D {
			return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
				layout.Flexed(1, v.label(12, colMuted, "Конфигурация AmneziaWG или WireGuard (.conf)").Layout),
				layout.Rigid(func(gtx C) D { return v.connectionCheck(gtx, &cv.showConfig, "Показать") }),
				hspace(10),
				layout.Rigid(func(gtx C) D {
					return v.smallButton(gtx, &cv.imports.importFile, "Импорт .conf", v.pickAWGFile != nil && !cv.importing())
				}))
		}),
		vspace(6),
		layout.Rigid(func(gtx C) D {
			gtx.Constraints.Max.Y = gtx.Dp(120)
			return v.field(gtx, &cv.config, "[Interface]\nPrivateKey = …\nAddress = …\n\n[Peer]\nPublicKey = …\nEndpoint = …", 4)
		}),
	)
}

func (v *view) vpnModePanel(gtx C) D {
	cv := &v.connections
	cv.config.SingleLine = true
	cv.config.Mask = '•'
	if cv.showConfig.Value {
		cv.config.Mask = 0
	}
	text := strings.TrimSpace(cv.config.Text())
	kind := vpn.DetectInputKind(text)
	headerLabel := "Ссылка vless://, hy2://, ss://, trojan://, socks5:// или подписка https://"
	canSinglePing := false
	switch kind {
	case "subscription":
		headerLabel = "Ссылка подписки"
	case "vless", "hysteria2", "shadowsocks", "trojan", "socks":
		headerLabel = "Профиль · " + vpn.ProtocolLabel(kind)
		canSinglePing = true
	case "json":
		headerLabel = "Профиль sing-box JSON"
		canSinglePing = true
	case "amneziawg":
		headerLabel = "Конфигурация WireGuard / AmneziaWG (переключите вкладку выше)"
	}

	isSub := subscriptionURL(text)
	fetchLabel := "Загрузить"
	if sub := cv.imports.subscription; sub != nil && sub.URL == text && len(sub.Nodes) > 0 {
		fetchLabel = "Обновить"
	}
	pingLabel := "Пинг"
	if cv.imports.pinging {
		pingLabel = "Пингую…"
	}
	singlePingCol, singlePingTxt := profilePingLook(cv.imports.nodePings["single:"+text], cv.imports.pinging)

	kids := []layout.FlexChild{
		layout.Rigid(func(gtx C) D {
			return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
				layout.Flexed(1, func(gtx C) D {
					if canSinglePing && singlePingTxt != "" {
						return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
							layout.Rigid(v.label(12, colMuted, headerLabel).Layout),
							hspace(8),
							layout.Rigid(bold(v.label(12, singlePingCol, singlePingTxt)).Layout))
					}
					return v.label(12, colMuted, headerLabel).Layout(gtx)
				}),
				layout.Rigid(func(gtx C) D { return v.connectionCheck(gtx, &cv.showConfig, "Показать") }),
				layout.Rigid(func(gtx C) D {
					if isSub {
						return layout.Inset{Left: 10}.Layout(gtx, func(gtx C) D {
							return v.smallButton(gtx, &cv.imports.fetch, fetchLabel, !cv.importing())
						})
					}
					if canSinglePing {
						return layout.Inset{Left: 10}.Layout(gtx, func(gtx C) D {
							return v.smallButton(gtx, &cv.imports.pingBtn, pingLabel, !cv.imports.pinging && !cv.importing())
						})
					}
					return D{}
				}))
		}),
		vspace(6),
		layout.Rigid(func(gtx C) D {
			return v.field(gtx, &cv.config, "https://… или vless://… , hy2://… , ss://… , trojan://… , socks5://…", 1)
		}),
	}

	if sub := cv.imports.subscription; sub != nil && sub.URL == text && len(sub.Nodes) > 0 {
		title := sub.Title
		if title == "" {
			title = "Подписка"
		}
		kids = append(kids,
			vspace(12),
			layout.Rigid(func(gtx C) D {
				return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
					layout.Flexed(1, v.label(12, colMuted, fmt.Sprintf("%s · серверов: %d", title, len(sub.Nodes))).Layout),
					layout.Rigid(func(gtx C) D {
						return v.smallButton(gtx, &cv.imports.pingBtn, pingLabel, !cv.imports.pinging && !cv.importing())
					}))
			}),
			vspace(6),
			layout.Rigid(v.subscriptionServerList))
	}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx, kids...)
}

func (v *view) connectionsBody(gtx C) D {
	cv := &v.connections
	if !cv.loaded {
		cv.load(v.ctl.settings())
	}
	cv.syncLegacyModeFromProtocol()
	disabled := cv.applyDone != nil || cv.importing() || cv.speedRunning

	card1 := func(gtx C) D {
		return v.card(gtx, func(gtx C) D {
			if disabled {
				gtx = gtx.Disabled()
			}
			kids := v.sectionTitle("Подключение", "Обход замедления и блокировок для сервисов Epic, Discord и выбранных сайтов. Игра идёт напрямую.")
			kids = append(kids, layout.Rigid(v.connectionModeSelector), vspace(14))
			switch cv.mode {
			case "off":
				kids = append(kids, layout.Rigid(func(gtx C) D {
					return v.statusBanner(gtx, colMuted, "Подключение выключено: сервисы Epic и Discord идут напрямую через ваш интернет.", nil)
				}))
			case "warp":
				kids = append(kids, layout.Rigid(v.warpModePanel))
			case "amneziawg":
				kids = append(kids, layout.Rigid(v.awgModePanel))
			default:
				kids = append(kids, layout.Rigid(v.vpnModePanel))
			}
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx, kids...)
		})
	}

	card2 := func(gtx C) D {
		return v.card(gtx, func(gtx C) D {
			if disabled {
				gtx = gtx.Disabled()
			}
			kids := v.sectionTitle("Что направлять через подключение", "Матчи Fortnite всегда идут напрямую через fnport без лишнего пинга.")
			kids = append(kids, layout.Rigid(func(gtx C) D {
				return v.switchRow(gtx, &cv.epic, "Сервисы Epic", "Вход в аккаунт, магазин, обновления и голосовой чат пати")
			}))
			if cv.epic.Value {
				kids = append(kids, vspace(6), layout.Rigid(func(gtx C) D {
					return layout.Inset{Left: 4}.Layout(gtx, func(gtx C) D {
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
							v.radio("auto", "Только если напрямую не открывается или замерзает (рекомендуется)", &cv.epicRouting),
							v.radio("always", "Всегда через подключение", &cv.epicRouting))
					})
				}))
			}
			kids = append(kids,
				vspace(10),
				layout.Rigid(v.divider),
				vspace(10),
				layout.Rigid(func(gtx C) D {
					return v.switchRow(gtx, &cv.discord, "Discord", "Сообщения, медиафайлы, стримы и голосовые каналы")
				}))
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx, kids...)
		})
	}

	card3 := func(gtx C) D {
		return v.card(gtx, func(gtx C) D {
			if disabled {
				gtx = gtx.Disabled()
			}
			kids := v.sectionTitle("Свои домены и приложения", "По одному домену в строке. Поддомены включаются автоматически.")
			kids = append(kids,
				layout.Rigid(func(gtx C) D {
					return v.field(gtx, &cv.domains, "Например, example.org", 3)
				}),
				vspace(12),
				layout.Rigid(v.divider),
				vspace(10),
				layout.Rigid(v.label(13, colText, "Приложения целиком (.exe)").Layout),
				vspace(4),
				layout.Rigid(func(gtx C) D {
					return v.connectionProcessEditor(gtx, &cv.processes, &cv.picker)
				}))
			if traceAvailable() {
				kids = append(kids, vspace(10), layout.Rigid(func(gtx C) D {
					return v.smallButton(gtx, &cv.traceOpen, "Диагностика (devtrace)", true)
				}))
			}
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx, kids...)
		})
	}

	children := []layout.FlexChild{
		layout.Rigid(card1),
		vspace(12),
		layout.Rigid(card2),
		vspace(12),
		layout.Rigid(card3),
	}
	if traceAvailable() && cv.traceExpanded {
		children = append(children, vspace(12), layout.Rigid(func(gtx C) D {
			return v.card(gtx, func(gtx C) D {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx C) D {
						return v.switchRow(gtx, &cv.trace, "Записывать сетевой след", "Только для локальной отладки соединений")
					}),
					vspace(8),
					layout.Rigid(func(gtx C) D {
						return v.connectionProcessEditor(gtx, &cv.traceProcesses, &cv.tracePicker)
					}),
					vspace(8),
					layout.Rigid(func(gtx C) D {
						return v.compactButton(gtx, &cv.openTrace, "Открыть папку логов", false, v.open != nil)
					}))
			})
		}))
	}

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
}

func (v *view) warpTab(gtx C) D {
	v.updateConnections(gtx)
	busy := v.connections.applyDone != nil || v.connections.importing() || v.connections.speedRunning
	msgColor := colGreen
	if v.connections.failed {
		msgColor = colRed
	} else if busy {
		msgColor = colMuted
	}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		v.title("Подключения"),
		layout.Flexed(1, func(gtx C) D {
			return v.list(gtx, &v.warpPage, 1, func(gtx C, _ int) D {
				return layout.Inset{Right: 10, Bottom: 12}.Layout(gtx, v.connectionsBody)
			})
		}),
		vspace(10),
		layout.Rigid(func(gtx C) D {
			return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
				layout.Rigid(func(gtx C) D {
					return v.button(gtx, &v.connections.saveTop, "Применить", true, !busy)
				}),
				hspace(10),
				layout.Rigid(func(gtx C) D {
					return v.button(gtx, &v.connections.reset, "Отменить изменения", false, !busy)
				}),
				hspace(14),
				layout.Flexed(1, func(gtx C) D {
					l := v.label(13, msgColor, v.connections.message)
					l.Font.Typeface = fonts.UI
					return l.Layout(gtx)
				}))
		}))
}
