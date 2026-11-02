package main

import (
	"encoding/json"
	"fmt"
	"image"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gioui.org/f32"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"

	"github.com/YUNGSLXRD/fnport/windows/internal/wnet"
)

// connectionView is owned exclusively by the UI goroutine. Workers receive values
// and buffered result channels, never editors or pointers to this state.
// The parent owns connectionSettings, networkTraceSettings and the WARP card.
type connectionView struct {
	registering                               bool
	loaded                                    bool
	enabled, epic, discord, trace, showConfig widget.Bool
	advanced, traceOpen                       widget.Clickable
	advancedOpen, traceExpanded               bool
	protocol                                  string
	protocolOpen                              bool
	protocolButton                            widget.Clickable
	protocolChoices                           []widget.Clickable
	protocolList                              widget.List
	config, processes, traceProcesses         widget.Editor
	final                                     widget.Editor
	picker, tracePicker                       connectionProcessPicker
	save, saveTop, reset, openTrace           widget.Clickable
	applyDone                                 chan error
	message                                   string
	failed                                    bool
}

// Use backend IDs so new sing-box protocols appear without duplicating the
// transport catalog. Native WARP and AmneziaWG are separate parent transports.
var connectionUIProtocols = func() []struct{ id, label string } {
	options := []struct{ id, label string }{{"warp", "WARP"}, {"amneziawg", "AmneziaWG"}}
	for _, protocol := range connectionProtocols() {
		if protocol.ID == "warp" || protocol.ID == "amneziawg" {
			continue
		}
		label := protocol.Label
		if protocol.ID == "custom" {
			label = "sing-box JSON"
		}
		options = append(options, struct{ id, label string }{protocol.ID, label})
	}
	return options
}()

type connectionProcessChoice struct {
	name    string
	checked widget.Bool
}

type connectionProcessResult struct {
	names []string
	err   error
}

type connectionProcessPicker struct {
	open         bool
	button       widget.Clickable
	refresh      widget.Clickable
	list         widget.List
	rows         []*connectionProcessChoice
	done         chan connectionProcessResult
	errorMessage string
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

func connectionProtocolLabel(protocol string) string {
	for _, p := range connectionUIProtocols {
		if p.id == protocol {
			return p.label
		}
	}
	// Do not silently replace a saved protocol unknown to this version of the UI.
	return protocol
}

// Keep raw sing-box JSON intact. Detailed schema and protocol validation belongs
// to Connection.validate in the backend; parsing here only rejects non-objects.
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
		// Do not echo JSON parser errors: they can contain credential fragments.
		return nil, fmt.Errorf("конфигурация должна быть объектом JSON")
	}
	return json.RawMessage(text), nil
}

func (cv *connectionView) load(s settings) {
	cv.enabled.Value = s.Connection.Enabled
	cv.discord.Value = s.Connection.Discord
	cv.epic.Value = s.Connection.Epic
	if !s.Connection.Enabled && s.Warp.Enabled {
		cv.enabled.Value = true
		cv.epic.Value = true
		s.Connection.Protocol = "warp"
	}
	cv.protocol = s.Connection.Protocol
	if cv.protocol == "" {
		cv.protocol = "warp"
	}
	cv.config.SetText(string(s.Connection.Config))
	cv.config.Mask = '•'
	cv.showConfig.Value = false
	cv.processes.SetText(strings.Join(s.Connection.Processes, "\n"))
	cv.final.SingleLine = true
	cv.final.SetText(s.Connection.Final)
	cv.trace.Value = s.Trace.Enabled
	cv.traceProcesses.SetText(strings.Join(s.Trace.Processes, "\n"))
	cv.protocolOpen, cv.picker.open, cv.tracePicker.open = false, false, false
	cv.protocolList.Axis = layout.Vertical
	cv.picker.list.Axis, cv.tracePicker.list.Axis = layout.Vertical, layout.Vertical
	cv.protocolChoices = make([]widget.Clickable, len(connectionUIProtocols))
	cv.loaded = true
}

func (cv *connectionView) draft() (connectionSettings, networkTraceSettings, error) {
	raw, detected, err := importConnection(cv.config.Text(), cv.enabled.Value && cv.protocol != "warp")
	if err != nil {
		return connectionSettings{}, networkTraceSettings{}, err
	}
	protocol := cv.protocol
	if detected != "" {
		protocol = detected
	}
	return connectionSettings{
		Enabled: cv.enabled.Value, Protocol: protocol, Config: raw, Epic: cv.epic.Value,
		Processes: connectionProcessLines(cv.processes.Text()), Discord: cv.discord.Value,
		Final: strings.TrimSpace(cv.final.Text()),
	}, networkTraceSettings{
		Enabled: cv.trace.Value, Processes: connectionProcessLines(cv.traceProcesses.Text()),
	}, nil
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
			// OS errors have no configuration content and are safe to show.
			p.errorMessage = "Не получить процессы: " + result.err.Error()
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

// Only names represented by the picker are changed. Manually entered names of
// processes which are not running stay in the editor when a checkbox changes.
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
	cb.Color, cb.IconColor, cb.Size = colText, colGreen, unit.Dp(20)
	return cb.Layout(gtx)
}

func (v *view) connectionToggle(gtx C, state *widget.Bool, label string) D {
	return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
		layout.Flexed(1, v.label(14, colText, label).Layout),
		layout.Rigid(func(gtx C) D {
			sw := material.Switch(v.th, state, label)
			sw.Color.Enabled, sw.Color.Track, sw.Color.Disabled = colGreen, colGray, colLine
			return sw.Layout(gtx)
		}))
}

func (v *view) connectionProcessEditor(gtx C, editor *widget.Editor, p *connectionProcessPicker) D {
	// Consume events on the previous snapshot before a refresh can remove rows.
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
	kids := []layout.FlexChild{
		layout.Rigid(func(gtx C) D { return v.field(gtx, editor, "Приложение.exe", 3) }),
		vspace(6),
		layout.Rigid(func(gtx C) D {
			label := "Выбрать запущенные ▾"
			if p.open {
				label = "Скрыть процессы ▴"
			}
			return v.button(gtx, &p.button, label, false, true)
		}),
	}
	if p.open {
		kids = append(kids, vspace(6), layout.Rigid(func(gtx C) D {
			label := "Обновить"
			if p.done != nil {
				label = "Загрузка…"
			}
			return v.button(gtx, &p.refresh, label, false, p.done == nil)
		}))
		if p.errorMessage != "" {
			kids = append(kids, vspace(6), layout.Rigid(v.label(12, colRed, p.errorMessage).Layout))
		} else if len(p.rows) == 0 && p.done == nil {
			kids = append(kids, vspace(6), layout.Rigid(v.label(12, colMuted, "Нет доступных процессов").Layout))
		}
		if len(p.rows) > 0 {
			kids = append(kids, layout.Rigid(func(gtx C) D {
				gtx.Constraints.Min.Y = 0
				gtx.Constraints.Max.Y = min(gtx.Constraints.Max.Y, gtx.Dp(192))
				return material.List(v.th, &p.list).Layout(gtx, len(p.rows), func(gtx C, i int) D {
					row := p.rows[i]
					return v.connectionCheck(gtx, &row.checked, row.name)
				})
			}))
		}
	}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx, kids...)
}

func (v *view) connectionProtocolDropdown(gtx C) D {
	cv := &v.connections
	if cv.protocolButton.Clicked(gtx) {
		cv.protocolOpen = !cv.protocolOpen
	}
	for i := range cv.protocolChoices {
		if cv.protocolChoices[i].Clicked(gtx) {
			cv.protocol, cv.protocolOpen = connectionUIProtocols[i].id, false
		}
	}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx C) D {
			return layout.Stack{Alignment: layout.E}.Layout(gtx,
				layout.Stacked(func(gtx C) D {
					gtx.Constraints.Min.X = gtx.Constraints.Max.X
					return v.button(gtx, &cv.protocolButton, connectionProtocolLabel(cv.protocol), false, true)
				}),
				layout.Stacked(func(gtx C) D {
					return layout.Inset{Right: 16}.Layout(gtx, func(gtx C) D {
						size := gtx.Dp(16)
						var p clip.Path
						p.Begin(gtx.Ops)
						a, b := float32(size)*0.3, float32(size)*0.65
						if cv.protocolOpen {
							a, b = b, a
						}
						p.MoveTo(f32.Pt(0, a))
						p.LineTo(f32.Pt(float32(size)/2, b))
						p.LineTo(f32.Pt(float32(size), a))
						paint.FillShape(gtx.Ops, colText, clip.Stroke{Path: p.End(), Width: 1.5}.Op())
						return D{Size: image.Pt(size, size)}
					})
				}))
		}),
		layout.Rigid(func(gtx C) D {
			if !cv.protocolOpen {
				return D{}
			}
			gtx.Constraints.Min.Y = 0
			gtx.Constraints.Max.Y = min(gtx.Constraints.Max.Y, gtx.Dp(192))
			return material.List(v.th, &cv.protocolList).Layout(gtx, len(connectionUIProtocols), func(gtx C, i int) D {
				p := connectionUIProtocols[i]
				return v.button(gtx, &cv.protocolChoices[i], p.label, p.id == cv.protocol, true)
			})
		}))
}

func (v *view) connectionsCard(gtx C) D {
	cv := &v.connections
	if !cv.loaded {
		cv.load(v.ctl.settings())
	}
	if cv.applyDone != nil {
		select {
		case err := <-cv.applyDone:
			cv.applyDone = nil
			cv.failed = err != nil
			if err != nil {
				cv.message = "Не применено: " + err.Error()
			} else {
				if cv.registering {
					cv.message = "Ключ получен. Нажми «Применить»."
				} else {
					cv.message = "Настройки применены"
					cv.loaded = false
				}
				cv.registering = false
				v.draftFor = 0
			}
		default:
		}
	}
	if cv.reset.Clicked(gtx) && cv.applyDone == nil {
		cv.load(v.ctl.settings())
		cv.message, cv.failed = "", false
	}
	if cv.openTrace.Clicked(gtx) && v.open != nil {
		v.open(filepath.Join(appDir(), "network-trace"))
	}
	if (cv.save.Clicked(gtx) || cv.saveTop.Clicked(gtx)) && cv.applyDone == nil {
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
	if cv.applyDone != nil || cv.picker.done != nil || cv.tracePicker.done != nil {
		gtx.Execute(op.InvalidateCmd{At: gtx.Now.Add(100 * time.Millisecond)})
	}

	if cv.advanced.Clicked(gtx) {
		cv.advancedOpen = !cv.advancedOpen
	}
	if cv.traceOpen.Clicked(gtx) {
		cv.traceExpanded = !cv.traceExpanded
	}
	if v.warpReg.Clicked(gtx) && cv.applyDone == nil {
		cv.registering = true
		cv.applyDone = make(chan error, 1)
		done := cv.applyDone
		ctl := v.ctl
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

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx C) D {
			return v.card(gtx, func(gtx C) D {
				if cv.applyDone != nil {
					gtx = gtx.Disabled()
				}
				kids := []layout.FlexChild{layout.Rigid(func(gtx C) D { return v.connectionToggle(gtx, &cv.enabled, "Подключение") }), vspace(12), layout.Rigid(v.connectionProtocolDropdown), vspace(12)}
				if cv.protocol == "warp" {
					info, label := "Ключ не получен", "Получить ключ"
					if v.ctl.settings().Warp.ready() {
						info, label = "Ключ сохранён", "Обновить ключ"
					}
					if status := v.ctl.warpStatus(false); status != "" {
						info = status
					}
					kids = append(kids, layout.Rigid(func(gtx C) D {
						return layout.Flex{Alignment: layout.Middle}.Layout(gtx, layout.Flexed(1, v.label(13, colMuted, info).Layout), hspace(12), layout.Rigid(func(gtx C) D { return v.compactButton(gtx, &v.warpReg, label, false, cv.applyDone == nil) }))
					}))
				} else {
					cv.config.SingleLine = true
					cv.config.Mask = '•'
					if cv.showConfig.Value {
						cv.config.Mask = 0
					}
					hint := "vless://… или JSON"
					if cv.protocol == "amneziawg" {
						hint = "Конфигурация JSON"
					}
					kids = append(kids, layout.Rigid(v.label(12, colMuted, "Ссылка подключения").Layout), vspace(6), layout.Rigid(func(gtx C) D { return v.field(gtx, &cv.config, hint, 1) }), vspace(4), layout.Rigid(func(gtx C) D { return v.connectionCheck(gtx, &cv.showConfig, "Показать") }))
				}
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx, kids...)
			})
		}), vspace(12),
		layout.Rigid(func(gtx C) D {
			return v.card(gtx, func(gtx C) D {
				if cv.applyDone != nil {
					gtx = gtx.Disabled()
				}
				kids := v.sectionTitle("Через подключение", "")
				kids = append(kids, layout.Rigid(func(gtx C) D { return v.connectionCheck(gtx, &cv.epic, "Сервисы Epic") }), layout.Rigid(func(gtx C) D {
					return layout.Inset{Left: 28, Bottom: 8}.Layout(gtx, v.label(12, colMuted, "Вход, магазин и загрузки").Layout)
				}), layout.Rigid(func(gtx C) D { return v.connectionCheck(gtx, &cv.discord, "Discord") }), vspace(10), layout.Rigid(v.label(12, colMuted, "Матчи Fortnite идут напрямую через fnport.").Layout))
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx, kids...)
			})
		}), vspace(12), layout.Rigid(func(gtx C) D {
			return layout.Flex{Alignment: layout.Middle}.Layout(gtx, layout.Rigid(func(gtx C) D { return v.compactButton(gtx, &cv.advanced, "Дополнительно", false, true) }), hspace(8), layout.Rigid(func(gtx C) D { return v.compactButton(gtx, &cv.traceOpen, "Диагностика", false, true) }))
		}),
		layout.Rigid(func(gtx C) D {
			if !cv.advancedOpen {
				return D{}
			}
			return layout.Inset{Top: 12}.Layout(gtx, func(gtx C) D {
				return v.card(gtx, func(gtx C) D {
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx, layout.Rigid(v.label(13, colMuted, "Другие приложения").Layout), vspace(8), layout.Rigid(func(gtx C) D { return v.connectionProcessEditor(gtx, &cv.processes, &cv.picker) }), vspace(12), layout.Rigid(v.label(12, colMuted, "Тег выхода · только для JSON с несколькими выходами").Layout), vspace(6), layout.Rigid(func(gtx C) D { return v.field(gtx, &cv.final, "Необязательно", 1) }))
				})
			})
		}),
		layout.Rigid(func(gtx C) D {
			if !cv.traceExpanded {
				return D{}
			}
			return layout.Inset{Top: 12}.Layout(gtx, func(gtx C) D {
				return v.card(gtx, func(gtx C) D {
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx, layout.Rigid(func(gtx C) D {
						return v.connectionCheck(gtx, &cv.trace, "Записывать сетевой след")
					}), vspace(8), layout.Rigid(func(gtx C) D { return v.connectionProcessEditor(gtx, &cv.traceProcesses, &cv.tracePicker) }), vspace(8), layout.Rigid(func(gtx C) D {
						return v.compactButton(gtx, &cv.openTrace, "Открыть логи", false, v.open != nil)
					}))
				})
			})
		}))
}

func (v *view) compactButton(gtx C, b *widget.Clickable, label string, primary, enabled bool) D {
	gtx.Constraints.Min.X = 0
	return v.button(gtx, b, label, primary, enabled)
}

func (v *view) warpTab(gtx C) D {
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx, v.title("Подключения"), layout.Flexed(1, func(gtx C) D {
		return v.list(gtx, &v.warpPage, 1, func(gtx C, _ int) D { return layout.Inset{Right: 10, Bottom: 12}.Layout(gtx, v.connectionsCard) })
	}), vspace(12), layout.Rigid(func(gtx C) D {
		return layout.Flex{Alignment: layout.Middle}.Layout(gtx, layout.Rigid(func(gtx C) D {
			return v.compactButton(gtx, &v.connections.saveTop, "Применить", true, v.connections.applyDone == nil)
		}), hspace(14), layout.Flexed(1, func(gtx C) D {
			c := colMuted
			if v.connections.failed {
				c = colRed
			}
			return v.label(12, c, v.connections.message).Layout(gtx)
		}))
	}), vspace(6))
}
