package main

import (
	"context"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"strings"
	"sync"
	"time"

	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget"

	"github.com/YUNGSLXRD/fnport/windows/internal/vpn"
)

type subscriptionResult struct {
	subscription *connectionSubscription
	err          error
}

type configFileResult struct {
	text    string
	forWARP bool
	err     error
}

type profilePingState struct {
	RTT     time.Duration
	Checked bool
	OK      bool
}

type connectionImportView struct {
	subscription       *connectionSubscription
	fetch              widget.Clickable
	pingBtn            widget.Clickable
	importFile         widget.Clickable
	serverList         widget.List
	serverChoices      []widget.Clickable
	fetchDone          chan subscriptionResult
	fileDone           chan configFileResult
	pingDone           chan map[string]profilePingState
	nodePings          map[string]profilePingState
	pinging            bool
	initialPingPending bool
	cancel             context.CancelFunc
}

func (cv *connectionView) importing() bool {
	return cv.imports.fetchDone != nil || cv.imports.fileDone != nil
}

func (cv *connectionView) cancelImport() {
	if cv.imports.cancel != nil {
		cv.imports.cancel()
		cv.imports.cancel = nil
	}
}

func (cv *connectionView) loadSubscriptionView(s *connectionSubscription) {
	cv.imports.subscription = cloneSubscription(s)
	cv.imports.serverList.Axis = layout.Vertical
	cv.imports.serverChoices = nil
	if s != nil {
		cv.imports.serverChoices = make([]widget.Clickable, len(s.Nodes))
	}
}

func profilePingLook(st profilePingState, pinging bool) (color.NRGBA, string) {
	if !st.Checked {
		if pinging {
			return colGray, "…"
		}
		return colGray, ""
	}
	if !st.OK || st.RTT <= 0 {
		return colGray, "—"
	}
	return vpnPingColor(st.RTT)
}

func (cv *connectionView) startProfilePings() {
	i := &cv.imports
	if i.pinging {
		return
	}
	text := strings.TrimSpace(cv.config.Text())

	if cv.mode == "vpn" && subscriptionURL(text) {
		if i.subscription == nil || i.subscription.URL != text || len(i.subscription.Nodes) == 0 {
			return
		}
		nodes := append([]subscriptionNode(nil), i.subscription.Nodes...)
		i.pinging = true
		done := make(chan map[string]profilePingState, 1)
		i.pingDone = done
		go func() {
			sem := make(chan struct{}, 6)
			var wg sync.WaitGroup
			var mu sync.Mutex
			out := make(map[string]profilePingState, len(nodes))
			for _, node := range nodes {
				node := node
				wg.Add(1)
				go func() {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()
					ctx, cancel := context.WithTimeout(context.Background(), 2600*time.Millisecond)
					defer cancel()
					d, err := measureProfilePingFunc(ctx, node.Protocol, node.Config, "")
					mu.Lock()
					out[node.ID] = profilePingState{RTT: d, Checked: true, OK: err == nil && d > 0}
					mu.Unlock()
				}()
			}
			wg.Wait()
			done <- out
			changes.Add(1)
		}()
		return
	}

	if cv.mode != "vpn" || text == "" || text == "null" {
		return
	}
	var raw json.RawMessage
	proto := cv.protocol
	if strings.Contains(text, "://") {
		b, det, _, err := vpn.ImportProfile(text, false)
		if err != nil || len(b) == 0 {
			return
		}
		raw = b
		if det != "" {
			proto = det
		}
	} else {
		b, err := connectionConfigJSON(text, false)
		if err != nil || len(b) == 0 {
			return
		}
		raw = b
	}
	finalTag := strings.TrimSpace(cv.final.Text())
	key := "single:" + text
	i.pinging = true
	done := make(chan map[string]profilePingState, 1)
	i.pingDone = done
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2600*time.Millisecond)
		defer cancel()
		d, err := measureProfilePingFunc(ctx, proto, raw, finalTag)
		done <- map[string]profilePingState{
			key: {RTT: d, Checked: true, OK: err == nil && d > 0},
		}
		changes.Add(1)
	}()
}

func (v *view) updateConnectionImports(gtx C) {
	cv := &v.connections
	i := &cv.imports

	for n := range i.serverChoices {
		if i.serverChoices[n].Clicked(gtx) && i.subscription != nil && n < len(i.subscription.Nodes) {
			i.subscription.Selected = i.subscription.Nodes[n].ID
			cv.protocol = i.subscription.Nodes[n].Protocol
			cv.final.SetText("")
		}
	}

	if i.pingDone != nil {
		select {
		case res := <-i.pingDone:
			i.pingDone = nil
			i.pinging = false
			if i.nodePings == nil {
				i.nodePings = make(map[string]profilePingState, len(res))
			}
			for k, val := range res {
				i.nodePings[k] = val
			}
		default:
		}
	}

	if i.fetchDone != nil {
		select {
		case result := <-i.fetchDone:
			i.fetchDone = nil
			cv.cancelImport()
			cv.failed = result.err != nil
			if result.err != nil {
				cv.message = result.err.Error()
			} else {
				retainSubscriptionSelection(result.subscription, i.subscription)
				cv.loadSubscriptionView(result.subscription)
				if n := result.subscription.ActiveNode(); n != nil {
					cv.protocol = n.Protocol
				}
				cv.mode = "vpn"
				cv.enabled.Value = true
				cv.final.SetText("")
				cv.message = fmt.Sprintf("Загружено серверов: %d. Выберите сервер и нажмите «Применить».", len(result.subscription.Nodes))
				if result.subscription.Skipped > 0 {
					cv.message = fmt.Sprintf("Доступно серверов: %d (пропущено неподдерживаемых: %d). Выберите сервер и нажмите «Применить».",
						len(result.subscription.Nodes), result.subscription.Skipped)
				}
				if v.open != nil || v.autoPingConnections {
					cv.startProfilePings()
				}
			}
		default:
		}
	}

	if i.fileDone != nil {
		select {
		case result := <-i.fileDone:
			i.fileDone = nil
			if result.err != nil {
				cv.failed = true
				cv.message = result.err.Error()
			} else if result.text != "" {
				if result.forWARP {
					cv.warpConf.SetText(result.text)
					cv.warpConfOpen = true
					cv.failed = false
					cv.message = "Файл загружен. Нажмите «Сохранить конфиг WARP»."
				} else {
					cv.config.SingleLine = false
					cv.config.SetText(result.text)
					cv.awgSavedText = result.text
					cv.failed = false
					cv.final.SetText("")
					cv.message = "Файл импортирован. Нажмите «Применить»."
				}
			}
		default:
		}
	}

	if i.initialPingPending {
		i.initialPingPending = false
		if v.open != nil || v.autoPingConnections {
			cv.startProfilePings()
		}
	}

	if i.pingBtn.Clicked(gtx) && !i.pinging && !cv.importing() {
		cv.startProfilePings()
	}

	if i.fetch.Clicked(gtx) && !cv.importing() && cv.applyDone == nil {
		source := strings.TrimSpace(cv.config.Text())
		if !subscriptionURL(source) {
			cv.failed = true
			cv.message = "Вставьте ссылку подписки http:// или https://"
		} else {
			cv.failed = false
			cv.message = "Загружаю подписку…"
			i.fetchDone = make(chan subscriptionResult, 1)
			done := i.fetchDone
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			i.cancel = cancel
			go func() {
				defer cancel()
				s, err := loadSubscription(ctx, source)
				done <- subscriptionResult{s, err}
				changes.Add(1)
			}()
		}
	}

	startFilePick := func(forWARP bool) {
		i.fileDone = make(chan configFileResult, 1)
		done := i.fileDone
		pick := v.pickAWGFile
		go func() {
			chosenPath, err := pick()
			text := ""
			if err == nil && chosenPath != "" {
				text, err = readAWGConfigFile(chosenPath)
			}
			done <- configFileResult{text: text, forWARP: forWARP, err: err}
			changes.Add(1)
		}()
	}

	if i.importFile.Clicked(gtx) && cv.mode == "amneziawg" && !cv.importing() && cv.applyDone == nil && v.pickAWGFile != nil {
		startFilePick(false)
	}
	if cv.warpImportBtn.Clicked(gtx) && cv.mode == "warp" && !cv.importing() && cv.applyDone == nil && v.pickAWGFile != nil {
		startFilePick(true)
	}

	if cv.importing() || i.pinging {
		gtx.Execute(op.InvalidateCmd{At: gtx.Now.Add(100 * time.Millisecond)})
	}
}

// subscriptionServerList renders an inline Opus-styled server list inside a rounded container
// with country flags, server ping, and protocol badges (zero floating popup overlap).
func (v *view) subscriptionServerList(gtx C) D {
	cv := &v.connections
	i := &cv.imports
	s := i.subscription
	if s == nil || s.URL != strings.TrimSpace(cv.config.Text()) || len(s.Nodes) == 0 {
		return D{}
	}

	return layout.Background{}.Layout(gtx,
		func(gtx C) D { return fill(gtx, colField, gtx.Dp(8)) },
		func(gtx C) D {
			return layout.UniformInset(unit.Dp(6)).Layout(gtx, func(gtx C) D {
				gtx.Constraints.Min.Y = 0
				gtx.Constraints.Max.Y = min(gtx.Constraints.Max.Y, gtx.Dp(204))
				return v.list(gtx, &i.serverList, len(s.Nodes), func(gtx C, idx int) D {
					node := s.Nodes[idx]
					active := node.ID == s.Selected
					cleanTitle, country := vpn.DisplayNodeName(node.Name)
					badge := vpn.ProtocolShortBadge(node.Protocol)
					pCol, pTxt := profilePingLook(i.nodePings[node.ID], i.pinging)

					return layout.Inset{Bottom: 2}.Layout(gtx, func(gtx C) D {
						return i.serverChoices[idx].Layout(gtx, func(gtx C) D {
							rowBg := colField
							if active {
								rowBg = colCard
							} else if i.serverChoices[idx].Hovered() {
								rowBg = colHover
							}
							return layout.Background{}.Layout(gtx,
								func(gtx C) D {
									d := fill(gtx, rowBg, gtx.Dp(6))
									if active {
										rr := clip.UniformRRect(image.Rectangle{Max: d.Size}, gtx.Dp(6))
										paint.FillShape(gtx.Ops, colLine, clip.Stroke{Path: rr.Path(gtx.Ops), Width: 1}.Op())
									}
									return d
								},
								func(gtx C) D {
									gtx.Constraints.Min.X = gtx.Constraints.Max.X
									return layout.Inset{Top: 8, Bottom: 8, Left: 10, Right: 10}.Layout(gtx, func(gtx C) D {
										return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
											layout.Rigid(func(gtx C) D {
												return drawRadioIndicator(gtx, active)
											}),
											hspace(10),
											layout.Rigid(func(gtx C) D {
												if country == "" {
													return D{}
												}
												return layout.Inset{Right: 8}.Layout(gtx, func(gtx C) D {
													return drawFlag(gtx, country, 12)
												})
											}),
											layout.Flexed(1, func(gtx C) D {
												lbl := v.label(13, colText, cleanTitle)
												if active {
													lbl = bold(lbl)
												}
												lbl.MaxLines = 1
												return lbl.Layout(gtx)
											}),
											layout.Rigid(func(gtx C) D {
												if pTxt == "" {
													return D{}
												}
												return layout.Inset{Left: 8}.Layout(gtx, bold(v.label(12, pCol, pTxt)).Layout)
											}),
											hspace(8),
											layout.Rigid(func(gtx C) D {
												badgeFg := colMuted
												if active {
													badgeFg = colGreen
												}
												return layout.Background{}.Layout(gtx,
													func(gtx C) D { return fill(gtx, colBg, gtx.Dp(4)) },
													func(gtx C) D {
														return layout.Inset{Top: 2, Bottom: 2, Left: 6, Right: 6}.Layout(gtx,
															mono(v.label(10, badgeFg, badge)).Layout)
													})
											}),
										)
									})
								})
						})
					})
				})
			})
		})
}

func drawRadioIndicator(gtx C, selected bool) D {
	sz := gtx.Dp(16)
	ringColor := colGray
	if selected {
		ringColor = colGreen
	}
	outer := clip.Ellipse{Min: image.Pt(1, 1), Max: image.Pt(sz-1, sz-1)}
	paint.FillShape(gtx.Ops, ringColor, clip.Stroke{Path: outer.Path(gtx.Ops), Width: float32(max(1, gtx.Dp(1.5)))}.Op())
	if selected {
		pad := max(3, sz/4+1)
		inner := clip.Ellipse{Min: image.Pt(pad, pad), Max: image.Pt(sz-pad, sz-pad)}
		paint.FillShape(gtx.Ops, colGreen, inner.Op(gtx.Ops))
	}
	return D{Size: image.Pt(sz, sz)}
}
