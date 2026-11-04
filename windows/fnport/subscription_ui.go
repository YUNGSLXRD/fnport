package main

import (
	"context"
	"fmt"
	"image"
	"strings"
	"time"

	"gioui.org/f32"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/widget"
)

type subscriptionResult struct {
	subscription *connectionSubscription
	err          error
}
type configFileResult struct {
	text string
	err  error
}

type connectionImportView struct {
	subscription                    *connectionSubscription
	fetch, importFile, serverButton widget.Clickable
	serverOpen                      bool
	serverList                      widget.List
	serverChoices                   []widget.Clickable
	fetchDone                       chan subscriptionResult
	fileDone                        chan configFileResult
	cancel                          context.CancelFunc
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
	cv.imports.serverOpen = false
	cv.imports.serverList.Axis = layout.Vertical
	cv.imports.serverChoices = nil
	if s != nil {
		cv.imports.serverChoices = make([]widget.Clickable, len(s.Nodes))
	}
}
func (v *view) updateConnectionImports(gtx C) {
	cv := &v.connections
	i := &cv.imports
	// Consume old choices before replacing rows with an asynchronous refresh.
	for n := range i.serverChoices {
		if i.serverChoices[n].Clicked(gtx) && i.subscription != nil && n < len(i.subscription.Nodes) {
			i.subscription.Selected = i.subscription.Nodes[n].ID
			cv.protocol = i.subscription.Nodes[n].Protocol
			cv.final.SetText("")
			i.serverOpen = false
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
				cv.protocol = result.subscription.node().Protocol
				cv.enabled.Value = true
				cv.final.SetText("")
				cv.message = fmt.Sprintf("Загружено серверов: %d. Выберите сервер и нажмите «Применить».", len(result.subscription.Nodes))
				if result.subscription.Skipped > 0 {
					cv.message = fmt.Sprintf("Серверов: %d, неподдерживаемых: %d. Выберите сервер и нажмите «Применить».", len(result.subscription.Nodes), result.subscription.Skipped)
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
				cv.config.SingleLine = false
				cv.config.SetText(result.text)
				cv.loadSubscriptionView(nil)
				cv.failed = false
				cv.final.SetText("")
				cv.message = "Файл импортирован. Нажмите «Применить»."
			}
		default:
		}
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
	if i.importFile.Clicked(gtx) && cv.protocol == "amneziawg" && !cv.importing() && cv.applyDone == nil && v.pickAWGFile != nil {
		i.fileDone = make(chan configFileResult, 1)
		done := i.fileDone
		pick := v.pickAWGFile
		go func() {
			path, err := pick()
			text := ""
			if err == nil && path != "" {
				text, err = readAWGConfigFile(path)
			}
			done <- configFileResult{text, err}
			changes.Add(1)
		}()
	}
	if cv.importing() {
		gtx.Execute(op.InvalidateCmd{At: gtx.Now.Add(100 * time.Millisecond)})
	}
}

func (v *view) subscriptionServerDropdown(gtx C) D {
	cv := &v.connections
	i := &cv.imports
	s := i.subscription
	if s == nil || s.URL != strings.TrimSpace(cv.config.Text()) || len(s.Nodes) == 0 {
		return D{}
	}
	if i.serverButton.Clicked(gtx) {
		i.serverOpen = !i.serverOpen
		cv.protocolOpen = false
	}
	label := "Выберите сервер"
	if n := s.node(); n != nil {
		label = n.Name
	}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx C) D {
			return layout.Stack{Alignment: layout.E}.Layout(gtx,
				layout.Stacked(func(gtx C) D {
					gtx.Constraints.Min.X = gtx.Constraints.Max.X
					return i.serverButton.Layout(gtx, func(gtx C) D {
						bg := colLine
						if i.serverButton.Hovered() {
							bg = colBtnHover
						}
						return layout.Background{}.Layout(gtx, func(gtx C) D { return fill(gtx, bg, gtx.Dp(8)) }, func(gtx C) D {
							l := bold(v.label(14, colText, label))
							l.MaxLines = 1
							return layout.Inset{Top: 8, Bottom: 8, Left: 16, Right: 48}.Layout(gtx, l.Layout)
						})
					})
				}),
				layout.Stacked(func(gtx C) D {
					return layout.Inset{Right: 16}.Layout(gtx, func(gtx C) D {
						size := gtx.Dp(16)
						var p clip.Path
						p.Begin(gtx.Ops)
						a, b := float32(size)*.3, float32(size)*.65
						if i.serverOpen {
							a, b = b, a
						}
						p.MoveTo(f32.Pt(0, a))
						p.LineTo(f32.Pt(float32(size)/2, b))
						p.LineTo(f32.Pt(float32(size), a))
						paint.FillShape(gtx.Ops, colText, clip.Stroke{Path: p.End(), Width: 1.5}.Op())
						return D{Size: image.Pt(size, size)}
					})
				}),
			)
		}),
		layout.Rigid(func(gtx C) D {
			if !i.serverOpen {
				return D{}
			}
			gtx.Constraints.Min.Y = 0
			gtx.Constraints.Max.Y = min(gtx.Constraints.Max.Y, gtx.Dp(240))
			rec := op.Record(gtx.Ops)
			offset := op.Offset(image.Pt(0, gtx.Dp(5))).Push(gtx.Ops)
			inner := op.Record(gtx.Ops)
			bg := mix(colLine, colBg, .18)
			d := v.list(gtx, &i.serverList, len(s.Nodes), func(gtx C, n int) D {
				node := s.Nodes[n]
				return i.serverChoices[n].Layout(gtx, func(gtx C) D {
					color := bg
					if node.ID == s.Selected {
						color = mix(bg, colGreen, .10)
					} else if i.serverChoices[n].Hovered() {
						color = mix(bg, colText, .05)
					}
					return layout.Background{}.Layout(gtx, func(gtx C) D { return fill(gtx, color, 0) }, func(gtx C) D {
						gtx.Constraints.Min.X = gtx.Constraints.Max.X
						l := v.label(14, colText, node.Name)
						l.MaxLines = 1
						return layout.Inset{Top: 10, Bottom: 10, Left: 16, Right: 16}.Layout(gtx, l.Layout)
					})
				})
			})
			content := inner.Stop()
			round := clip.UniformRRect(image.Rectangle{Max: d.Size}, gtx.Dp(8)).Push(gtx.Ops)
			paint.Fill(gtx.Ops, bg)
			content.Add(gtx.Ops)
			round.Pop()
			offset.Pop()
			op.Defer(gtx.Ops, rec.Stop())
			return D{}
		}),
	)
}
