package main

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Only fixed stages and numeric codes reach logs. Underlying network/core
// errors can contain imported credentials, so never format or unwrap their text.
type connectionSetupError struct {
	stage   string
	code    uint32
	timeout bool
}

func (e *connectionSetupError) Error() string {
	return fmt.Sprintf("этап %s, код %d, тайм-аут %t", e.stage, e.code, e.timeout)
}
func connectionFailure(stage string, cause error) *connectionSetupError {
	e := &connectionSetupError{stage: stage}
	var errno syscall.Errno
	if errors.As(cause, &errno) {
		e.code = uint32(errno)
	}
	var ne net.Error
	if errors.As(cause, &ne) {
		e.timeout = ne.Timeout()
	}
	return e
}

type connectionFailureWindow struct {
	last  time.Time
	count uint64
}

func (w *connectionFailureWindow) record(now time.Time) (uint64, bool) {
	w.count++
	if !w.last.IsZero() && now.Sub(w.last) < 10*time.Second {
		return 0, false
	}
	n := w.count
	w.count, w.last = 0, now
	return n, true
}
func (r *connectionRouter) reportFailure(udp bool, cause error) {
	kind, index := "TCP", 0
	if udp {
		kind, index = "UDP", 1
	}
	r.failuresMu.Lock()
	count, show := r.failures[index].record(time.Now())
	r.failuresMu.Unlock()
	if !show {
		return
	}
	detail := connectionFailure("transport", cause)
	var setup *connectionSetupError
	if errors.As(cause, &setup) {
		detail = setup
	}
	if r.transport != nil {
		select {
		case <-r.transport.done:
			detail = &connectionSetupError{stage: "core_exited"}
		default:
		}
	}
	logf("Подключения: %s через %s не установлено (%s); ошибок с предыдущего сообщения: %d", kind, r.settings.Protocol, detail, count)
}

// Retain only a tiny in-memory suffix to recognize split runtime markers.
// Neither stderr nor a user-supplied substring is returned or written to disk.
type connectionCoreDiagnostic struct {
	mu    sync.Mutex
	tail  string
	class string
}

func (d *connectionCoreDiagnostic) Write(b []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for off := 0; off < len(b); off += 256 {
		end := off + 256
		if end > len(b) {
			end = len(b)
		}
		s := d.tail + string(b[off:end])
		switch {
		case strings.Contains(s, "fatal error: out of memory"), strings.Contains(s, "fatal error: runtime: out of memory"):
			d.class = "out_of_memory"
		case d.class != "out_of_memory" && strings.Contains(s, "panic:"):
			d.class = "panic"
		case d.class == "" && strings.Contains(s, "fatal error:"):
			d.class = "runtime_fatal"
		}
		if len(s) > 64 {
			s = s[len(s)-64:]
		}
		d.tail = s
	}
	return len(b), nil
}
func (d *connectionCoreDiagnostic) category() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.class == "" {
		return "none"
	}
	return d.class
}
