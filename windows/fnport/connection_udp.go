package main

import (
	"net"
	"net/netip"
	"time"

	"github.com/YUNGSLXRD/fnport/windows/internal/wnet"
)

func (e *engine) assignConnection(f *uflow) {
	ctx, cancel := connectionContext(e.tcp.ctx)
	c, err := e.connection.dial(ctx, f.key.dst, true)
	cancel()
	if err != nil {
		f.mu.Lock()
		report := !f.reported
		f.reported = true
		f.failed = true
		f.retryAfter = time.Now().Add(5 * time.Second)
		f.pending = nil
		f.mu.Unlock()
		if report {
			logf("Подключения: UDP к %s не установлено через %s, повторю при следующем трафике", f.key.dst, e.connection.settings.Protocol)
		}
		return
	}

	// Install under the same engine lock as close, so stopping cannot miss a socket.
	e.mu.Lock()
	select {
	case <-e.done:
		e.mu.Unlock()
		c.Close()
		return
	default:
	}
	f.mu.Lock()
	queue := make(chan []byte, maxPending)
	for _, b := range f.pending {
		queue <- b
	}
	f.pending = nil
	f.tunnel, f.send = c, queue
	f.mu.Unlock()
	e.mu.Unlock()
	done := make(chan struct{})
	go func() { defer close(done); e.backConnection(f, c) }()
	// A tunnel waiting for its handshake must never block the shared TUN reader.
	go func() {
		for {
			select {
			case <-done:
				return
			case <-e.done:
				c.Close()
				return
			case b := <-queue:
				c.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if _, err := c.Write(b); err != nil {
					c.Close()
					return
				}
				f.out.Add(1)
				f.totalOut.Add(1)
			}
		}
	}()

}

func (e *engine) backConnection(f *uflow, c net.Conn) {
	defer c.Close()
	defer func() {
		e.mu.Lock()
		if e.flows[f.key] == f {
			delete(e.flows, f.key)
		}
		e.mu.Unlock()
	}()
	buf := make([]byte, 65535)
	client := netip.AddrPortFrom(f.key.srcIP, f.key.cport)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return
		}
		f.in.Add(1)
		f.totalIn.Add(1)
		f.mu.Lock()
		f.last = time.Now()
		f.mu.Unlock()
		if e.dev.WritePacket(wnet.BuildUDP4(f.key.dst, client, buf[:n], uint16(e.ipID.Add(1)))) != nil {
			return
		}
	}
}
