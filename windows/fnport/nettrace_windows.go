//go:build windows && devtrace

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/netip"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

func networkTraceSupported() bool { return true }

// Diagnostic only. A fixed PowerShell command returns structured DNS cache
// objects, never localized console tables. It runs at most once per ten seconds,
// has a timeout/output cap, and is never called on the forwarding path. No DNS
// queries or reverse lookups are issued. DoH/app-local caches may be absent.
func readNetworkTraceDNS(ctx context.Context) (map[netip.Addr][]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, err
	}
	ps := filepath.Join(system, "WindowsPowerShell", "v1.0", "powershell.exe")
	script := `[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false); $ErrorActionPreference='Stop'; @(Get-DnsClientCache | Where-Object { $_.Type -eq 1 -or $_.Type -eq 28 } | Select-Object Entry,Data,TimeToLive) | ConvertTo-Json -Compress`
	cmd := exec.CommandContext(ctx, ps, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.WaitDelay = time.Second
	output := &traceLimitedBuffer{limit: 4 * 1024 * 1024}
	cmd.Stdout = output
	cmd.Stderr = io.Discard // never log raw command output or local configuration
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return parseNetworkTraceDNS(output.Bytes())
}

type traceLimitedBuffer struct {
	buffer bytes.Buffer
	limit  int
}

func (b *traceLimitedBuffer) Bytes() []byte { return b.buffer.Bytes() }

func (b *traceLimitedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.buffer.Len() {
		return 0, errors.New("DNS cache output exceeds limit")
	}
	return b.buffer.Write(p)
}
