//go:build linux

package main

import (
	"context"
	"net"
	"os"
	"testing"
	"time"
)

func TestLinuxRealCoreConfigurationAndLifecycle(t *testing.T) {
	requireNetworkNamespace(t)
	path := os.Getenv("FNPORT_TEST_SING_BOX")
	if path == "" {
		t.Skip("pinned Linux sing-box required")
	}
	runNetTest(t, "", "ip", "link", "set", "lo", "up")
	c := routerTestConfig()
	c.WAN = "lo"
	raw, err := c.coreConfig()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	p, err := startCore(ctx, path, dir, raw)
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	socket, err := net.DialTimeout("tcp", "127.0.0.1:10898", time.Second)
	if err != nil {
		t.Fatal("local proxy did not start", err)
	}
	socket.Close()
	p.close()
	socket, err = net.DialTimeout("tcp", "127.0.0.1:10898", time.Second)
	if err == nil {
		socket.Close()
		t.Fatal("proxy remained after stop")
	}
	c.Protocol = "warp"
	raw, err = c.coreConfig()
	if err != nil {
		t.Fatal(err)
	}
	// Checking native schema must not create an interface or touch network state.
	if err = writePrivate(dir+"/native.json", raw); err != nil {
		t.Fatal(err)
	}
	runNetTest(t, "", path, "check", "-c", dir+"/native.json")
}

func TestLinuxPackagedDiscordData(t *testing.T) {
	domains, voice, err := loadDiscordData(func() string {
		if dir := os.Getenv("FNPORT_ROUTER_DATA"); dir != "" {
			return dir
		}
		return "../../fnport/files"
	}())
	if err != nil || len(domains) != 20 || len(voice) != 8 {
		t.Fatal("packaged Discord data does not load", err)
	}
}
