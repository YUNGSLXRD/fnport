//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"time"

	"github.com/YUNGSLXRD/fnport/windows/internal/vpn"
)

type routerPaths struct{ Core, Run, Data string }

func loadDiscordData(dir string) ([]string, []string, error) {
	text, err := os.ReadFile(dir + "/discord-domains.lst")
	if err != nil {
		return append([]string(nil), vpn.DiscordDomains...), append([]string(nil), vpn.DiscordVoiceNetworks...), nil
	}
	raw, err := os.ReadFile(dir + "/discord-rules.json")
	if err != nil {
		return nil, nil, errors.New("discord_rules_missing")
	}
	var list struct {
		Voice []string `json:"voice_networks"`
	}
	if json.Unmarshal(raw, &list) != nil {
		return nil, nil, errors.New("discord_rules_invalid")
	}
	voice := list.Voice
	domains := domainList(string(text))
	if len(domains) == 0 || len(voice) == 0 {
		return nil, nil, errors.New("discord_rules_empty")
	}
	return domains, voice, nil
}

func probeTunnelConnectivity(ctx context.Context, c routerConfig) bool {
	check, stop := context.WithTimeout(ctx, 8*time.Second)
	defer stop()
	provider := dnsProviders[c.DNSProvider]
	port := "443"
	if c.DNSMode == "tls" {
		port = "853"
	} else if c.DNSMode == "plain" {
		port = "53"
	}
	link, err := dialCore(check, net.JoinHostPort(provider.IP, port))
	if err != nil {
		return false
	}
	_ = link.Close()
	return true
}

func runRouter(parent context.Context, c routerConfig, nodeName string, paths routerPaths) (result error) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	status := connectionStatus{State: "starting", Protocol: c.Protocol, NodeName: nodeName}
	defer func() {
		if result != nil && parent.Err() == nil {
			status.State = "failed"
			status.Error = result.Error()
		} else {
			status.State = "stopped"
			status.Error = ""
		}
		saveStatus(paths.Run, status)
	}()
	if err := c.validate(); err != nil {
		return err
	}
	if err := privateDir(paths.Run); err != nil {
		return err
	}
	saveStatus(paths.Run, status)

	var discord, voice []string
	var err error
	if c.Discord {
		discord, voice, err = loadDiscordData(paths.Data)
		if err != nil {
			return err
		}
	}
	cache := &serviceAddresses{}
	fw, err := newOwnedFirewall(ctx, c, voice, cache)
	if err != nil {
		return err
	}
	defer fw.close()

	var native *nativeTunnel
	if c.Protocol == "warp" || c.Protocol == "amneziawg" || c.Protocol == "wireguard" {
		native, err = newNativeTunnel(ctx, c)
		if err != nil {
			return err
		}
		defer native.close()
		if c.Protocol == "warp" {
			status.State = "selecting_exit"
			saveStatus(paths.Run, status)
			report, e := selectNativeExit(ctx, native, c.Native.Endpoint)
			if e != nil {
				return e
			}
			status.Colo = report.Colo
			status.Country = report.Country
			status.Address = report.Address
			status.RTTMS = report.RTT.Milliseconds()
		} else {
			endpoint, e := resolveNativeEndpoint(ctx, c.WAN, c.Native.Endpoint)
			if e != nil {
				return e
			}
			if e = native.setEndpoint(endpoint); e != nil {
				return e
			}
		}
	}

	config, err := c.coreConfig()
	if err != nil {
		return err
	}
	core, err := startCore(ctx, paths.Core, paths.Run, config)
	if err != nil {
		return err
	}
	defer core.close()
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 2*time.Second)
		defer stop()
		_ = fw.alive(cleanup, false)
	}()

	acl := newClientACL(c)
	if err := acl.refresh(ctx); err != nil {
		return err
	}
	ready := make(chan struct{})
	dns := newDNSBroker(c, vpn.EpicDomains, discord, cache, acl.allow)
	dns.publish = fw.publish
	dns.ready = ready
	dnsDone := make(chan error, 1)
	go func() { dnsDone <- dns.serve(ctx, ":10553") }()
	defer cancel()
	select {
	case <-ready:
	case err := <-dnsDone:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}

	if !probeTunnelConnectivity(ctx, c) {
		return errors.New("selected_connection_unreachable")
	}
	if status.Address == "" {
		check, stop := context.WithTimeout(ctx, 6*time.Second)
		report, e := traceExit(check, dialCore)
		stop()
		if e == nil {
			status.Colo = report.Colo
			status.Country = report.Country
			status.Address = report.Address
			status.RTTMS = report.RTT.Milliseconds()
		}
	}
	if err := fw.alive(ctx, true); err != nil {
		return err
	}
	status.State = "connected"
	saveStatus(paths.Run, status)

	go dns.preResolveServices(ctx)

	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	healthTick := time.NewTicker(60 * time.Second)
	defer healthTick.Stop()
	tickCount := 0
	healthFails := 0

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-core.done:
			return errors.New("core_exited")
		case err := <-dnsDone:
			if err != nil {
				return err
			}
			return errors.New("dns_stopped")
		case <-tick.C:
			tickCount++
			round, stop := context.WithTimeout(ctx, 2*time.Second)
			err := fw.publish(round)
			if err == nil && tickCount%2 == 0 {
				err = acl.refresh(round)
				if err == nil {
					err = fw.alive(round, true)
				}
			}
			stop()
			if err != nil {
				return err
			}
		case <-healthTick.C:
			if probeTunnelConnectivity(ctx, c) {
				healthFails = 0
				continue
			}
			healthFails++
			if healthFails < 2 {
				continue
			}
			healthFails = 0
			dns.doh.CloseIdle()
			if c.Protocol == "warp" && native != nil {
				if report, e := selectNativeExit(ctx, native, c.Native.Endpoint); e == nil && probeTunnelConnectivity(ctx, c) {
					status.Colo = report.Colo
					status.Country = report.Country
					status.Address = report.Address
					status.RTTMS = report.RTT.Milliseconds()
					saveStatus(paths.Run, status)
					continue
				}
			}
			return errors.New("tunnel_healthcheck_failed")
		}
	}
}
