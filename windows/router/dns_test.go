package main

import (
	"context"
	"errors"
	"golang.org/x/net/dns/dnsmessage"
	"net/netip"
	"testing"
	"time"
)

func dnsQuery(t *testing.T, host string, typ dnsmessage.Type) []byte {
	t.Helper()
	name, err := dnsmessage.NewName(host + ".")
	if err != nil {
		t.Fatal(err)
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 42, RecursionDesired: true})
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: name, Type: typ, Class: dnsmessage.ClassINET})
	out, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func dnsAnswer(t *testing.T, query []byte, ip [4]byte, ttl uint32) []byte {
	t.Helper()
	var p dnsmessage.Parser
	h, _ := p.Start(query)
	q, _ := p.AllQuestions()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RecursionAvailable: true})
	b.StartQuestions()
	b.Question(q[0])
	b.StartAnswers()
	b.AResource(dnsmessage.ResourceHeader{Name: q[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: ttl}, dnsmessage.AResource{A: ip})
	out, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func TestRouterDNSSelectsServicesAndPreservesOtherDNS(t *testing.T) {
	c := routerTestConfig()
	c.Discord = true
	cache := &serviceAddresses{}
	b := newDNSBroker(c, []string{"epicgames.com"}, []string{"discord.com", "discord.media"}, cache, func(netip.Addr) bool { return true })
	selectedCalls, directCalls := 0, 0
	b.resolve = func(_ context.Context, q []byte, selected bool) ([]byte, error) {
		if selected {
			selectedCalls++
		} else {
			directCalls++
		}
		return dnsAnswer(t, q, [4]byte{8, 8, 4, 4}, 60), nil
	}
	for _, host := range []string{"voice.discord.media", "account.epicgames.com", "router.lan", "discord.com.attacker.test"} {
		if b.answer(context.Background(), dnsQuery(t, host, dnsmessage.TypeA)) == nil {
			t.Fatal("missing response")
		}
	}
	if selectedCalls != 2 || directCalls != 2 {
		t.Fatal("DNS escaped selected service boundary")
	}
	rows, _ := cache.snapshot(time.Now())
	if len(rows) != 2 {
		t.Fatal("wrong cache membership")
	}
	before := selectedCalls + directCalls
	response := b.answer(context.Background(), dnsQuery(t, "voice.discord.media", dnsmessage.TypeAAAA))
	var p dnsmessage.Parser
	h, err := p.Start(response)
	_, questionErr := p.AllQuestions()
	answers, answerErr := p.AllAnswers()
	if err != nil || questionErr != nil || answerErr != nil || h.RCode != dnsmessage.RCodeSuccess || len(answers) != 0 || selectedCalls+directCalls != before {
		t.Fatal("selected IPv6 service escaped IPv4 tunnel")
	}
}
func TestRouterDNSRejectsMismatchedRepliesAndExpiresAddresses(t *testing.T) {
	c := routerTestConfig()
	cache := &serviceAddresses{}
	b := newDNSBroker(c, []string{"epicgames.com"}, nil, cache, func(netip.Addr) bool { return true })
	b.resolve = func(_ context.Context, q []byte, _ bool) ([]byte, error) {
		out := dnsAnswer(t, q, [4]byte{8, 8, 4, 4}, 60)
		out[1]++
		return out, nil
	}
	var p dnsmessage.Parser
	h, err := p.Start(b.answer(context.Background(), dnsQuery(t, "account.epicgames.com", dnsmessage.TypeA)))
	if err != nil || h.RCode != dnsmessage.RCodeServerFailure {
		t.Fatal("mismatched DNS reply accepted")
	}
	now := time.Now()
	q := dnsQuery(t, "account.epicgames.com", dnsmessage.TypeA)
	cache.learn("epic", dnsAnswer(t, q, [4]byte{127, 0, 0, 1}, 60), now)
	cache.learn("epic", dnsAnswer(t, q, [4]byte{198, 18, 0, 2}, 60), now)
	cache.learn("epic", dnsAnswer(t, q, [4]byte{8, 8, 4, 4}, 2), now)
	rows, changed := cache.snapshot(now)
	if len(rows) != 1 || !changed {
		t.Fatal("invalid/fake addresses entered service routes")
	}
	rows, changed = cache.snapshot(now.Add(3 * time.Second))
	if len(rows) != 0 || !changed {
		t.Fatal("DNS lease did not expire")
	}
}

func TestRouterDNSWaitsForFirewallBeforeAnswer(t *testing.T) {
	cache := &serviceAddresses{}
	b := newDNSBroker(routerTestConfig(), []string{"epicgames.com"}, nil, cache, func(netip.Addr) bool { return true })
	b.resolve = func(_ context.Context, q []byte, _ bool) ([]byte, error) {
		return dnsAnswer(t, q, [4]byte{8, 8, 4, 4}, 60), nil
	}
	entered, release := make(chan struct{}), make(chan struct{})
	b.publish = func(context.Context) error { close(entered); <-release; return nil }
	done := make(chan []byte, 1)
	go func() { done <- b.answer(context.Background(), dnsQuery(t, "account.epicgames.com", dnsmessage.TypeA)) }()
	<-entered
	select {
	case <-done:
		t.Fatal("DNS client received IP before firewall route")
	default:
	}
	close(release)
	var p dnsmessage.Parser
	h, err := p.Start(<-done)
	if err != nil || h.RCode != dnsmessage.RCodeSuccess {
		t.Fatal("route-ready response rejected")
	}
	b.publish = func(context.Context) error { return errors.New("route_failed") }
	h, err = p.Start(b.answer(context.Background(), dnsQuery(t, "account.epicgames.com", dnsmessage.TypeA)))
	if err != nil || h.RCode != dnsmessage.RCodeServerFailure {
		t.Fatal("route failure allowed direct first connection")
	}
}
