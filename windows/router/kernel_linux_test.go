//go:build linux

package main

import (
	"bytes"
	"golang.org/x/net/dns/dnsmessage"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func requireNetworkNamespace(t *testing.T) {
	t.Helper()
	if os.Getenv("FNPORT_ROUTER_NET_TEST") != "1" {
		t.Skip("isolated Linux namespace required")
	}
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	initial, err := os.Readlink("/proc/1/ns/net")
	if err != nil || current == initial || os.Geteuid() != 0 {
		t.Fatal("refusing changes outside root-owned isolated network namespace")
	}
}
func runNetTest(t *testing.T, stdin string, command string, args ...string) []byte {
	t.Helper()
	cmd := exec.Command(command, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v: %s", command, err, out)
	}
	return out
}
func TestLinuxFirewallKernel(t *testing.T) {
	requireNetworkNamespace(t)
	c := routerTestConfig()
	c.Discord = true
	c.Devices = append(c.Devices, "02:00:00:00:00:11")
	rules, err := firewallRules(c, []string{"35.192.0.0/11", "104.16.0.0/12"})
	if err != nil {
		t.Fatal(err)
	}
	runNetTest(t, rules, "nft", "-c", "-f", "-")
	runNetTest(t, rules, "nft", "-f", "-")
	defer runNetTest(t, "", "nft", "delete", "table", "inet", "fnport_connections")
	out := runNetTest(t, "", "nft", "list", "set", "inet", "fnport_connections", "clients4")
	if bytes.Contains(out, []byte("elements =")) {
		t.Fatal("clients activated before readiness")
	}
	runNetTest(t, "add element inet fnport_connections clients4 { 192.168.1.100 timeout 1s }\nadd element inet fnport_connections clients_mac { 02:00:00:00:00:11 timeout 1s }\n", "nft", "-f", "-")
}

func TestLinuxFirewallOwnershipAndFailOpen(t *testing.T) {
	requireNetworkNamespace(t)
	c := routerTestConfig()
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	cache := &serviceAddresses{}
	fw, err := newOwnedFirewall(t.Context(), c, nil, cache)
	if err != nil {
		t.Fatal(err)
	}
	defer fw.close()
	if _, err := newOwnedFirewall(t.Context(), c, nil, cache); err == nil {
		t.Fatal("second instance overwrote owned resources")
	}
	if err := fw.alive(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	if out := runNetTest(t, "", "nft", "list", "set", "inet", "fnport_connections", "clients4"); !bytes.Contains(out, []byte("192.168.1.100")) {
		t.Fatal("selected client missing")
	}
	q := dnsQuery(t, "account.epicgames.com", dnsmessage.TypeA)
	cache.learn("epic", dnsAnswer(t, q, [4]byte{8, 8, 4, 4}, 60), time.Now())
	if err := fw.publish(t.Context()); err != nil {
		t.Fatal(err)
	}
	if out := runNetTest(t, "", "nft", "list", "set", "inet", "fnport_connections", "services4"); !bytes.Contains(out, []byte("8.8.4.4")) {
		t.Fatal("DNS route not published")
	}
	if err := fw.alive(t.Context(), false); err != nil {
		t.Fatal(err)
	}
	if out := runNetTest(t, "", "nft", "list", "set", "inet", "fnport_connections", "clients4"); bytes.Contains(out, []byte("elements =")) {
		t.Fatal("clients remain intercepted after failure")
	}
	fw.close()
	if err := routingAvailable(t.Context()); err != nil {
		t.Fatal("owned routing leaked", err)
	}
	if exec.Command("nft", "list", "table", "inet", "fnport_connections").Run() == nil {
		t.Fatal("owned firewall leaked")
	}
	// A conflicting priority belongs to someone else and must remain intact.
	runNetTest(t, "", "ip", "-4", "rule", "add", "pref", "79", "fwmark", "1234", "lookup", "main")
	defer runNetTest(t, "", "ip", "-4", "rule", "del", "pref", "79", "fwmark", "1234", "lookup", "main")
	if _, err := newOwnedFirewall(t.Context(), c, nil, cache); err == nil {
		t.Fatal("conflicting routing accepted")
	}
	rules := runNetTest(t, "", "ip", "-4", "rule", "show")
	if !bytes.Contains(rules, []byte("0x4d2")) {
		t.Fatal("another service rule was deleted")
	}
}

func TestLinuxRecoversOnlyOwnedCrashResources(t *testing.T) {
	requireNetworkNamespace(t)
	c := routerTestConfig()
	c.validate()
	fw, err := newOwnedFirewall(t.Context(), c, nil, &serviceAddresses{})
	if err != nil {
		t.Fatal(err)
	}
	defer fw.close()
	if err := recoverOwnedFirewall(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := routingAvailable(t.Context()); err != nil {
		t.Fatal("stale routing survived recovery", err)
	}
	fw.table, fw.route, fw.proxy, fw.bypass = false, false, false, false
	runNetTest(t, "table inet fnport_connections { comment \"someone-else\"; }", "nft", "-f", "-")
	defer runNetTest(t, "", "nft", "delete", "table", "inet", "fnport_connections")
	if err := recoverOwnedFirewall(t.Context()); err == nil {
		t.Fatal("foreign table accepted")
	}
	if out := runNetTest(t, "", "nft", "list", "table", "inet", "fnport_connections"); !bytes.Contains(out, []byte("someone-else")) {
		t.Fatal("foreign table modified")
	}
}

func TestLinuxDNSConntrackCleanup(t *testing.T) {
	requireNetworkNamespace(t)
	c := routerTestConfig()
	fw, err := newOwnedFirewall(t.Context(), c, nil, &serviceAddresses{})
	if err != nil {
		t.Fatal(err)
	}
	defer fw.close()
	for _, family := range []string{"ipv4", "ipv6"} {
		src, dst := "192.0.2.2", "192.0.2.1"
		if family == "ipv6" {
			src, dst = "2001:db8::2", "2001:db8::1"
		}
		for _, mark := range []string{"61811", "61812"} {
			port := "55000"
			if mark == "61812" {
				port = "55001"
			}
			runNetTest(t, "", "conntrack", "-I", "-p", "udp", "--orig-src", src, "--orig-dst", dst, "--sport", port, "--dport", "53", "--reply-src", dst, "--reply-dst", src, "--reply-port-src", "53", "--reply-port-dst", port, "--mark", mark, "--timeout", "120")
		}
		t.Cleanup(func() { exec.Command("conntrack", "-D", "-f", family, "--mark", "61812").Run() })
	}
	if err := fw.alive(t.Context(), false); err != nil {
		t.Fatal(err)
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		out := runNetTest(t, "", "conntrack", "-L", "-f", family)
		if bytes.Contains(out, []byte("mark=61811")) {
			t.Fatalf("owned DNS %s conntrack remained after stop: %s", family, out)
		}
		if !bytes.Contains(out, []byte("mark=61812")) {
			t.Fatalf("unrelated %s conntrack was removed: %s", family, out)
		}
	}
}
