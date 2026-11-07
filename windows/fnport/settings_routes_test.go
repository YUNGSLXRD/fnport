package main

import (
	"net/netip"
	"reflect"
	"testing"
)

func TestGameRouteUpgrade(t *testing.T) {
	legacy := []string{"3.0.0.0/8", "13.32.0.0/11", "15.0.0.0/8", "18.0.0.0/8", "35.156.0.0/14", "35.176.0.0/13"}
	for _, tc := range []struct {
		name    string
		routes  []string
		migrate bool
	}{
		{"legacy", legacy, true},
		{"reordered", []string{"35.176.0.0/13", "35.156.0.0/14", "18.0.0.0/8", "15.0.0.0/8", "13.32.0.0/11", " 3.0.0.0/8 "}, true},
		{"current", defaultSettings().Routes, false},
		{"empty", []string{}, false},
		{"custom subset", legacy[:3], false},
		{"custom extra", append(append([]string(nil), legacy...), "192.0.2.0/24"), false},
		{"custom replacement", []string{"3.0.0.0/8", "13.32.0.0/11", "15.0.0.0/8", "18.0.0.0/8", "35.156.0.0/14", "192.0.2.0/24"}, false},
		{"duplicate", []string{"3.0.0.0/8", "3.0.0.0/8", "15.0.0.0/8", "18.0.0.0/8", "35.156.0.0/14", "35.176.0.0/13"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := append([]string{}, tc.routes...)
			got := upgradeDefaultGameRoutes(tc.routes)
			want := tc.routes
			if tc.migrate {
				want = append(append([]string(nil), tc.routes...), "51.44.0.0/16")
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("routes = %v, want %v", got, want)
			}
			if !reflect.DeepEqual(tc.routes, before) {
				t.Fatal("migration changed source routes")
			}
			if again := upgradeDefaultGameRoutes(got); !reflect.DeepEqual(again, got) {
				t.Fatal("upgrade is not idempotent")
			}
		})
	}
}

func TestParisGameServerCoverage(t *testing.T) {
	s := defaultSettings()
	s.Fake = "" // This test checks routes without reading installed fake files.
	cfg, err := s.config()
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"51.44.0.1", "51.44.255.254"} {
		if !inPrefixes(netip.MustParseAddr(ip), cfg.routes) || !cfg.gamePort(15009) {
			t.Fatalf("Paris game server %s is not covered", ip)
		}
	}
	for _, ip := range []string{"51.43.255.254", "51.45.0.1", "34.165.0.1"} {
		if inPrefixes(netip.MustParseAddr(ip), cfg.routes) {
			t.Fatalf("unrelated network %s was included", ip)
		}
	}
	if cfg.gamePort(443) {
		t.Fatal("HTTPS was classified as game UDP")
	}
}
