package vpn

import (
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

// EpicDomains covers Epic Games Launcher login, store, updates, CDN, party, chat,
// matchmaking, Easy Anti-Cheat, and hCaptcha. Game UDP servers and QoS latency
// beacons (ping-*.ds.on.epicgames.com) are excluded and always stay direct.
var EpicDomains = []string{
	"fortnite-vod.akamaized.net",
	"fortnite-storage-live.s3.amazonaws.com",
	"epicgames.com",
	"epicgames.dev",
	"epicgames.net",
	"epicgamescdn.com",
	"unrealengine.com",
	"fortnite.com",
	"easyanticheat.net",
	"hcaptcha.com",
	"epicgames-download1.akamaized.net",
	"egdownload.fastly-edge.com",
	"account-public-service-prod.ol.epicgames.com",
	"account-public-service-prod03.ol.epicgames.com",
	"launcherwaitingroom-public-service-prod06.ol.epicgames.com",
	"launcher-public-service-prod06.ol.epicgames.com",
	"www.epicgames.com",
	"launcher-website-prod07.ol.epicgames.com",
	"tracking.epicgames.com",
	"accounts.launcher-website-prod07.ol.epicgames.com",
	"accounts.epicgames.com",
	"cdn1.epicgames.com",
	"cdn2.epicgames.com",
	"cdn1.unrealengine.com",
	"cdn2.unrealengine.com",
	"datarouter.ol.epicgames.com",
	"entitlement-public-service-prod08.ol.epicgames.com",
	"orderprocessor-public-service-ecomprod01.ol.epicgames.com",
	"catalog-public-service-prod06.ol.epicgames.com",
	"friends-public-service-prod.ol.epicgames.com",
	"friends-public-service-prod06.ol.epicgames.com",
	"lightswitch-public-service-prod.ol.epicgames.com",
	"lightswitch-public-service-prod06.ol.epicgames.com",
	"accountportal-website-prod07.ol.epicgames.com",
	"ut-public-service-prod10.ol.epicgames.com",
	"party-service-prod.ol.epicgames.com",
	"xmpp-service-prod.ol.epicgames.com",
	"fortnite-public-service-prod11.ol.epicgames.com",
	"events-public-service-live.ol.epicgames.com",
	"fngw-mcp-gc-livefn.ol.epicgames.com",
	"fortnite-matchmaking-public-service-live-eu.ol.epicgames.com",
	"eulatracking-public-service-prod-m.ol.epicgames.com",
	"statsproxy-public-service-live.ol.epicgames.com",
	"talon-service-prod.ecosec.on.epicgames.com",
	"fortnitecontent-website-prod07.ol.epicgames.com",
	"library-service.live.use1a.on.epicgames.com",
	"datastorage-public-service-liveegs.live.use1a.on.epicgames.com",
	"download.epicgames.com",
	"download2.epicgames.com",
	"download3.epicgames.com",
	"download4.epicgames.com",
	"fastly-download.epicgames.com",
	"cloudflare.epicgamescdn.com",
	"static-assets-prod.epicgames.com",
	"shared-static-prod.epicgames.com",
	"store-site-backend-static.ak.epicgames.com",
	"store-content.ak.epicgames.com",
	"store.epicgames.com",
	"launcher.store.epicgames.com",
	"egs-platform-service.store.epicgames.com",
	"api.epicgames.dev",
	"js.hcaptcha.com",
}

// DiscordDomains covers Discord web, desktop gateway, CDN, media, activities, and voice signaling.
var DiscordDomains = []string{
	"dis.gd",
	"discord-activities.com",
	"discord-attachments-uploads-prd.storage.googleapis.com",
	"discord.co",
	"discord.com",
	"discord.design",
	"discord.dev",
	"discord.gg",
	"discord.gift",
	"discord.gifts",
	"discord.media",
	"discord.new",
	"discord.store",
	"discord.tools",
	"discordactivities.com",
	"discordapp.com",
	"discordapp.net",
	"discordmerch.com",
	"discordpartygames.com",
	"discordsays.com",
}

// DiscordPreResolveDomains includes key Discord subdomains resolved at startup so an
// already-running Discord client connects through the tunnel without waiting on DNS TTL expiry.
var DiscordPreResolveDomains = []string{
	"discord.com",
	"gateway.discord.gg",
	"cdn.discordapp.com",
	"media.discordapp.net",
	"images-ext-1.discordapp.net",
	"images-ext-2.discordapp.net",
	"status.discord.com",
	"updates.discord.com",
	"latency.discord.media",
}

// DiscordVoiceNetworks lists IPv4 ranges used by Discord WebRTC/RTP voice servers (UDP 50000-65535),
// whose addresses are sent inside the encrypted gateway session without a DNS lookup.
var DiscordVoiceNetworks = []string{
	"104.16.0.0/12",
	"138.128.136.0/21",
	"162.158.0.0/15",
	"172.64.0.0/13",
	"34.0.0.0/14",
	"35.192.0.0/11",
	"5.200.14.128/25",
	"66.22.192.0/18",
}

var DiscordVoicePrefixes = func() []netip.Prefix {
	out := make([]netip.Prefix, 0, len(DiscordVoiceNetworks))
	for _, s := range DiscordVoiceNetworks {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

var validHostRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$`)

// CleanDomain turns a user-entered URL, wildcard, or domain line into a lowercase bare domain.
func CleanDomain(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/:?# \t\r"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimPrefix(strings.TrimPrefix(s, "*."), ".")
	s = strings.TrimSuffix(s, ".")
	if len(s) > 253 || !strings.Contains(s, ".") || strings.Contains(s, "..") || !validHostRe.MatchString(s) {
		return ""
	}
	return s
}

// ParseDomainList extracts deduplicated, validated domains from a newline-separated string.
func ParseDomainList(text string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, line := range strings.Split(text, "\n") {
		line, _, _ = strings.Cut(line, "#")
		if d := CleanDomain(line); d != "" && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return out
}

// SortedDomainList returns a sorted deduplicated domain slice for canonical storage.
func SortedDomainList(text string) []string {
	out := ParseDomainList(text)
	sort.Strings(out)
	return out
}

// IsEpicBeacon reports whether host is an Epic QoS latency beacon, which must always
// be probed directly to measure real ISP path latency rather than VPN exit latency.
func IsEpicBeacon(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if h == "ds.on.epicgames.com" || strings.HasSuffix(h, ".ds.on.epicgames.com") {
		return true
	}
	return strings.HasPrefix(h, "qosping-") && strings.HasSuffix(h, ".ol.epicgames.com")
}

// MatchDomain reports whether host equals or is a subdomain of any entry in names.
func MatchDomain(host string, names []string) bool {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if h == "" {
		return false
	}
	for _, s := range names {
		if h == s || strings.HasSuffix(h, "."+s) {
			return true
		}
	}
	return false
}

// MatchEpic reports whether host belongs to Epic's launcher/store/service domains
// while excluding QoS latency beacons.
func MatchEpic(host string, names []string) bool {
	if IsEpicBeacon(host) {
		return false
	}
	if len(names) == 0 {
		names = EpicDomains
	}
	return MatchDomain(host, names)
}
