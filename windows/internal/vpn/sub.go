package vpn

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	SubscriptionMaxBytes = 4 << 20
	SubscriptionMaxNodes = 512
)

// Node represents a single selectable server from a subscription.
type Node struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Protocol string          `json:"protocol"`
	Config   json.RawMessage `json:"config"`
}

// Subscription holds a fetched subscription URL, its parsed servers, and the active selection.
type Subscription struct {
	URL      string    `json:"url"`
	Title    string    `json:"title,omitempty"`
	Nodes    []Node    `json:"nodes"`
	Selected string    `json:"selected"`
	Updated  time.Time `json:"updated"`
	Skipped  int       `json:"skipped,omitempty"`
}

// Clone returns a deep copy of s.
func (s *Subscription) Clone() *Subscription {
	if s == nil {
		return nil
	}
	c := *s
	c.Nodes = make([]Node, len(s.Nodes))
	for i := range s.Nodes {
		c.Nodes[i] = s.Nodes[i]
		c.Nodes[i].Config = bytes.Clone(s.Nodes[i].Config)
	}
	return &c
}

// ActiveNode returns the currently selected node, or nil if none matches.
func (s *Subscription) ActiveNode() *Node {
	if s == nil {
		return nil
	}
	for i := range s.Nodes {
		if s.Nodes[i].ID == s.Selected {
			return &s.Nodes[i]
		}
	}
	return nil
}

// IsSubscriptionURL reports whether text is an http:// or https:// subscription link without credentials.
func IsSubscriptionURL(text string) bool {
	u, err := url.Parse(strings.TrimSpace(text))
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Hostname() != "" && u.User == nil
}

var deviceIDMu sync.Mutex

// DeviceIDAt loads or atomically generates a persistent 32-hex-char device ID for HWID subscriptions.
func DeviceIDAt(idFile string) (string, error) {
	deviceIDMu.Lock()
	defer deviceIDMu.Unlock()
	if b, err := os.ReadFile(idFile); err == nil {
		id := strings.TrimSpace(string(b))
		if len(id) == 32 {
			if raw, e := hex.DecodeString(id); e == nil && len(raw) == 16 {
				return id, nil
			}
		}
		return "", errors.New("не удалось прочитать постоянный идентификатор подписок")
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", errors.New("не удалось прочитать идентификатор подписок")
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", errors.New("не удалось создать идентификатор подписок")
	}
	id := hex.EncodeToString(b[:])
	if os.MkdirAll(filepath.Dir(idFile), 0o700) != nil {
		return "", errors.New("не удалось сохранить идентификатор подписок")
	}
	f, err := os.OpenFile(idFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", errors.New("не удалось сохранить идентификатор подписок")
	}
	_, writeErr := io.WriteString(f, id+"\n")
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		return "", errors.New("не удалось сохранить идентификатор подписок")
	}
	return id, nil
}

// SubscriptionUA builds a safe User-Agent string for subscription requests.
func SubscriptionUA(ver, id string) string {
	ver = strings.Map(func(c rune) rune {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.ContainsRune("._-", c) {
			return c
		}
		return '_'
	}, ver)
	if ver == "" {
		ver = "dev"
	}
	if len(ver) > 64 {
		ver = ver[:64]
	}
	return "fnport/" + ver + "/" + id
}

// FetchSubscription downloads and parses a subscription over the provided HTTP client.
func FetchSubscription(
	ctx context.Context,
	source, id, ver, osName, osVer string,
	client *http.Client,
) (*Subscription, error) {
	if !IsSubscriptionURL(source) {
		return nil, errors.New("нужна ссылка подписки http:// или https://")
	}
	if len(id) != 32 {
		return nil, errors.New("недоступен идентификатор устройства")
	}
	if _, err := hex.DecodeString(id); err != nil {
		return nil, errors.New("недоступен идентификатор устройства")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSpace(source), nil)
	if err != nil {
		return nil, errors.New("не удалось создать запрос подписки")
	}
	req.Header.Set("User-Agent", SubscriptionUA(ver, id))
	req.Header.Set("Accept", "text/plain, application/json;q=0.9")
	req.Header.Set("x-hwid", id)
	req.Header.Set("x-device-os", osName)
	req.Header.Set("x-device-model", "fnport for "+osName)
	if osVer != "" {
		req.Header.Set("x-ver-os", osVer)
	}

	c := *client
	c.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("redirect limit")
		}
		prev := via[0].URL
		same := strings.EqualFold(next.URL.Host, prev.Host) && next.URL.Scheme == prev.Scheme
		upgrade := prev.Scheme == "http" && next.URL.Scheme == "https" &&
			strings.EqualFold(prev.Hostname(), next.URL.Hostname()) && next.URL.Port() == ""
		if !same && !upgrade {
			return errors.New("subscription redirect origin changed")
		}
		return nil
	}

	resp, err := c.Do(req)
	if err != nil {
		return nil, errors.New("не удалось загрузить подписку: проверьте ссылку и соединение")
	}
	defer resp.Body.Close()
	for _, h := range []string{"x-hwid-max-devices-reached", "x-hwid-limit"} {
		if strings.EqualFold(resp.Header.Get(h), "true") {
			return nil, errors.New("достигнут лимит устройств подписки; освободите место в панели провайдера")
		}
	}
	if strings.EqualFold(resp.Header.Get("x-hwid-not-supported"), "true") {
		return nil, errors.New("панель не приняла идентификатор устройства fnport")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("подписка недоступна (HTTP %d)", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, SubscriptionMaxBytes+1))
	if err != nil {
		return nil, errors.New("загрузка подписки прервалась")
	}
	if len(body) > SubscriptionMaxBytes {
		return nil, errors.New("подписка больше 4 МБ")
	}
	if strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/html") {
		return nil, errors.New("сервер вернул веб-страницу; нужна прямая ссылка подписки")
	}
	nodes, skipped, err := ParseSubscription(body)
	if err != nil {
		return nil, err
	}
	title := resp.Header.Get("profile-title")
	if strings.HasPrefix(title, "base64:") {
		title = DecodeSubscriptionText(strings.TrimPrefix(title, "base64:"))
	}
	return &Subscription{
		URL:      strings.TrimSpace(source),
		Title:    CleanSubscriptionName(title, "Подписка"),
		Nodes:    nodes,
		Selected: nodes[0].ID,
		Updated:  time.Now(),
		Skipped:  skipped,
	}, nil
}

var subscriptionUUIDRe = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

// CleanSubscriptionName strips control characters and prevents credentials/UUIDs from appearing as titles.
func CleanSubscriptionName(name, fallback string) string {
	if !utf8.ValidString(name) || strings.Contains(name, "://") || subscriptionUUIDRe.MatchString(name) {
		return fallback
	}
	name = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, name)
	name = strings.TrimSpace(name)
	if name == "" {
		return fallback
	}
	runes := []rune(name)
	if len(runes) > 80 {
		name = string(runes[:80]) + "…"
	}
	return name
}

// DecodeSubscriptionText decodes standard or URL-safe Base64 subscription payloads.
func DecodeSubscriptionText(text string) string {
	text = strings.Join(strings.Fields(text), "")
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(text); err == nil && utf8.Valid(b) {
			return string(b)
		}
	}
	return ""
}

// ParseSubscription parses a plain URI list, Base64 URI list, or sing-box JSON subscription.
func ParseSubscription(body []byte) ([]Node, int, error) {
	if len(body) > SubscriptionMaxBytes {
		return nil, 0, errors.New("подписка больше 4 МБ")
	}
	text := strings.TrimSpace(strings.TrimPrefix(string(body), "\ufeff"))
	if text == "" {
		return nil, 0, errors.New("подписка пуста")
	}
	if !strings.Contains(text, "://") && !strings.HasPrefix(text, "{") && !strings.HasPrefix(text, "[") {
		if decoded := DecodeSubscriptionText(text); decoded != "" {
			text = strings.TrimSpace(decoded)
		}
	}

	var nodes []Node
	skipped := 0
	seen := make(map[string]bool)

	add := func(raw json.RawMessage, protocol, name string) {
		if len(nodes) >= SubscriptionMaxNodes {
			skipped++
			return
		}
		if !CoreOutbounds[protocol] {
			skipped++
			return
		}
		var obj map[string]any
		if json.Unmarshal(raw, &obj) != nil {
			skipped++
			return
		}
		delete(obj, "name")
		delete(obj, "tag")
		if _, err := ValidateOutboundObject(obj, ""); err != nil {
			skipped++
			return
		}
		canonical, err := json.Marshal(obj)
		if err != nil {
			skipped++
			return
		}
		hash := sha256.Sum256(canonical)
		id := hex.EncodeToString(hash[:16])
		if seen[id] {
			return
		}
		seen[id] = true
		fallback := fmt.Sprintf("%s · сервер %d", ProtocolLabel(protocol), len(nodes)+1)
		nodes = append(nodes, Node{
			ID:       id,
			Name:     CleanSubscriptionName(name, fallback),
			Protocol: protocol,
			Config:   canonical,
		})
	}

	if strings.HasPrefix(text, "{") || strings.HasPrefix(text, "[") {
		var value any
		if json.Unmarshal([]byte(text), &value) != nil {
			return nil, 0, errors.New("некорректный JSON подписки")
		}
		var visit func(any)
		visit = func(v any) {
			switch o := v.(type) {
			case []any:
				for _, item := range o {
					visit(item)
				}
			case map[string]any:
				container := false
				for _, key := range []string{"outbounds", "endpoints"} {
					if out, ok := o[key]; ok {
						visit(out)
						container = true
					}
				}
				if container {
					return
				}
				protocol, _ := o["type"].(string)
				name, _ := o["tag"].(string)
				if n, ok := o["name"].(string); ok && n != "" {
					name = n
				}
				raw, e := json.Marshal(o)
				if e == nil {
					add(raw, protocol, name)
				} else {
					skipped++
				}
			}
		}
		visit(value)
	} else {
		for _, line := range strings.Split(text, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
				continue
			}
			raw, protocol, name, err := ImportProfile(line, true)
			if err != nil {
				skipped++
				continue
			}
			add(raw, protocol, name)
		}
	}

	if len(nodes) == 0 {
		return nil, skipped, errors.New("в подписке нет поддерживаемых серверов (VLESS, Hysteria 2, Shadowsocks, Trojan, SOCKS5)")
	}
	return nodes, skipped, nil
}

// RetainSelection preserves the user's chosen server across subscription refreshes.
func RetainSelection(next, old *Subscription) {
	if old == nil || next == nil || next.URL != old.URL {
		return
	}
	chosen := old.ActiveNode()
	if chosen == nil {
		return
	}
	for _, n := range next.Nodes {
		if n.ID == chosen.ID {
			next.Selected = n.ID
			return
		}
	}
	var match *Node
	for i := range next.Nodes {
		if next.Nodes[i].Name == chosen.Name {
			if match != nil {
				return
			}
			match = &next.Nodes[i]
		}
	}
	if match != nil {
		next.Selected = match.ID
	}
}

var countryKeywords = []struct {
	code string
	keys []string
}{
	{"DE", []string{"герман", "germany", "deutschland", "frankfurt", "франкфурт", "берлин", "berlin", "мюнхен", "munich", "falkenstein"}},
	{"NL", []string{"нидерланд", "голланди", "netherlands", "amsterdam", "амстердам", "meppel"}},
	{"FI", []string{"финлянд", "finland", "helsinki", "хельсинки"}},
	{"SE", []string{"швеци", "sweden", "stockholm", "стокгольм"}},
	{"PL", []string{"польш", "poland", "warsaw", "варшав"}},
	{"LV", []string{"латви", "latvia", "riga", "рига"}},
	{"EE", []string{"эстон", "estonia", "tallinn", "таллин"}},
	{"LT", []string{"литв", "lithuania", "vilnius", "вильнюс"}},
	{"GB", []string{"великобритан", "британ", "англи", "united kingdom", "london", "лондон"}},
	{"FR", []string{"франц", "france", "paris", "париж", "страсбург", "марсель"}},
	{"US", []string{"сша", "америк", "united states", "new york", "нью-йорк", "miami", "los angeles"}},
	{"TR", []string{"турци", "turkey", "türkiye", "istanbul", "стамбул", "анталия"}},
	{"KZ", []string{"казахстан", "kazakhstan", "алматы", "almaty", "астана", "astana"}},
	{"AT", []string{"австри", "austria", "vienna", "вена"}},
	{"CH", []string{"швейцар", "switzerland", "zurich", "цюрих", "женев"}},
	{"CZ", []string{"чехи", "czech", "prague", "прага"}},
	{"IT", []string{"итали", "italy", "milan", "милан", "рим", "rome"}},
	{"ES", []string{"испан", "spain", "madrid", "мадрид", "барселон"}},
	{"NO", []string{"норвег", "norway", "oslo", "осло"}},
	{"DK", []string{"дани", "denmark", "copenhagen", "копенгаген"}},
	{"IE", []string{"ирланд", "ireland", "dublin", "дублин"}},
	{"BE", []string{"бельги", "belgium", "brussels", "брюссел"}},
	{"RO", []string{"румын", "romania", "bucharest", "бухарест"}},
	{"BG", []string{"болгар", "bulgaria", "sofia", "софи"}},
	{"HU", []string{"венгр", "hungary", "budapest", "будапешт"}},
	{"AM", []string{"армени", "armenia", "yerevan", "ереван"}},
	{"UA", []string{"украин", "ukraine", "kyiv", "киев"}},
	{"RU", []string{"росси", "russia", "москв", "moscow", "петербург", "spb"}},
}

// DisplayNodeName extracts an ISO-3166 country code (from Regional Indicator flag emojis or
// country/city keywords) and strips unsupported emoji glyphs so Gio renders clean text + vector flags.
func DisplayNodeName(raw string) (clean string, country string) {
	runes := []rune(raw)
	var kept []rune
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if r >= 0x1F1E6 && r <= 0x1F1FF {
			if i+1 < len(runes) && runes[i+1] >= 0x1F1E6 && runes[i+1] <= 0x1F1FF {
				if country == "" {
					c1 := byte('A' + (r - 0x1F1E6))
					c2 := byte('A' + (runes[i+1] - 0x1F1E6))
					code := string([]byte{c1, c2})
					if code == "UK" {
						code = "GB"
					}
					country = code
				}
				i++
			}
			continue
		}
		if r == 0xFE0E || r == 0xFE0F || r == 0x200D || r >= 0x1F000 || (r >= 0x2600 && r <= 0x27BF) {
			continue
		}
		kept = append(kept, r)
	}
	clean = strings.Join(strings.Fields(string(kept)), " ")
	clean = strings.TrimLeft(clean, "·-|—– ")
	if clean == "" {
		clean = strings.TrimSpace(raw)
	}
	if country == "" {
		lower := strings.ToLower(clean)
		for _, ck := range countryKeywords {
			for _, kw := range ck.keys {
				if strings.Contains(lower, kw) {
					country = ck.code
					break
				}
			}
			if country != "" {
				break
			}
		}
	}
	return clean, country
}
