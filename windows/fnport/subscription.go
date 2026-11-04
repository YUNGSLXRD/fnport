package main

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
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/YUNGSLXRD/fnport/windows/internal/wnet"
)

const subscriptionMaxBytes = 4 << 20
const subscriptionMaxNodes = 512

type subscriptionNode struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Protocol string          `json:"protocol"`
	Config   json.RawMessage `json:"config"`
}
type connectionSubscription struct {
	URL      string             `json:"url"`
	Title    string             `json:"title,omitempty"`
	Nodes    []subscriptionNode `json:"nodes"`
	Selected string             `json:"selected"`
	Updated  time.Time          `json:"updated"`
	Skipped  int                `json:"skipped,omitempty"`
}

func cloneSubscription(s *connectionSubscription) *connectionSubscription {
	if s == nil {
		return nil
	}
	c := *s
	c.Nodes = append([]subscriptionNode(nil), s.Nodes...)
	for i := range c.Nodes {
		c.Nodes[i].Config = bytes.Clone(c.Nodes[i].Config)
	}
	return &c
}
func (s *connectionSubscription) node() *subscriptionNode {
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
func subscriptionURL(text string) bool {
	u, e := url.Parse(strings.TrimSpace(text))
	return e == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Hostname() != "" && u.User == nil
}

var subscriptionIDMu sync.Mutex

func subscriptionDeviceIDAt(path string) (string, error) {
	subscriptionIDMu.Lock()
	defer subscriptionIDMu.Unlock()
	if b, err := os.ReadFile(path); err == nil {
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
	if os.MkdirAll(filepath.Dir(path), 0700) != nil {
		return "", errors.New("не удалось сохранить идентификатор подписок")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
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
func subscriptionDeviceID() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", errors.New("недоступна папка данных fnport")
	}
	return subscriptionDeviceIDAt(filepath.Join(dir, "fnport", "subscription-device-id"))
}
func subscriptionUA(ver, id string) string {
	ver = strings.Map(func(c rune) rune {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._-", c) {
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
func subscriptionHTTPClient() *http.Client {
	tr := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, e := net.SplitHostPort(address)
		if e != nil {
			return nil, errors.New("неверный адрес")
		}
		p, e := net.LookupPort("tcp", port)
		if e != nil {
			return nil, errors.New("неверный порт")
		}
		ip, e := netip.ParseAddr(host)
		if e != nil {
			ips := lookupAll(host)
			if len(ips) == 0 {
				return nil, errors.New("не найден адрес")
			}
			ip = ips[0]
		}
		return wnet.DialTCP(ctx, netip.AddrPortFrom(ip, uint16(p)))
	}}
	return &http.Client{Transport: tr, Timeout: 20 * time.Second}
}
func fetchSubscription(ctx context.Context, source, id, ver string, client *http.Client) (*connectionSubscription, error) {
	if !subscriptionURL(source) {
		return nil, errors.New("нужна ссылка подписки http:// или https://")
	}
	if len(id) != 32 {
		return nil, errors.New("недоступен идентификатор устройства")
	}
	if _, e := hex.DecodeString(id); e != nil {
		return nil, errors.New("недоступен идентификатор устройства")
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSpace(source), nil)
	if e != nil {
		return nil, errors.New("не удалось создать запрос подписки")
	}
	req.Header.Set("User-Agent", subscriptionUA(ver, id))
	req.Header.Set("Accept", "text/plain, application/json;q=0.9")
	req.Header.Set("x-hwid", id)
	req.Header.Set("x-device-os", subscriptionOS())
	req.Header.Set("x-device-model", "fnport for "+subscriptionOS())
	if v := subscriptionOSVersion(); v != "" {
		req.Header.Set("x-ver-os", v)
	}
	c := *client
	c.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("redirect limit")
		}
		prev := via[0].URL
		same := strings.EqualFold(next.URL.Host, prev.Host) && next.URL.Scheme == prev.Scheme
		upgrade := prev.Scheme == "http" && next.URL.Scheme == "https" && strings.EqualFold(prev.Hostname(), next.URL.Hostname()) && next.URL.Port() == ""
		if !same && !upgrade {
			return errors.New("subscription redirect origin changed")
		}
		return nil
	}
	resp, e := c.Do(req)
	if e != nil {
		return nil, errors.New("не удалось загрузить подписку: проверьте ссылку и соединение")
	}
	defer resp.Body.Close()
	for _, h := range []string{"x-hwid-max-devices-reached", "x-hwid-limit"} {
		if strings.EqualFold(resp.Header.Get(h), "true") {
			return nil, errors.New("достигнут лимит устройств подписки; освободите место в панели или у провайдера")
		}
	}
	if strings.EqualFold(resp.Header.Get("x-hwid-not-supported"), "true") {
		return nil, errors.New("панель не приняла идентификатор устройства fnport")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("подписка недоступна (HTTP %d)", resp.StatusCode)
	}
	b, e := io.ReadAll(io.LimitReader(resp.Body, subscriptionMaxBytes+1))
	if e != nil {
		return nil, errors.New("загрузка подписки прервалась")
	}
	if len(b) > subscriptionMaxBytes {
		return nil, errors.New("подписка больше 4 МБ")
	}
	if strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/html") {
		return nil, errors.New("сервер вернул веб-страницу; нужна ссылка на содержимое подписки")
	}
	nodes, skipped, e := parseSubscription(b)
	if e != nil {
		return nil, e
	}
	title := resp.Header.Get("profile-title")
	if strings.HasPrefix(title, "base64:") {
		title = decodeSubscriptionText(strings.TrimPrefix(title, "base64:"))
	}
	return &connectionSubscription{URL: strings.TrimSpace(source), Title: cleanSubscriptionName(title, "Подписка"), Nodes: nodes, Selected: nodes[0].ID, Updated: time.Now(), Skipped: skipped}, nil
}
func loadSubscription(ctx context.Context, source string) (*connectionSubscription, error) {
	id, e := subscriptionDeviceID()
	if e != nil {
		return nil, e
	}
	c := subscriptionHTTPClient()
	defer c.CloseIdleConnections()
	return fetchSubscription(ctx, source, id, version, c)
}

var subscriptionUUID = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

func cleanSubscriptionName(name, fallback string) string {
	if !utf8.ValidString(name) || strings.Contains(name, "://") || subscriptionUUID.MatchString(name) {
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
	r := []rune(name)
	if len(r) > 80 {
		name = string(r[:80]) + "…"
	}
	return name
}
func decodeSubscriptionText(text string) string {
	text = strings.Join(strings.Fields(text), "")
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, e := enc.DecodeString(text); e == nil && utf8.Valid(b) {
			return string(b)
		}
	}
	return ""
}
func parseSubscription(body []byte) ([]subscriptionNode, int, error) {
	if len(body) > subscriptionMaxBytes {
		return nil, 0, errors.New("подписка больше 4 МБ")
	}
	text := strings.TrimSpace(strings.TrimPrefix(string(body), "\ufeff"))
	if text == "" {
		return nil, 0, errors.New("подписка пуста")
	}
	if !strings.Contains(text, "://") && !strings.HasPrefix(text, "{") && !strings.HasPrefix(text, "[") {
		if decoded := decodeSubscriptionText(text); decoded != "" {
			text = strings.TrimSpace(decoded)
		}
	}
	var nodes []subscriptionNode
	skipped := 0
	seen := map[string]bool{}
	add := func(raw json.RawMessage, protocol, name string) {
		if len(nodes) >= subscriptionMaxNodes {
			skipped++
			return
		}
		allowed := false
		for _, p := range connectionUIProtocols {
			if p.id == protocol && protocol != "off" && protocol != "warp" && protocol != "amneziawg" {
				allowed = true
			}
		}
		if !allowed {
			skipped++
			return
		}
		var obj map[string]any
		if json.Unmarshal(raw, &obj) != nil {
			skipped++
			return
		}
		if obj["detour"] != nil {
			skipped++
			return
		}
		delete(obj, "name")
		canonical, e := json.Marshal(obj)
		if e != nil || (connectionSettings{Enabled: true, Protocol: protocol, Config: canonical}).validate() != nil {
			skipped++
			return
		}
		hash := sha256.Sum256(canonical)
		id := hex.EncodeToString(hash[:16])
		if seen[id] {
			return
		}
		seen[id] = true
		fallback := strings.ToUpper(protocol) + fmt.Sprintf(" · сервер %d", len(nodes)+1)
		nodes = append(nodes, subscriptionNode{ID: id, Name: cleanSubscriptionName(name, fallback), Protocol: protocol, Config: canonical})
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
				if n, ok := o["name"].(string); ok {
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
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			raw, protocol, e := importConnection(line, true)
			if e != nil {
				skipped++
				continue
			}
			name := ""
			if u, e := url.Parse(line); e == nil {
				name = u.Fragment
			}
			add(raw, protocol, name)
		}
	}
	if len(nodes) == 0 {
		return nil, skipped, errors.New("в подписке нет поддерживаемых серверов; поддерживаются ссылки VLESS и конфигурации sing-box JSON")
	}
	return nodes, skipped, nil
}
func retainSubscriptionSelection(next, old *connectionSubscription) {
	if old == nil || next == nil || next.URL != old.URL {
		return
	}
	chosen := old.node()
	if chosen == nil {
		return
	}
	for _, n := range next.Nodes {
		if n.ID == chosen.ID {
			next.Selected = n.ID
			return
		}
	}
	var match *subscriptionNode
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

func subscriptionOS() string {
	switch runtime.GOOS {
	case "windows":
		return "Windows"
	case "darwin":
		return "macOS"
	default:
		return "Linux"
	}
}
