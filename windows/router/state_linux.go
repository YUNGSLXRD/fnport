//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"github.com/YUNGSLXRD/fnport/windows/internal/vpn"
	"golang.org/x/sys/unix"
)

const (
	privateConfigDir       = "/etc/fnport/connections"
	warpProfilePath        = privateConfigDir + "/warp.json"
	subscriptionPath       = privateConfigDir + "/subscription.json"
	subscriptionPublicPath = privateConfigDir + "/subscription-public.json"
	deviceIDPath           = privateConfigDir + "/device.id"
	runtimeDir             = "/var/run/fnport-connections"
	corePath               = "/usr/lib/fnport-connections/sing-box"
	dataDir                = "/usr/share/fnport"
)

type connectionStatus struct {
	State    string `json:"state"`
	Protocol string `json:"protocol,omitempty"`
	NodeName string `json:"node_name,omitempty"`
	Error    string `json:"error,omitempty"`
	Colo     string `json:"colo,omitempty"`
	Country  string `json:"country,omitempty"`
	Address  string `json:"address,omitempty"`
	RTTMS    int64  `json:"rtt_ms,omitempty"`
	Updated  int64  `json:"updated"`
}

type publicNodeSummary struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Country  string `json:"country,omitempty"`
	Protocol string `json:"protocol"`
	Badge    string `json:"badge"`
}

type publicSubscriptionSummary struct {
	Present  bool                `json:"present"`
	Title    string              `json:"title,omitempty"`
	Selected string              `json:"selected,omitempty"`
	Updated  int64               `json:"updated,omitempty"`
	Skipped  int                 `json:"skipped,omitempty"`
	Nodes    []publicNodeSummary `json:"nodes,omitempty"`
}

func saveStatus(dir string, s connectionStatus) {
	s.Updated = time.Now().Unix()
	b, _ := json.Marshal(s)
	_ = writePrivate(dir+"/status.json", b)
}

func readPrivate(filePath string, limit int64) ([]byte, error) {
	fd, err := unix.Open(filePath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("private_file_unavailable")
	}
	f := os.NewFile(uintptr(fd), filePath)
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("private_file_permissions")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, errors.New("private_file_too_large")
	}
	return b, nil
}

func loadStoredSubscription() (*vpn.Subscription, error) {
	raw, err := readPrivate(subscriptionPath, 8<<20)
	if err != nil {
		return nil, err
	}
	var sub vpn.Subscription
	if json.Unmarshal(raw, &sub) != nil || len(sub.Nodes) == 0 {
		return nil, errors.New("subscription_invalid")
	}
	return &sub, nil
}

func saveStoredSubscription(sub *vpn.Subscription) error {
	raw, err := json.Marshal(sub)
	if err != nil {
		return errors.New("subscription_save_failed")
	}
	if err := writePrivate(subscriptionPath, raw); err != nil {
		return err
	}
	pub, err := json.Marshal(summarizeSubscription(sub))
	if err == nil {
		_ = writePrivate(subscriptionPublicPath, pub)
	}
	return nil
}

func summarizeSubscription(sub *vpn.Subscription) publicSubscriptionSummary {
	if sub == nil || len(sub.Nodes) == 0 {
		return publicSubscriptionSummary{Present: false}
	}
	nodes := make([]publicNodeSummary, 0, len(sub.Nodes))
	for _, n := range sub.Nodes {
		clean, cc := vpn.DisplayNodeName(n.Name)
		nodes = append(nodes, publicNodeSummary{
			ID:       n.ID,
			Name:     clean,
			Country:  cc,
			Protocol: n.Protocol,
			Badge:    vpn.ProtocolShortBadge(n.Protocol),
		})
	}
	return publicSubscriptionSummary{
		Present:  true,
		Title:    sub.Title,
		Selected: sub.Selected,
		Updated:  sub.Updated.Unix(),
		Skipped:  sub.Skipped,
		Nodes:    nodes,
	}
}

func fetchRouterSubscription(ctx context.Context, wan, rawURL string) (publicSubscriptionSummary, error) {
	if !validIface.MatchString(wan) {
		return publicSubscriptionSummary{}, errors.New("invalid_wan_interface")
	}
	urlStr := strings.TrimSpace(rawURL)
	if !vpn.IsSubscriptionURL(urlStr) {
		return publicSubscriptionSummary{}, errors.New("invalid_subscription_url")
	}
	if err := privateDir(privateConfigDir); err != nil {
		return publicSubscriptionSummary{}, err
	}
	devID, err := vpn.DeviceIDAt(deviceIDPath)
	if err != nil {
		return publicSubscriptionSummary{}, errors.New("subscription_device_id_failed")
	}
	client := wanHTTPClient(wan, 20*time.Second)
	sub, err := vpn.FetchSubscription(ctx, urlStr, devID, version, "OpenWrt", "", client)
	if err != nil {
		return publicSubscriptionSummary{}, errors.New("subscription_fetch_failed")
	}
	if old, lerr := loadStoredSubscription(); lerr == nil {
		vpn.RetainSelection(sub, old)
	}
	if err := saveStoredSubscription(sub); err != nil {
		return publicSubscriptionSummary{}, err
	}
	return summarizeSubscription(sub), nil
}

func selectRouterSubscription(nodeID string) (publicSubscriptionSummary, error) {
	nodeID = strings.TrimSpace(nodeID)
	sub, err := loadStoredSubscription()
	if err != nil {
		return publicSubscriptionSummary{}, errors.New("subscription_missing")
	}
	found := false
	for _, n := range sub.Nodes {
		if n.ID == nodeID {
			found = true
			break
		}
	}
	if !found {
		return publicSubscriptionSummary{}, errors.New("subscription_node_not_found")
	}
	sub.Selected = nodeID
	if err := saveStoredSubscription(sub); err != nil {
		return publicSubscriptionSummary{}, err
	}
	return summarizeSubscription(sub), nil
}

func loadConfig(ctx context.Context, filePath string) (routerConfig, string, error) {
	var c routerConfig
	raw, err := readPrivate(filePath, 2<<20)
	if err != nil {
		return c, "", err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if d.Decode(&c) != nil || d.Decode(new(any)) != io.EOF {
		return c, "", errors.New("invalid_configuration")
	}
	if err := c.validate(); err != nil {
		return c, "", err
	}

	nodeName := ""
	switch c.Protocol {
	case "warp":
		if strings.TrimSpace(c.Profile) != "" {
			c.Native, err = vpn.ParseWARPConf(c.Profile, 4, 40, 70)
		} else {
			c.Native, err = loadWarpProfile(warpProfilePath)
		}
	case "amneziawg", "wireguard":
		c.Native, _, err = vpn.ImportAWG(c.Profile)
	default:
		if vpn.IsSubscriptionURL(c.Profile) {
			sub, lerr := loadStoredSubscription()
			if lerr != nil || sub.URL != strings.TrimSpace(c.Profile) {
				fctx, cancel := context.WithTimeout(ctx, 25*time.Second)
				_, ferr := fetchRouterSubscription(fctx, c.WAN, c.Profile)
				cancel()
				if ferr != nil {
					return c, "", ferr
				}
				sub, lerr = loadStoredSubscription()
			}
			if lerr != nil || sub == nil || len(sub.Nodes) == 0 {
				return c, "", errors.New("subscription_missing")
			}
			if c.Node != "" {
				for _, n := range sub.Nodes {
					if n.ID == c.Node {
						if sub.Selected != n.ID {
							sub.Selected = n.ID
							_ = saveStoredSubscription(sub)
						}
						break
					}
				}
			}
			active := sub.ActiveNode()
			if active == nil {
				active = &sub.Nodes[0]
			}
			clean, _ := vpn.DisplayNodeName(active.Name)
			nodeName = clean
			c.Protocol = active.Protocol
			c.Profile = string(active.Config)
		} else if c.Protocol == "vpn" {
			if looksLikeAWGConf(c.Profile) {
				c.Protocol = "amneziawg"
				c.Native, _, err = vpn.ImportAWG(c.Profile)
			} else {
				var imported json.RawMessage
				var proto, title string
				imported, proto, title, err = vpn.ImportProfile(c.Profile, true)
				if err == nil {
					c.Protocol = proto
					if proto == "amneziawg" {
						c.Native, err = parseNativeAWG(imported)
					} else {
						c.Profile = string(imported)
						if title != "" {
							clean, _ := vpn.DisplayNodeName(vpn.CleanSubscriptionName(title, ""))
							nodeName = clean
						}
					}
				}
			}
		}
	}
	if err != nil {
		return c, "", err
	}
	return c, nodeName, nil
}
