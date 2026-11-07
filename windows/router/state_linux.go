//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

const privateConfigDir = "/etc/fnport/connections"
const warpProfilePath = privateConfigDir + "/warp.json"
const runtimeDir = "/var/run/fnport-connections"
const corePath = "/usr/lib/fnport-connections/sing-box"
const dataDir = "/usr/share/fnport"

type connectionStatus struct {
	State    string `json:"state"`
	Protocol string `json:"protocol,omitempty"`
	Error    string `json:"error,omitempty"`
	Colo     string `json:"colo,omitempty"`
	Country  string `json:"country,omitempty"`
	Address  string `json:"address,omitempty"`
	RTTMS    int64  `json:"rtt_ms,omitempty"`
	Updated  int64  `json:"updated"`
}

func saveStatus(dir string, s connectionStatus) {
	s.Updated = time.Now().Unix()
	b, _ := json.Marshal(s)
	writePrivate(dir+"/status.json", b)
}
func readPrivate(path string, limit int64) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("private_file_unavailable")
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return nil, errors.New("private_file_permissions")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, errors.New("private_file_too_large")
	}
	return b, nil
}
func loadConfig(path string) (routerConfig, error) {
	var c routerConfig
	raw, err := readPrivate(path, 2<<20)
	if err != nil {
		return c, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || d.Decode(new(any)) != io.EOF {
		return c, errors.New("invalid_configuration")
	}
	if err := c.validate(); err != nil {
		return c, err
	}
	switch c.Protocol {
	case "warp":
		if c.Profile != "" {
			raw := []byte(c.Profile)
			if looksLikeAWGConf(c.Profile) {
				raw, err = importAWGConf(c.Profile)
				if err != nil {
					return c, errors.New("invalid_native_profile")
				}
			}
			c.Native, err = parseNativeAWG(raw)
		} else {
			c.Native, err = loadWarpProfile(warpProfilePath)
		}
	case "amneziawg", "wireguard":
		raw := []byte(c.Profile)
		if looksLikeAWGConf(c.Profile) {
			raw, err = importAWGConf(c.Profile)
			if err != nil {
				return c, errors.New("invalid_native_profile")
			}
		}
		c.Native, err = parseNativeAWG(raw)
	}
	if err != nil {
		return c, err
	}
	return c, nil
}
