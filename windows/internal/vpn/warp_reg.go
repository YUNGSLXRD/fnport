package vpn

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

const (
	warpAPIHost    = "api.cloudflareclient.com"
	warpAPIVersion = "v0a5641"
)

// WarpAPIAddrs are Cloudflare registration API addresses that answer from Russia
// when domestic resolvers return unreachable anycast ranges.
var WarpAPIAddrs = []netip.Addr{
	netip.MustParseAddr("104.16.24.84"),
	netip.MustParseAddr("104.16.192.82"),
}

type warpRegResponse struct {
	ID     string `json:"id"`
	Token  string `json:"token"`
	Config *struct {
		Peers []struct {
			PublicKey string `json:"public_key"`
		} `json:"peers"`
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
			} `json:"addresses"`
		} `json:"interface"`
	} `json:"config"`
}

// warpHello matches the 1.1.1.1 Android client's TLS ClientHello (from ViRb3/wgcf, MIT).
func warpHello() *utls.ClientHelloSpec {
	return &utls.ClientHelloSpec{
		TLSVersMin:         utls.VersionTLS12,
		TLSVersMax:         utls.VersionTLS12,
		CipherSuites:       []uint16{utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},
		CompressionMethods: []uint8{0},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{},
			&utls.ExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateNever},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{utls.X25519, utls.CurveP256, utls.CurveP384}},
			&utls.SupportedPointsExtension{SupportedPoints: []uint8{0}},
			&utls.SessionTicketExtension{},
			&utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}},
			&utls.StatusRequestExtension{},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256, utls.PSSWithSHA256, utls.PKCS1WithSHA256,
				utls.ECDSAWithP384AndSHA384, utls.PSSWithSHA384, utls.PKCS1WithSHA384,
				utls.PSSWithSHA512, utls.PKCS1WithSHA512, utls.PKCS1WithSHA1,
			}},
			&utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle},
		},
	}
}

// splitConn splits the initial TLS ClientHello write across TCP segments (and optionally
// across two TLS handshake records) in the middle of the SNI hostname.
type splitConn struct {
	net.Conn
	mark    []byte
	records bool
	done    bool
}

func (c *splitConn) Write(b []byte) (int, error) {
	if c.done {
		return c.Conn.Write(b)
	}
	c.done = true
	cut := bytes.Index(b, c.mark)
	if cut < 0 {
		cut = len(b) / 2
	} else {
		cut += len(c.mark) / 2
	}
	parts := [][]byte{b[:1], b[1:cut], b[cut:]}
	if c.records && len(b) > 5 && b[0] == 22 && cut > 5 && cut < len(b) {
		rec := func(body []byte) []byte {
			return append([]byte{b[0], b[1], b[2], byte(len(body) >> 8), byte(len(body))}, body...)
		}
		first, second := rec(b[5:cut]), rec(b[cut:])
		parts = [][]byte{first[:1], first[1:], second}
	}
	for _, part := range parts {
		if len(part) == 0 {
			continue
		}
		if _, err := c.Conn.Write(part); err != nil {
			return 0, err
		}
		time.Sleep(15 * time.Millisecond)
	}
	return len(b), nil
}

// RegisterWARP generates a local X25519 keypair and registers the public key with Cloudflare.
// dialTCP connects out of the physical WAN interface; extraIPs provides resolved fallback API IPs.
func RegisterWARP(
	ctx context.Context,
	dialTCP func(context.Context, netip.AddrPort) (net.Conn, error),
	extraIPs []netip.Addr,
) (AWGConfig, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return AWGConfig{}, err
	}
	ips := append(append([]netip.Addr(nil), WarpAPIAddrs...), extraIPs...)
	call := func(method, endpointPath, token string, body []byte) ([]byte, error) {
		tc, err := connectWARPAPI(ctx, dialTCP, ips)
		if err != nil {
			return nil, err
		}
		defer tc.Close()
		stop := context.AfterFunc(ctx, func() { _ = tc.Close() })
		defer stop()

		req, _ := http.NewRequest(method, "https://"+warpAPIHost+"/"+warpAPIVersion+endpointPath, bytes.NewReader(body))
		req.Header.Set("User-Agent", "1.1.1.1/6.38.9-5641 (Android 16.0.0)")
		req.Header.Set("CF-Client-Version", "a-6.38.9-5641")
		req.Header.Set("Content-Type", "application/json; charset=UTF-8")
		req.Header.Set("Connection", "close")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if err := req.Write(tc); err != nil {
			return nil, err
		}
		resp, err := http.ReadResponse(bufio.NewReader(tc), req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			return nil, err
		}
		if resp.StatusCode/100 != 2 {
			return nil, fmt.Errorf("Cloudflare ответил %s", resp.Status)
		}
		return b, nil
	}

	body, _ := json.Marshal(map[string]any{
		"fcm_token":     "",
		"install_id":    "",
		"key":           base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()),
		"locale":        "en_US",
		"model":         "PC",
		"tos":           time.Now().Format(time.RFC3339Nano),
		"serial_number": "",
		"os_version":    "16.0.0",
		"key_type":      "curve25519",
		"tunnel_type":   "wireguard",
	})
	reply, err := call("POST", "/reg", "", body)
	if err != nil {
		return AWGConfig{}, err
	}
	var reg warpRegResponse
	if err := json.Unmarshal(reply, &reg); err != nil {
		return AWGConfig{}, fmt.Errorf("непонятный ответ Cloudflare: %w", err)
	}
	if reg.Config == nil && reg.ID != "" && !strings.ContainsAny(reg.ID, "/?#\\\r\n") {
		if b, err := call("GET", "/reg/"+reg.ID, reg.Token, nil); err == nil {
			_ = json.Unmarshal(b, &reg)
		}
	}
	if reg.Config == nil || len(reg.Config.Peers) == 0 || reg.Config.Interface.Addresses.V4 == "" {
		return AWGConfig{}, errors.New("Cloudflare не прислал настройки туннеля")
	}
	cfg := AWGConfig{
		MTU:        1280,
		PrivateKey: base64.StdEncoding.EncodeToString(priv.Bytes()),
		PeerKey:    reg.Config.Peers[0].PublicKey,
		Address:    reg.Config.Interface.Addresses.V4,
		Jc:         4,
		Jmin:       40,
		Jmax:       70,
		H1:         "1",
		H2:         "2",
		H3:         "3",
		H4:         "4",
	}
	return cfg, nil
}

func connectWARPAPI(
	ctx context.Context,
	dialTCP func(context.Context, netip.AddrPort) (net.Conn, error),
	ips []netip.Addr,
) (*utls.UConn, error) {
	var lastErr error
	var handshakeFailed bool
	for _, records := range []bool{false, true} {
		tried := make(map[netip.Addr]bool)
		for _, ip := range ips {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if tried[ip] {
				continue
			}
			tried[ip] = true
			attemptCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
			raw, err := dialTCP(attemptCtx, netip.AddrPortFrom(ip, 443))
			if err != nil {
				cancel()
				lastErr = fmt.Errorf("не соединяется с Cloudflare: %w", err)
				continue
			}
			_ = raw.SetDeadline(time.Now().Add(6 * time.Second))
			sc := &splitConn{Conn: raw, mark: []byte(warpAPIHost), records: records}
			tc := utls.UClient(sc, &utls.Config{ServerName: warpAPIHost, NextProtos: []string{"http/1.1"}}, utls.HelloCustom)
			err = tc.ApplyPreset(warpHello())
			if err == nil {
				err = tc.HandshakeContext(attemptCtx)
			}
			cancel()
			if err == nil {
				_ = raw.SetDeadline(time.Now().Add(20 * time.Second))
				return tc, nil
			}
			_ = raw.Close()
			handshakeFailed = true
			lastErr = err
		}
	}
	if handshakeFailed {
		return nil, fmt.Errorf("HTTPS к Cloudflare не прошёл (%v): похоже, провайдер блокирует регистрацию WARP. "+
			"Получите ключ в другой сети (дома, с телефона) или импортируйте готовый файл .conf", lastErr)
	}
	if lastErr == nil {
		lastErr = errors.New("не найден адрес " + warpAPIHost)
	}
	return nil, lastErr
}
