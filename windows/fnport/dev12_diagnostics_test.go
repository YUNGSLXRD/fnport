package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/YUNGSLXRD/fnport/windows/internal/wnet"
)

func TestBeaconComparisonReport(t *testing.T) {
	for _, tc := range []struct {
		control, fake []int
		want          string
	}{
		{[]int{30, 30}, []int{1, 1}, "unclear"}, {[]int{29, 30}, []int{0, 5}, "unclear"},
		{[]int{30, 30}, []int{30, 0}, "unclear"}, {[]int{30, 30}, nil, "unclear"},
		{[]int{12, 12}, []int{0, 0}, "unclear"}, {[]int{30, 30}, []int{0, 0}, "kills"},
		{[]int{29, 30}, []int{28, 29}, "harmless"},
	} {
		fake := beaconFakeVerdict(tc.control, tc.fake)
		if fake != tc.want {
			t.Fatalf("%v / %v: %s", tc.control, tc.fake, fake)
		}
		if fake != "unclear" {
			continue
		}
		s := defaultSettings()
		r := finish(&checkResult{Settings: s, Freeze: "no", Fake: fake, FakeFile: s.Fake, FakeCity: "Франкфурт", FakeControl: tc.control, FakeCheck: &ttlReplies{s.FakeTTL, tc.fake}}, s)
		for _, output := range []string{strings.Join(r.Summary, "\n"), newController(s).report(r)} {
			if !strings.Contains(output, joinReplies(tc.control)) || !strings.Contains(output, joinReplies(tc.fake)) || strings.Contains(output, "фейк не мешает") || r.Recommend != nil {
				t.Fatal(output)
			}
		}
	}
}

// The server passes handshake probes but accepts only a few game packets.
// Exercise probe -> close -> bind -> real traffic, with and without contention
// for the same local port. No real game server or external probes are used.
func TestProbeToGameHandoff(t *testing.T) {
	for _, tc := range []struct {
		name    string
		occupy  bool
		replies int
	}{
		{"two replies on tested port", false, 2}, {"four replies on replacement port", true, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer srv.Close()
			dst := srv.LocalAddr().(*net.UDPAddr).AddrPort()
			allGamePackets := make(chan struct{})
			go func() {
				var b [2048]byte
				games := 0
				for {
					n, a, err := srv.ReadFromUDPAddrPort(b[:])
					if err != nil {
						return
					}
					if bytes.Equal(b[:n], handshake) {
						srv.WriteToUDPAddrPort(b[:n], a)
						continue
					}
					games++
					if games <= tc.replies {
						srv.WriteToUDPAddrPort(b[:n], a)
					}
					if games == 8 {
						close(allGamePackets)
					}
				}
			}()
			cfg := testConfig()
			cfg.gameRanges = [][2]uint16{{dst.Port(), dst.Port()}}
			cfg.fakes = nil
			cfg.pairOffset = 0
			dev := newChanDev()
			e := newEngine(cfg, dev, clientIP, nil)
			defer e.close()
			tested := e.prober.pick(dst, e.busy)
			if tested.port == 0 || tested.source != modeGame {
				t.Fatalf("probe candidate %+v", tested)
			}
			if tc.occupy {
				holder, err := wnet.ListenUDP(tested.port, true)
				if err != nil {
					t.Fatal(err)
				}
				defer holder.Close()
			}
			for i := 0; i < 8; i++ {
				e.udp(wnet.UDPPacket{Src: netip.AddrPortFrom(clientIP, 50000), Dst: dst, Payload: []byte{byte(i)}})
			}
			select {
			case <-allGamePackets:
			case <-time.After(3 * time.Second):
				t.Fatal("initial game packets never arrived")
			}
			for i := 0; i < tc.replies; i++ {
				select {
				case <-dev.out:
				case <-time.After(time.Second):
					t.Fatal("missing game reply")
				}
			}
			f := flowOf(e, 50000, dst)
			info := f.info(true)
			if info.NoGood != tc.occupy || (info.Port != tested.port) != tc.occupy || info.Out != 8 || info.In != int64(tc.replies) {
				t.Fatalf("probe %+v, game %+v", tested, info)
			}
		})
	}
}

func newOfflineWarpTunnel(t *testing.T) *warpTunnel {
	t.Helper()
	// Dummy keys, no endpoint: native TCP cannot receive a reply or send traffic outside.
	key := func(b byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32)) }
	w, err := newWarpDev(warpSettings{Address: "10.9.0.2", PrivateKey: key(3), PeerKey: key(5)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.close)
	return w
}

func TestWarpNativeProbeHonorsCancellation(t *testing.T) {
	w := newOfflineWarpTunnel(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	why := w.bulkFrom(ctx, "https://192.0.2.1/")
	if why == "" || ctx.Err() != context.DeadlineExceeded || time.Since(start) > time.Second {
		t.Fatalf("native download did not honor cancellation: %s, %v, %s", why, ctx.Err(), time.Since(start))
	}
}

func TestWarpFallbackDoesNotStartComparison(t *testing.T) {
	germany := newOfflineWarpTunnel(t)
	best, err := selectWarpExit(context.Background(), []string{"DE", "next"}, 30*time.Millisecond,
		func(ctx context.Context, ep string) (*warpTunnel, time.Duration, string) {
			if _, ok := ctx.Deadline(); ok {
				t.Fatal("fallback started short window")
			}
			if ep == "DE" {
				return germany, time.Millisecond, "FRA"
			}
			return nil, 0, ""
		})
	if err != nil || best != germany {
		t.Fatalf("lost fallback: %p, %v", best, err)
	}
}

func TestWarpComparisonWindow(t *testing.T) {
	for _, cancelParent := range []bool{false, true} {
		parent, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		finland := newOfflineWarpTunnel(t)
		window := 30 * time.Millisecond
		if cancelParent {
			window = time.Minute // This case must end by parent cancellation, not a timer.
		}
		best, err := selectWarpExit(parent, []string{"FI", "slow", "unused"}, window,
			func(ctx context.Context, ep string) (*warpTunnel, time.Duration, string) {
				switch ep {
				case "FI":
					if _, ok := ctx.Deadline(); ok {
						t.Fatal("fallback started short window")
					}
					return finland, 40 * time.Millisecond, "HEL"
				case "slow":
					if _, ok := ctx.Deadline(); !ok {
						t.Fatal("missing comparison deadline")
					}
					if cancelParent {
						cancel()
					}
					<-ctx.Done()
					return nil, 0, ""
				default:
					t.Fatalf("probed after window expired: %s", ep)
					return nil, 0, ""
				}
			})
		cancel()
		if cancelParent {
			if err != context.Canceled || best != nil {
				t.Fatalf("cancel: %p, %v", best, err)
			}
		} else if err != nil || best != finland {
			t.Fatalf("lost validated exit: %p, %v", best, err)
		}
	}
}

func TestSelectedWarpWaitHonorsDialDeadline(t *testing.T) {
	tcp := &tcpRelay{ctx: context.Background()}
	tcp.warpWait.Store(true)
	router := connectionRouter{settings: connectionSettings{Protocol: "warp"}, tcp: tcp}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := router.dial(ctx, netip.MustParseAddrPort("192.0.2.1:443"), false)
	stage, ok := err.(*connectionSetupError)
	if !ok || stage.stage != "warp_wait" || !stage.timeout || time.Since(start) > time.Second {
		t.Fatal(err, time.Since(start))
	}
}
