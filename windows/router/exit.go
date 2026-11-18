package main

import (
	"context"
	"errors"
	"time"

	"github.com/YUNGSLXRD/fnport/windows/internal/vpn"
)

type exitReport struct {
	Colo    string
	Country string
	Address string
	RTT     time.Duration
	Bytes   int64
}

func exitTier(colo string) int {
	return vpn.WarpExitTier(colo)
}

func chooseExit(
	ctx context.Context,
	endpoints []string,
	window time.Duration,
	probe func(context.Context, string) (exitReport, error),
) (string, exitReport, error) {
	var best exitReport
	chosen := ""
	attemptCtx := ctx
	preferred := 0
	for i, endpoint := range endpoints {
		if i >= 16 || preferred >= 3 || attemptCtx.Err() != nil {
			break
		}
		report, err := probe(attemptCtx, endpoint)
		if err != nil || attemptCtx.Err() != nil || report.Bytes < 1<<20 || report.RTT <= 0 || exitTier(report.Colo) < 0 {
			continue
		}
		if c := vpn.ColoCountry[report.Colo]; c != "" {
			report.Country = c
		}
		if exitTier(report.Colo) == 0 {
			preferred++
			if preferred == 1 {
				bounded, cancel := context.WithTimeout(ctx, window)
				defer cancel()
				attemptCtx = bounded
			}
		}
		if chosen == "" || vpn.BetterWarpExit(report.Colo, report.RTT, best.Colo, best.RTT) {
			chosen, best = endpoint, report
		}
	}
	if ctx.Err() != nil {
		return "", exitReport{}, ctx.Err()
	}
	if chosen == "" {
		return "", exitReport{}, errors.New("warp_no_usable_endpoint")
	}
	return chosen, best, nil
}
