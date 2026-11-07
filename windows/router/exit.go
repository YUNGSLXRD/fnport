package main

import (
	"context"
	"errors"
	"time"
)

type exitReport struct {
	Colo    string
	Country string
	Address string
	RTT     time.Duration
	Bytes   int64
}

var preferredColos = map[string]string{"HEL": "FI", "TKU": "FI", "TMP": "FI", "ARN": "SE", "GOT": "SE", "WAW": "PL", "KRK": "PL", "GDN": "PL", "WRO": "PL", "POZ": "PL", "RIX": "LV", "TLL": "EE", "TAY": "EE", "FRA": "DE", "MUC": "DE", "BER": "DE", "TXL": "DE", "HAM": "DE", "DUS": "DE", "STR": "DE"}

func exitTier(colo string) int {
	switch preferredColos[colo] {
	case "FI", "SE", "PL", "LV", "EE":
		return 0
	case "DE":
		return 1
	default:
		return -1
	}
}
func chooseExit(ctx context.Context, endpoints []string, window time.Duration, probe func(context.Context, string) (exitReport, error)) (string, exitReport, error) {
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
		report.Country = preferredColos[report.Colo]
		if exitTier(report.Colo) == 0 {
			preferred++
			if preferred == 1 {
				bounded, cancel := context.WithTimeout(ctx, window)
				defer cancel()
				attemptCtx = bounded
			}
		}
		if chosen == "" || exitTier(report.Colo) < exitTier(best.Colo) || exitTier(report.Colo) == exitTier(best.Colo) && report.RTT < best.RTT {
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
