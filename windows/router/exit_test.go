package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRouterExitSelectionPreservesValidatedCandidate(t *testing.T) {
	ctx := t.Context()
	calls := 0
	endpoint, report, err := chooseExit(ctx, []string{"ru", "de", "fi", "stalled"}, 20*time.Millisecond, func(ctx context.Context, endpoint string) (exitReport, error) {
		calls++
		switch endpoint {
		case "ru":
			return exitReport{Colo: "DME", Bytes: 1 << 20, RTT: time.Millisecond}, nil
		case "de":
			return exitReport{Colo: "FRA", Bytes: 1 << 20, RTT: time.Millisecond}, nil
		case "fi":
			return exitReport{Colo: "HEL", Bytes: 1 << 20, RTT: 40 * time.Millisecond}, nil
		default:
			<-ctx.Done()
			return exitReport{}, ctx.Err()
		}
	})
	if err != nil || endpoint != "fi" || report.Country != "FI" || calls != 4 {
		t.Fatal("validated preferred exit lost", endpoint, err)
	}
	endpoint, _, err = chooseExit(ctx, []string{"partial"}, time.Second, func(context.Context, string) (exitReport, error) {
		return exitReport{Colo: "HEL", Bytes: 9000, RTT: time.Millisecond}, nil
	})
	if err == nil || endpoint != "" {
		t.Fatal("partial download accepted")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	_, _, err = chooseExit(canceled, []string{"fi"}, time.Second, func(context.Context, string) (exitReport, error) {
		t.Fatal("probe after cancellation")
		return exitReport{}, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost")
	}
}
