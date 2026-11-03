package main

type networkTraceSettings struct {
	Enabled   bool     `json:"enabled"`
	Processes []string `json:"processes,omitempty"`
}

type networkUDPStats struct {
	QueueMaxMS   float64 `json:"queue_max_ms"`
	WriteMaxMS   float64 `json:"write_max_ms"`
	Queued       int     `json:"queued"`
	QueueDropped uint64  `json:"queue_dropped"`
	Out          int64   `json:"sent"`
	In           int64   `json:"received"`
}

type networkTCPStats struct {
	Route           string  `json:"route"`
	Received        int64   `json:"received_bytes"`
	Sent            int64   `json:"sent_bytes"`
	FirstResponseMS float64 `json:"first_response_ms_after_accept"`
	ElapsedMS       float64 `json:"elapsed_ms"`
	Finished        bool    `json:"finished"`
}
