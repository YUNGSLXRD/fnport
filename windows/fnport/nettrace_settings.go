package main

type networkTraceSettings struct {
	Enabled   bool     `json:"enabled"`
	Processes []string `json:"processes,omitempty"`
}
