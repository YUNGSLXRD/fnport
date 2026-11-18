package main

import (
	"encoding/json"

	"github.com/YUNGSLXRD/fnport/windows/internal/vpn"
)

func importConnection(text string, required bool) (json.RawMessage, string, error) {
	raw, proto, _, err := vpn.ImportProfile(text, required)
	return raw, proto, err
}
