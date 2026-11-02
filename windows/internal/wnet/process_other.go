//go:build !windows

package wnet

import "strings"

func processNameKey(s string) string              { return strings.ToLower(s) }
func readProcessRows(uint8) ([]processRow, error) { return nil, ErrProcessUnsupported }
func processExecutable(uint32) (string, error)    { return "", ErrProcessUnsupported }
func processSnapshot() (map[uint32]string, error) { return nil, ErrProcessUnsupported }
