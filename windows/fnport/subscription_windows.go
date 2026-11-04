//go:build windows

package main

import (
	"fmt"
	"golang.org/x/sys/windows"
)

func subscriptionOSVersion() string {
	v := windows.RtlGetVersion()
	return fmt.Sprintf("%d.%d.%d", v.MajorVersion, v.MinorVersion, v.BuildNumber)
}
