//go:build windows

package wnet

import (
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var processIPHelper = windows.NewLazySystemDLL("iphlpapi.dll")
var processTCPTable = processIPHelper.NewProc("GetExtendedTcpTable")
var processUDPTable = processIPHelper.NewProc("GetExtendedUdpTable")

func processNameKey(s string) string { return strings.ToLower(s) }

func readProcessRows(proto uint8) ([]processRow, error) {
	var rows []processRow
	var errs []error
	for _, family := range []uint32{windows.AF_INET, windows.AF_INET6} {
		b, err := nativeProcessTable(proto, family)
		if err == nil {
			var parsed []processRow
			parsed, err = parseProcessTable(b, proto, family == windows.AF_INET6)
			rows = append(rows, parsed...)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("process table protocol %d family %d: %w", proto, family, err))
		}
	}
	return rows, errors.Join(errs...)
}

func nativeProcessTable(proto uint8, family uint32) ([]byte, error) {
	proc, class := processTCPTable, uintptr(5) // TCP_TABLE_OWNER_PID_ALL
	if proto == 17 {
		proc, class = processUDPTable, 1
	} // UDP_TABLE_OWNER_PID
	if err := proc.Find(); err != nil {
		return nil, err
	}
	size := uint32(16 * 1024)
	for attempt := 0; attempt < 5; attempt++ {
		if size < 4 || size > 64*1024*1024 {
			return nil, errors.New("invalid native process table size")
		}
		b := make([]byte, size)
		allocated := size
		code, _, _ := proc.Call(uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(&size)), 0, uintptr(family), class, 0)
		runtime.KeepAlive(b)
		if code == uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
			continue
		}
		if code != 0 {
			return nil, windows.Errno(code)
		}
		if size > allocated {
			return nil, errors.New("native process table exceeded buffer")
		}
		return b[:size], nil
	}
	return nil, errors.New("process table kept growing during enumeration")
}

func processExecutable(pid uint32) (string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)
	b := make([]uint16, 32768)
	n := uint32(len(b))
	if err := windows.QueryFullProcessImageName(h, 0, &b[0], &n); err != nil {
		return "", err
	}
	name := filepath.Base(windows.UTF16ToString(b[:n]))
	if name == "" || name == "." {
		return "", errors.New("empty process executable")
	}
	return name, nil
}

func processSnapshot() (map[uint32]string, error) {
	h, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(h)
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	err = windows.Process32First(h, &entry)
	out := make(map[uint32]string)
	for err == nil {
		out[entry.ProcessID] = windows.UTF16ToString(entry.ExeFile[:])
		err = windows.Process32Next(h, &entry)
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return nil, err
	}
	return out, nil
}
