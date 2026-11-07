//go:build linux

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type coreProcess struct {
	cmd  *exec.Cmd
	done chan struct{}
	once sync.Once
}

func privateDir(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return errors.New("private_directory_unavailable")
	}
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return errors.New("private_directory_permissions")
	}
	return nil
}
func writePrivate(path string, data []byte) error {
	if privateDir(filepath.Dir(path)) != nil {
		return errors.New("private_directory_permissions")
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".fnport-")
	if err != nil {
		return errors.New("private_file_unavailable")
	}
	name := f.Name()
	defer os.Remove(name)
	if f.Chmod(0600) != nil {
		f.Close()
		return errors.New("private_file_permissions")
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil || os.Rename(name, path) != nil {
		return errors.New("private_file_write_failed")
	}
	return nil
}
func startCore(ctx context.Context, path, dir string, config []byte) (*coreProcess, error) {
	st, err := os.Stat(path)
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0022 != 0 {
		return nil, errors.New("core_not_installed")
	}
	versionCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	out, err := exec.CommandContext(versionCtx, path, "version").Output()
	cancel()
	if err != nil || !strings.Contains(string(out), "sing-box version "+coreVersion+"\n") {
		return nil, errors.New("core_version_mismatch")
	}
	configPath := filepath.Join(dir, "core.json")
	if err := writePrivate(configPath, config); err != nil {
		return nil, err
	}
	checkCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	err = exec.CommandContext(checkCtx, path, "check", "-c", configPath).Run()
	cancel()
	if err != nil {
		return nil, errors.New("core_profile_rejected")
	}
	p := &coreProcess{done: make(chan struct{})}
	p.cmd = exec.Command(path, "run", "-c", configPath, "-D", dir)
	p.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if p.cmd.Start() != nil {
		return nil, errors.New("core_start_failed")
	}
	go func() { p.cmd.Wait(); close(p.done) }()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(30 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			p.close()
			return nil, ctx.Err()
		case <-p.done:
			return nil, errors.New("core_exited")
		case <-deadline.C:
			p.close()
			return nil, errors.New("core_not_ready")
		case <-tick.C:
			c, err := net.DialTimeout("tcp4", "127.0.0.1:10898", 100*time.Millisecond)
			if err == nil {
				c.Close()
				return p, nil
			}
		}
	}
}
func (p *coreProcess) close() {
	p.once.Do(func() {
		if p.cmd.Process == nil {
			return
		}
		select {
		case <-p.done:
			return
		default:
		}
		unix.Kill(-p.cmd.Process.Pid, unix.SIGTERM)
		select {
		case <-p.done:
		case <-time.After(2 * time.Second):
			unix.Kill(-p.cmd.Process.Pid, unix.SIGKILL)
			<-p.done
		}
	})
}
