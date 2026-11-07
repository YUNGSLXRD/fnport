//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var version = "dev"

func main() {
	unix.Umask(0077)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err := runCommand(ctx, os.Args[1:])
	if err != nil {
		b, _ := json.Marshal(map[string]string{"error": err.Error()})
		fmt.Println(string(b))
		os.Exit(1)
	}
}
func runCommand(ctx context.Context, args []string) error {
	if len(args) == 1 && args[0] == "version" {
		fmt.Println(version)
		return nil
	}
	if os.Geteuid() != 0 {
		return errors.New("root_required")
	}
	if len(args) == 2 && args[0] == "register-warp" {
		registration, cancel := context.WithTimeout(ctx, 90*time.Second)
		defer cancel()
		if err := registerRouterWarp(registration, args[1], warpProfilePath); err != nil {
			return err
		}
		fmt.Println(`{"registered":true}`)
		return nil
	}
	if len(args) != 2 || args[0] != "run" {
		return errors.New("invalid_command")
	}
	if privateDir(runtimeDir) != nil {
		return errors.New("runtime_directory_unavailable")
	}
	lock, err := os.OpenFile(runtimeDir+"/instance.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return errors.New("instance_lock_failed")
	}
	defer lock.Close()
	if unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		return errors.New("already_running")
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	if err := recoverOwnedFirewall(ctx); err != nil {
		return err
	}
	if err := writePrivate(runtimeDir+"/daemon.pid", []byte(strconv.Itoa(os.Getpid()))); err != nil {
		return err
	}
	defer os.Remove(runtimeDir + "/daemon.pid")
	c, err := loadConfig(args[1])
	if err != nil {
		saveStatus(runtimeDir, connectionStatus{State: "failed", Error: err.Error()})
		return err
	}
	return runRouter(ctx, c, routerPaths{corePath, runtimeDir, dataDir})
}
