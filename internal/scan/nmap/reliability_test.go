package nmap

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestCancelKillsNmapProcessGroup(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child")
	r, _ := fakeNmap(t, "sleep 300 &\necho $! > '"+pidFile+"'\nwait")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := r.Discover(ctx, []string{"192.0.2.10"}, Options{ProbePorts: []int{80}})
		done <- err
	}()
	var pid int
	deadline := time.Now().Add(5 * time.Second)
	for pid == 0 {
		if raw, err := os.ReadFile(pidFile); err == nil && strings.HasSuffix(string(raw), "\n") {
			pid, _ = strconv.Atoi(strings.TrimSpace(string(raw)))
		}
		if time.Now().After(deadline) {
			t.Fatal("fake nmap did not start its child")
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Discover after cancel = %v, want context.Canceled", err)
	}
	gone := time.Now().Add(2 * time.Second)
	for syscall.Kill(pid, 0) == nil && time.Now().Before(gone) {
		time.Sleep(10 * time.Millisecond)
	}
	if err := syscall.Kill(pid, 0); err == nil {
		t.Fatalf("child process %d of nmap still running after context cancel, want the whole process group killed", pid)
	}
}
