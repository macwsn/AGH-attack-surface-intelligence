package nmap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type ExecRunner struct {
	Path string
}

func (r ExecRunner) Discover(ctx context.Context, addrs []string, opts Options) ([]Host, error) {
	args, err := DiscoverArgs(addrs, opts)
	if err != nil {
		return nil, err
	}
	return r.run(ctx, args)
}

func (r ExecRunner) Services(ctx context.Context, addrs []string, ports []int, opts Options) ([]Host, error) {
	args, err := ServicesArgs(addrs, ports, opts)
	if err != nil {
		return nil, err
	}
	return r.run(ctx, args)
}

func (r ExecRunner) run(ctx context.Context, args []string) ([]Host, error) {
	path := r.Path
	if path == "" {
		path = "nmap"
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, fmt.Errorf("nmap: %w", ctxErr)
	}
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, fmt.Errorf("nmap exited with %d: %s: %w", exitErr.ExitCode(), lastLine(stderr.String()), err)
		}
		return nil, fmt.Errorf("run nmap: %w", err)
	}
	hosts, err := Parse(&stdout)
	if err != nil {
		return nil, fmt.Errorf("nmap output: %w", err)
	}
	return hosts, nil
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}
