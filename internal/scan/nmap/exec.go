package nmap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"syscall"
	"time"
)

var ErrNoTargetsScanned = errors.New("nmap scanned none of the targets")

type ExecRunner struct {
	Path string
}

func (r ExecRunner) Discover(ctx context.Context, addrs []string, opts Options) ([]Host, error) {
	args, err := DiscoverArgs(addrs, opts)
	if err != nil {
		return nil, err
	}
	return r.run(ctx, args, len(addrs))
}

func (r ExecRunner) Services(ctx context.Context, addrs []string, ports []int, opts Options) ([]Host, error) {
	var probed, policy []int
	for _, p := range ports {
		if slices.Contains(opts.NoVersion, p) {
			policy = append(policy, p)
		} else {
			probed = append(probed, p)
		}
	}
	var hosts []Host
	if len(probed) > 0 {
		light := !opts.Standard && !opts.StockProbes
		if light && opts.VersionDB == "" {
			if db, cleanup, err := r.LightProbes(); err == nil {
				defer cleanup()
				opts.VersionDB = db
			}
		}
		args, err := ServicesArgs(addrs, probed, opts)
		if err != nil {
			return nil, err
		}
		if hosts, err = r.run(ctx, args, len(addrs)); err != nil {
			return nil, err
		}
		if light && opts.VersionDB != "" {
			r.markSoft(hosts)
		}
	}
	if len(policy) == 0 {
		return hosts, nil
	}
	args, err := PortsArgs(addrs, policy, opts)
	if err != nil {
		return nil, err
	}
	open, err := r.run(ctx, args, len(addrs))
	if err != nil {
		return nil, err
	}
	return mergeHosts(hosts, open), nil
}

func mergeHosts(a, b []Host) []Host {
	for _, h := range b {
		i := slices.IndexFunc(a, func(x Host) bool { return x.Address == h.Address })
		if i < 0 {
			a = append(a, h)
			continue
		}
		a[i].Up = a[i].Up || h.Up
		a[i].Ports = append(a[i].Ports, h.Ports...)
		for _, n := range h.Hostnames {
			if !slices.Contains(a[i].Hostnames, n) {
				a[i].Hostnames = append(a[i].Hostnames, n)
			}
		}
	}
	return a
}

func (r ExecRunner) run(ctx context.Context, args []string, targets int) ([]Host, error) {
	path := r.Path
	if path == "" {
		path = "nmap"
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
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
	hosts, total, err := parse(&stdout)
	if err != nil {
		return nil, fmt.Errorf("nmap output: %w", err)
	}
	if total == "0" && targets > 0 {
		return nil, fmt.Errorf("%w (0 of %d): %s", ErrNoTargetsScanned, targets, skipReason(stderr.String()))
	}
	return hosts, nil
}

func skipReason(stderr string) string {
	for _, line := range strings.Split(stderr, "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "WARNING: No targets were specified") {
			return line
		}
	}
	return "no reason given"
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}
