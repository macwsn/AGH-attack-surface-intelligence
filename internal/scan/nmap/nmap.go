package nmap

import (
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

type Host struct {
	Address   string
	Hostnames []string
	Up        bool
	TimedOut  bool
	Ports     []Port
}

type Port struct {
	Number        int
	Protocol      string
	State         string
	Service       string
	Product       string
	Version       string
	ExtraInfo     string
	Tunnel        string
	Guessed       bool
	Soft          bool
	Banner        string
	ScriptProduct string
	ScriptVersion string
}

type Options struct {
	ProbePorts  []int
	MaxRate     int
	HostTimeout time.Duration
	MaxRetries  int
	ResolveDNS  bool
	Standard    bool
	StockProbes bool
	VersionDB   string
	NoVersion   []int
}

type Runner interface {
	Discover(ctx context.Context, addrs []string, opts Options) ([]Host, error)
	Services(ctx context.Context, addrs []string, ports []int, opts Options) ([]Host, error)
}

type LightProber interface {
	LightProbes() (path string, cleanup func(), err error)
}

func DiscoverArgs(addrs []string, opts Options) ([]string, error) {
	targets, err := validateAddrs(addrs)
	if err != nil {
		return nil, err
	}
	if len(opts.ProbePorts) == 0 {
		return nil, fmt.Errorf("nmap discover: no probe ports")
	}
	probe, err := portList(opts.ProbePorts)
	if err != nil {
		return nil, fmt.Errorf("nmap discover: %w", err)
	}
	common, err := commonArgs(opts)
	if err != nil {
		return nil, err
	}
	args := []string{"-sn", "-PE", "-PS" + probe}
	args = append(args, common...)
	return append(args, targets...), nil
}

func ServicesArgs(addrs []string, ports []int, opts Options) ([]string, error) {
	targets, err := validateAddrs(addrs)
	if err != nil {
		return nil, err
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("nmap services: no ports")
	}
	list, err := portList(ports)
	if err != nil {
		return nil, fmt.Errorf("nmap services: %w", err)
	}
	common, err := commonArgs(opts)
	if err != nil {
		return nil, err
	}
	args := []string{"-Pn", "-sT", "-sV"}
	if !opts.Standard {
		args = append(args, "--version-light")
	}
	if opts.VersionDB != "" {
		if !filepath.IsAbs(opts.VersionDB) {
			return nil, fmt.Errorf("nmap services: version db %q is not an absolute path", opts.VersionDB)
		}
		args = append(args, "--versiondb", opts.VersionDB)
	}
	args = append(args, "-p", list)
	args = append(args, common...)
	return append(args, targets...), nil
}

func PortsArgs(addrs []string, ports []int, opts Options) ([]string, error) {
	targets, err := validateAddrs(addrs)
	if err != nil {
		return nil, err
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("nmap ports: no ports")
	}
	list, err := portList(ports)
	if err != nil {
		return nil, fmt.Errorf("nmap ports: %w", err)
	}
	common, err := commonArgs(opts)
	if err != nil {
		return nil, err
	}
	args := append([]string{"-Pn", "-sT", "-p", list}, common...)
	return append(args, targets...), nil
}

func commonArgs(opts Options) ([]string, error) {
	var args []string
	if opts.MaxRate < 0 {
		return nil, fmt.Errorf("nmap: negative max rate %d", opts.MaxRate)
	}
	if opts.MaxRate > 0 {
		args = append(args, "--max-rate", strconv.Itoa(opts.MaxRate))
	}
	if opts.HostTimeout < 0 {
		return nil, fmt.Errorf("nmap: negative host timeout %s", opts.HostTimeout)
	}
	if opts.HostTimeout > 0 {
		ms := opts.HostTimeout.Milliseconds()
		if ms == 0 {
			ms = 1
		}
		args = append(args, "--host-timeout", strconv.FormatInt(ms, 10)+"ms")
	}
	if opts.MaxRetries < 0 {
		return nil, fmt.Errorf("nmap: negative max retries %d", opts.MaxRetries)
	}
	if opts.MaxRetries > 0 {
		args = append(args, "--max-retries", strconv.Itoa(opts.MaxRetries))
	}
	if !opts.ResolveDNS {
		args = append(args, "-n")
	}
	return append(args, "-oX", "-"), nil
}

func validateAddrs(addrs []string) ([]string, error) {
	if len(addrs) == 0 {
		return nil, fmt.Errorf("nmap: no addresses")
	}
	out := make([]string, 0, len(addrs)+1)
	var v6 bool
	for i, a := range addrs {
		ip, err := netip.ParseAddr(a)
		if err != nil || ip.Zone() != "" {
			return nil, fmt.Errorf("nmap: invalid address %q", a)
		}
		ip = ip.Unmap()
		if i == 0 {
			v6 = ip.Is6()
			if v6 {
				out = append(out, "-6")
			}
		} else if ip.Is6() != v6 {
			return nil, fmt.Errorf("nmap: mixed IPv4 and IPv6 addresses")
		}
		out = append(out, ip.String())
	}
	return out, nil
}

func portList(ports []int) (string, error) {
	for _, p := range ports {
		if p < 1 || p > 65535 {
			return "", fmt.Errorf("invalid port %d", p)
		}
	}
	return FormatPorts(ports), nil
}

func FormatPorts(ports []int) string {
	sorted := slices.Clone(ports)
	slices.Sort(sorted)
	sorted = slices.Compact(sorted)
	var parts []string
	for i := 0; i < len(sorted); {
		j := i
		for j+1 < len(sorted) && sorted[j+1] == sorted[j]+1 {
			j++
		}
		part := strconv.Itoa(sorted[i])
		if j > i {
			part += "-" + strconv.Itoa(sorted[j])
		}
		parts = append(parts, part)
		i = j + 1
	}
	return strings.Join(parts, ",")
}
