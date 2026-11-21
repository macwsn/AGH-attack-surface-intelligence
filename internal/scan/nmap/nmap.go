package nmap

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

type Host struct {
	Address   string
	Hostnames []string
	Up        bool
	Ports     []Port
}

type Port struct {
	Number    int
	Protocol  string
	State     string
	Service   string
	Product   string
	Version   string
	ExtraInfo string
	Tunnel    string
}

type Options struct {
	ProbePorts  []int
	MaxRate     int
	HostTimeout time.Duration
	ResolveDNS  bool
}

type Runner interface {
	Discover(ctx context.Context, addrs []string, opts Options) ([]Host, error)
	Services(ctx context.Context, addrs []string, ports []int, opts Options) ([]Host, error)
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
	args := []string{"-Pn", "-sT", "-sV", "--version-light", "-p", list}
	args = append(args, common...)
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
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		if p < 1 || p > 65535 {
			return "", fmt.Errorf("invalid port %d", p)
		}
		parts = append(parts, strconv.Itoa(p))
	}
	return strings.Join(parts, ","), nil
}
