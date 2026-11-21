package nmaptest

import (
	"context"
	"slices"
	"sync"

	"asi/internal/scan/nmap"
)

type Call struct {
	Method string
	Addrs  []string
	Ports  []int
	Opts   nmap.Options
}

type Runner struct {
	DiscoverFunc func(ctx context.Context, addrs []string, opts nmap.Options) ([]nmap.Host, error)
	ServicesFunc func(ctx context.Context, addrs []string, ports []int, opts nmap.Options) ([]nmap.Host, error)

	mu    sync.Mutex
	calls []Call
}

var _ nmap.Runner = (*Runner)(nil)

func (r *Runner) Discover(ctx context.Context, addrs []string, opts nmap.Options) ([]nmap.Host, error) {
	r.record(Call{Method: "Discover", Addrs: slices.Clone(addrs), Opts: opts})
	if r.DiscoverFunc == nil {
		return nil, nil
	}
	return r.DiscoverFunc(ctx, addrs, opts)
}

func (r *Runner) Services(ctx context.Context, addrs []string, ports []int, opts nmap.Options) ([]nmap.Host, error) {
	r.record(Call{Method: "Services", Addrs: slices.Clone(addrs), Ports: slices.Clone(ports), Opts: opts})
	if r.ServicesFunc == nil {
		return nil, nil
	}
	return r.ServicesFunc(ctx, addrs, ports, opts)
}

func (r *Runner) Calls() []Call {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.calls)
}

func (r *Runner) record(c Call) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, c)
}
