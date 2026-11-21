package scan

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"asi/internal/detect"
	"asi/internal/inventory"
	"asi/internal/probe"
	"asi/internal/scan/nmap"
	"asi/internal/targets"
)

const (
	DefaultWorkers      = 4
	DefaultMaxRate      = 100
	InitialGroupSize    = 64
	MinGroupSize        = 16
	MaxGroupSize        = 1024
	GroupTimeMin        = 30 * time.Second
	GroupTimeMax        = 60 * time.Second
	SizeWindow          = 4
	DefaultGroupTimeout = 10 * time.Minute
	PerHostConcurrency  = 2
	HostConcurrency     = 8
)

var ErrAlreadyCompleted = errors.New("scan: run is already completed")

type Store interface {
	RecordGroup(ctx context.Context, runID int64, g inventory.GroupResult) error
	RecordLateHosts(ctx context.Context, runID int64, hosts []inventory.HostResult) error
	RunGroups(ctx context.Context, runID int64) ([]inventory.GroupInfo, error)
	RecordFailedGroup(ctx context.Context, runID int64, g inventory.FailedGroup) error
	FailedGroups(ctx context.Context, runID int64) ([]inventory.FailedGroup, error)
	SetRunTotal(ctx context.Context, runID int64, total int) error
	SetRunStatus(ctx context.Context, runID int64, status inventory.RunStatus) error
	PreviouslyLiveAddresses(ctx context.Context, runID int64) ([]string, error)
	Export(ctx context.Context, asOfRun string) (inventory.Export, error)
}

var _ Store = (*inventory.Inventory)(nil)

type Scanner struct {
	Store        Store
	Runner       nmap.Runner
	Resolver     targets.Resolver
	Clock        Clock
	Transport    func(target string) http.RoundTripper
	ProbeTimeout time.Duration
	HostTimeout  time.Duration
	GroupTimeout time.Duration
	Signatures   SignatureSource
}

type SignatureSource interface {
	Enabled(ctx context.Context) ([]detect.Signature, error)
}

func ParsePorts(s string) ([]int, error) {
	var ports []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		n, err := strconv.Atoi(part)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("invalid port %q", part)
		}
		ports = append(ports, n)
	}
	return normalizePorts(ports)
}

func normalizePorts(in []int) ([]int, error) {
	if len(in) == 0 {
		return nil, errors.New("no ports")
	}
	out := slices.Clone(in)
	for _, p := range out {
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("invalid port %d", p)
		}
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

type runner struct {
	*Scanner
	run      inventory.Run
	clock    Clock
	set      *targets.Set
	ports    []int
	allowed  map[int]bool
	sigs     *detect.Set
	workers  int
	nmapRate int
	nmapSem  chan struct{}
	prober   *probe.Prober
	sizer    *sizer
	timeout  time.Duration

	finished map[string]bool

	mu        sync.Mutex
	nextIndex int
	seen      map[string]bool
	failed    map[string]bool
}

func (s *Scanner) Run(ctx context.Context, run inventory.Run) error {
	if run.Status == inventory.RunCompleted {
		return fmt.Errorf("run %q: %w", run.Name, ErrAlreadyCompleted)
	}
	if run.Status != inventory.RunRunning {
		if err := s.Store.SetRunStatus(ctx, run.ID, inventory.RunRunning); err != nil {
			return fmt.Errorf("run %q: %w", run.Name, err)
		}
	}
	err := s.execute(ctx, run)
	final := inventory.RunCompleted
	switch {
	case ctx.Err() != nil:
		final = inventory.RunPaused
		err = fmt.Errorf("run %q paused: %w", run.Name, ctx.Err())
	case err != nil:
		final = inventory.RunFailed
		err = fmt.Errorf("run %q failed: %w", run.Name, err)
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if serr := s.Store.SetRunStatus(sctx, run.ID, final); serr != nil {
		return errors.Join(err, fmt.Errorf("run %q: %w", run.Name, serr))
	}
	return err
}

func (s *Scanner) execute(ctx context.Context, run inventory.Run) error {
	r, err := s.prepare(ctx, run)
	if err != nil {
		return err
	}
	total := 0
	for range r.set.All() {
		total++
	}
	if err := s.Store.SetRunTotal(ctx, run.ID, total); err != nil {
		return err
	}
	if err := r.resumeState(ctx); err != nil {
		return err
	}
	if err := r.groups(ctx); err != nil {
		return err
	}
	return r.reprobe(ctx)
}

func (s *Scanner) prepare(ctx context.Context, run inventory.Run) (*runner, error) {
	st := run.Settings
	ports, err := normalizePorts(st.Ports)
	if err != nil {
		return nil, fmt.Errorf("settings: %w", err)
	}
	include, err := targets.Parse(strings.NewReader(strings.Join(st.Targets, "\n")))
	if err != nil {
		return nil, fmt.Errorf("settings: targets: %w", err)
	}
	exclude, err := targets.Parse(strings.NewReader(strings.Join(st.Excludes, "\n")))
	if err != nil {
		return nil, fmt.Errorf("settings: excludes: %w", err)
	}
	res := s.Resolver
	if res == nil {
		res = net.DefaultResolver
	}
	set, err := targets.Build(ctx, include, exclude, res)
	if err != nil {
		return nil, fmt.Errorf("expand targets: %w", err)
	}
	var sigs *detect.Set
	if st.SignaturesDir != "" {
		if sigs, err = detect.LoadDir(st.SignaturesDir); err != nil {
			return nil, fmt.Errorf("load signatures: %w", err)
		}
	}
	if s.Signatures != nil {
		stored, err := s.Signatures.Enabled(ctx)
		if err != nil {
			return nil, fmt.Errorf("load signatures: %w", err)
		}
		if sigs, err = detect.Combine(sigs, stored); err != nil {
			return nil, fmt.Errorf("load signatures: %w", err)
		}
	}
	workers := st.Workers
	if workers < 1 {
		workers = DefaultWorkers
	}
	rate := st.MaxRate
	if rate < 1 {
		rate = DefaultMaxRate
	}
	if rate < 2 {
		return nil, fmt.Errorf("settings: max rate %d: need at least 2 to share between nmap and the probe", rate)
	}
	clock := s.Clock
	if clock == nil {
		clock = realClock{}
	}
	nmapBudget := rate / 2
	slots := min(workers, nmapBudget)
	share := nmapBudget / slots
	r := &runner{
		Scanner:  s,
		run:      run,
		clock:    clock,
		set:      set,
		ports:    ports,
		allowed:  map[int]bool{},
		sigs:     sigs,
		workers:  workers,
		nmapRate: share,
		nmapSem:  make(chan struct{}, slots),
		sizer:    &sizer{size: InitialGroupSize},
		timeout:  s.GroupTimeout,
		finished: map[string]bool{},
		seen:     map[string]bool{},
		failed:   map[string]bool{},
	}
	if r.timeout <= 0 {
		r.timeout = DefaultGroupTimeout
	}
	if st.GroupSize > 0 {
		r.sizer = &sizer{size: st.GroupSize, fixed: true}
	}
	for _, p := range ports {
		r.allowed[p] = true
	}
	limiter := NewLimiter(rate-nmapBudget, clock)
	r.prober = &probe.Prober{
		Timeout: s.ProbeTimeout,
		Transport: func(target string) http.RoundTripper {
			var next http.RoundTripper
			if s.Transport != nil {
				next = s.Transport(target)
			} else {
				next = probe.NewTransport(target, s.ProbeTimeout)
			}
			return &limitedTransport{limiter: limiter, next: next}
		},
	}
	return r, nil
}

func (r *runner) resumeState(ctx context.Context) error {
	groups, err := r.Store.RunGroups(ctx, r.run.ID)
	if err != nil {
		return err
	}
	failed, err := r.Store.FailedGroups(ctx, r.run.ID)
	if err != nil {
		return err
	}
	for _, g := range failed {
		r.nextIndex = max(r.nextIndex, g.Index+1)
		for _, a := range g.Addresses {
			r.finished[a] = true
			r.failed[a] = true
		}
	}
	if len(groups) == 0 {
		return nil
	}
	for _, g := range groups {
		r.nextIndex = max(r.nextIndex, g.Index+1)
		for _, a := range g.Addresses {
			r.finished[a] = true
		}
	}
	exp, err := r.Store.Export(ctx, r.run.Name)
	if err != nil {
		return fmt.Errorf("hosts already seen: %w", err)
	}
	for _, h := range exp.Hosts {
		if r.finished[h.Address] && h.MissedRuns == 0 {
			r.seen[h.Address] = true
		}
	}
	return nil
}

type job struct {
	index   int
	targets []targets.Target
}

func (r *runner) groups(ctx context.Context) error {
	gctx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan job)
	go r.dispatch(gctx, jobs)
	var (
		wg       sync.WaitGroup
		errMu    sync.Mutex
		firstErr error
	)
	for range r.workers {
		wg.Go(func() {
			for j := range jobs {
				if gctx.Err() != nil {
					continue
				}
				if err := r.group(gctx, j); err != nil {
					errMu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					errMu.Unlock()
					cancel()
				}
			}
		})
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return err
	}
	return firstErr
}

func (r *runner) dispatch(ctx context.Context, jobs chan<- job) {
	defer close(jobs)
	next, stop := iter.Pull(r.set.All())
	defer stop()
	for {
		size := r.sizer.current()
		g := make([]targets.Target, 0, size)
		done := false
		for len(g) < size {
			t, ok := next()
			if !ok {
				done = true
				break
			}
			if !r.finished[t.Addr.String()] {
				g = append(g, t)
			}
		}
		if len(g) > 0 {
			select {
			case jobs <- job{index: r.newIndex(), targets: g}:
			case <-ctx.Done():
				return
			}
		}
		if done {
			return
		}
	}
}

func (r *runner) newIndex() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	i := r.nextIndex
	r.nextIndex++
	return i
}

func (r *runner) group(ctx context.Context, j job) error {
	err := r.attempt(ctx, j)
	if !timedOut(ctx, err) {
		return err
	}
	parts := []job{j}
	if half := len(j.targets) / 2; half > 0 {
		parts = []job{{index: j.index, targets: j.targets[:half]}, {index: r.newIndex(), targets: j.targets[half:]}}
	}
	for _, p := range parts {
		err := r.attempt(ctx, p)
		if timedOut(ctx, err) {
			err = r.fail(ctx, p, err)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func timedOut(ctx context.Context, err error) bool {
	return err != nil && ctx.Err() == nil && errors.Is(err, context.DeadlineExceeded)
}

func addresses(ts []targets.Target) []string {
	addrs := make([]string, len(ts))
	for i, t := range ts {
		addrs[i] = t.Addr.String()
	}
	return addrs
}

func (r *runner) fail(ctx context.Context, j job, cause error) error {
	addrs := addresses(j.targets)
	if err := r.Store.RecordFailedGroup(ctx, r.run.ID, inventory.FailedGroup{Index: j.index, Addresses: addrs, Reason: cause.Error()}); err != nil {
		return err
	}
	r.mu.Lock()
	for _, a := range addrs {
		r.failed[a] = true
	}
	r.mu.Unlock()
	return nil
}

func (r *runner) attempt(ctx context.Context, j job) error {
	start := r.clock.Now()
	addrs := addresses(j.targets)
	byAddr := make(map[string]targets.Target, len(j.targets))
	for i, t := range j.targets {
		byAddr[addrs[i]] = t
	}
	actx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	hosts, err := r.scanHosts(actx, addrs, byAddr)
	if err != nil {
		return fmt.Errorf("group %d: %w", j.index, err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	d := max(r.clock.Now().Sub(start), 0)
	if err := r.Store.RecordGroup(ctx, r.run.ID, inventory.GroupResult{Index: j.index, Addresses: addrs, Hosts: hosts, Duration: d}); err != nil {
		return err
	}
	r.mu.Lock()
	for _, h := range hosts {
		r.seen[h.Address] = true
	}
	r.mu.Unlock()
	r.sizer.observe(len(addrs), d)
	return nil
}

func (r *runner) reprobe(ctx context.Context) error {
	prev, err := r.Store.PreviouslyLiveAddresses(ctx, r.run.ID)
	if err != nil {
		return err
	}
	want := map[string]bool{}
	for _, a := range prev {
		if ip, err := netip.ParseAddr(a); err == nil && !r.seen[ip.Unmap().String()] && !r.failed[ip.Unmap().String()] {
			want[ip.Unmap().String()] = true
		}
	}
	if len(want) == 0 {
		return nil
	}
	var missing []string
	byAddr := map[string]targets.Target{}
	for t := range r.set.All() {
		if a := t.Addr.String(); want[a] {
			missing = append(missing, a)
			byAddr[a] = t
		}
	}
	if len(missing) == 0 {
		return nil
	}
	hosts, err := r.scanHosts(ctx, missing, byAddr)
	if err != nil {
		return fmt.Errorf("re-probe: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := r.Store.RecordLateHosts(ctx, r.run.ID, hosts); err != nil {
		return fmt.Errorf("re-probe: %w", err)
	}
	return nil
}

func (r *runner) nmapOptions() nmap.Options {
	return nmap.Options{ProbePorts: slices.Clone(r.ports), MaxRate: r.nmapRate, HostTimeout: r.HostTimeout}
}

func (r *runner) acquireNmap(ctx context.Context) error {
	select {
	case r.nmapSem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *runner) scanHosts(ctx context.Context, addrs []string, inScope map[string]targets.Target) ([]inventory.HostResult, error) {
	if err := r.acquireNmap(ctx); err != nil {
		return nil, err
	}
	found, err := r.Runner.Discover(ctx, addrs, r.nmapOptions())
	<-r.nmapSem
	if err != nil {
		return nil, fmt.Errorf("discover: %w", err)
	}
	type live struct {
		addr      string
		hostnames []string
		ports     []nmap.Port
	}
	var hosts []*live
	byAddr := map[string]*live{}
	for _, h := range found {
		a, ok := scopedAddr(h.Address, inScope)
		if !ok || !h.Up || byAddr[a] != nil {
			continue
		}
		l := &live{addr: a, hostnames: append(slices.Clone(inScope[a].Hostnames), h.Hostnames...)}
		byAddr[a] = l
		hosts = append(hosts, l)
	}
	if len(hosts) == 0 {
		return []inventory.HostResult{}, nil
	}
	slices.SortFunc(hosts, func(a, b *live) int {
		return netip.MustParseAddr(a.addr).Compare(netip.MustParseAddr(b.addr))
	})
	liveAddrs := make([]string, len(hosts))
	for i, h := range hosts {
		liveAddrs[i] = h.addr
	}
	if err := r.acquireNmap(ctx); err != nil {
		return nil, err
	}
	svc, err := r.Runner.Services(ctx, liveAddrs, slices.Clone(r.ports), r.nmapOptions())
	<-r.nmapSem
	if err != nil {
		return nil, fmt.Errorf("services: %w", err)
	}
	for _, h := range svc {
		a, ok := scopedAddr(h.Address, inScope)
		l := byAddr[a]
		if !ok || l == nil {
			continue
		}
		l.hostnames = append(l.hostnames, h.Hostnames...)
		for _, p := range h.Ports {
			proto := strings.ToLower(p.Protocol)
			if (proto != "" && proto != "tcp") || p.State != "open" || !r.allowed[p.Number] {
				continue
			}
			if !slices.ContainsFunc(l.ports, func(q nmap.Port) bool { return q.Number == p.Number }) {
				l.ports = append(l.ports, p)
			}
		}
	}

	results := make([]inventory.HostResult, len(hosts))
	sem := make(chan struct{}, HostConcurrency)
	var wg sync.WaitGroup
	for i, h := range hosts {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			return nil, ctx.Err()
		}
		wg.Go(func() {
			defer func() { <-sem }()
			hostname := ""
			if names := inScope[h.addr].Hostnames; len(names) > 0 {
				hostname = names[0]
			}
			results[i] = inventory.HostResult{
				Address:   h.addr,
				Hostnames: h.hostnames,
				Services:  r.services(ctx, h.addr, hostname, h.ports),
			}
		})
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return results, nil
}

func scopedAddr(s string, inScope map[string]targets.Target) (string, bool) {
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return "", false
	}
	a := ip.Unmap().String()
	_, ok := inScope[a]
	return a, ok
}

func (r *runner) services(ctx context.Context, addr, hostname string, ports []nmap.Port) []inventory.ServiceResult {
	slices.SortFunc(ports, func(a, b nmap.Port) int { return a.Number - b.Number })
	out := make([]inventory.ServiceResult, len(ports))
	sem := make(chan struct{}, PerHostConcurrency)
	var wg sync.WaitGroup
	for i, p := range ports {
		out[i] = inventory.ServiceResult{
			Port:     p.Number,
			Protocol: "tcp",
			State:    p.State,
			Service:  p.Service,
			Product:  p.Product,
			Version:  p.Version,
		}
		schemes := httpSchemes(p)
		if len(schemes) == 0 {
			continue
		}
		wg.Go(func() {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			r.probe(ctx, &out[i], addr, hostname, schemes)
		})
	}
	wg.Wait()
	return out
}

func (r *runner) probe(ctx context.Context, svc *inventory.ServiceResult, addr, hostname string, schemes []bool) {
	for _, useTLS := range schemes {
		sess, err := r.prober.Probe(ctx, addr, svc.Port, useTLS, hostname)
		if err != nil {
			continue
		}
		res := r.sigs.Detect(ctx, sess)
		h := sess.HTTP
		svc.HTTP = &h
		for _, t := range res.Technologies {
			svc.Technologies = append(svc.Technologies, inventory.Technology(t))
		}
		for _, f := range res.Findings {
			svc.Findings = append(svc.Findings, inventory.Finding(f))
		}
		return
	}
}

func httpSchemes(p nmap.Port) []bool {
	name := strings.ToLower(p.Service)
	switch {
	case strings.ToLower(p.Tunnel) == "ssl", name == "https", name == "ssl", strings.HasPrefix(name, "https-"):
		return []bool{true}
	case strings.Contains(name, "http"):
		return []bool{false}
	case name == "", name == "unknown":
		return []bool{false, true}
	}
	return nil
}

type sizer struct {
	mu      sync.Mutex
	size    int
	fixed   bool
	perAddr []float64
}

func (z *sizer) current() int {
	z.mu.Lock()
	defer z.mu.Unlock()
	return z.size
}

func (z *sizer) observe(n int, d time.Duration) {
	if z.fixed || n == 0 {
		return
	}
	z.mu.Lock()
	defer z.mu.Unlock()
	z.perAddr = append(z.perAddr, d.Seconds()/float64(n))
	if len(z.perAddr) > SizeWindow {
		z.perAddr = z.perAddr[1:]
	}
	var sum float64
	for _, v := range z.perAddr {
		sum += v
	}
	avg := sum / float64(len(z.perAddr))
	if expected := avg * float64(z.size); expected >= GroupTimeMin.Seconds() && expected <= GroupTimeMax.Seconds() {
		return
	}
	target := float64(MaxGroupSize)
	if avg > 0 {
		target = min(((GroupTimeMin+GroupTimeMax)/2).Seconds()/avg, target)
	}
	z.size = max(int(target), MinGroupSize)
}
