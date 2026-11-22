package scan

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	DefaultMaxAddresses = 262144
	DefaultMaxWork      = DefaultMaxAddresses * 1000
	HeartbeatInterval   = 5 * time.Second
	StoreRetryFor       = 60 * time.Second
	StoreRetryMax       = 10 * time.Second
	StatusRetryFor      = 30 * time.Second
	GuessTimeout        = 3 * time.Second
	SecondPassPerPort   = 20 * time.Second
	SecondPassHostMax   = 90 * time.Second
	SecondPassRetries   = 1
)

var (
	ErrAlreadyCompleted = errors.New("scan: run is already completed")
	ErrStoreUnavailable = errors.New("database unavailable")
)

const (
	ServiceDetectionLight    = "light"
	ServiceDetectionStandard = "standard"
	NotProbedID              = "builtin-not-probed-by-policy"
)

type Store interface {
	RecordGroup(ctx context.Context, runID int64, g inventory.GroupResult) error
	RecordLateHosts(ctx context.Context, runID int64, hosts []inventory.HostResult) error
	RunGroups(ctx context.Context, runID int64) ([]inventory.GroupInfo, error)
	RecordFailedGroup(ctx context.Context, runID int64, g inventory.FailedGroup) error
	FailedGroups(ctx context.Context, runID int64) ([]inventory.FailedGroup, error)
	SetRunTotal(ctx context.Context, runID int64, total int) error
	SetRunStatus(ctx context.Context, runID int64, status inventory.RunStatus) error
	Heartbeat(ctx context.Context, runID int64, inFlight int) error
	PreviouslyLiveAddresses(ctx context.Context, runID int64) ([]string, error)
	PreviousFavicons(ctx context.Context, runID int64) (map[inventory.FaviconKey]string, error)
	Export(ctx context.Context, asOfRun string) (inventory.Export, error)
	RecordRateSamples(ctx context.Context, runID int64, samples []inventory.RateSample) error
	AddRunPackets(ctx context.Context, runID int64, packets int) error
	RecheckPlan(ctx context.Context, run inventory.Run, inScope func(address string) bool) (inventory.Run, []inventory.KnownService, error)
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

type SharedSignatures interface {
	SignatureSource
	Set(ctx context.Context) (*detect.Set, error)
	Dir() string
}

var portPresets = map[string]string{"top100": top100Ports, "top1000": top1000Ports, "all": "1-65535"}

func ParsePorts(s string) ([]int, error) {
	var ports []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if preset, ok := portPresets[strings.ToLower(part)]; ok {
			p, err := ParsePorts(preset)
			if err != nil {
				return nil, fmt.Errorf("preset %s: %w", part, err)
			}
			ports = append(ports, p...)
			continue
		}
		first, last, isRange := strings.Cut(part, "-")
		lo, err := parsePort(first)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q", part)
		}
		hi := lo
		if isRange {
			if hi, err = parsePort(last); err != nil || hi < lo {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
		}
		for p := lo; p <= hi; p++ {
			ports = append(ports, p)
		}
	}
	return normalizePorts(ports)
}

func parsePort(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" || strings.Trim(s, "0123456789") != "" {
		return 0, errors.New("not a number")
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return 0, errors.New("out of range")
	}
	return n, nil
}

func FormatPorts(ports []int) string { return nmap.FormatPorts(ports) }

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

type knownHost struct {
	ports []int
	http  map[int]bool
}

type runner struct {
	*Scanner
	run         inventory.Run
	clock       Clock
	set         *targets.Set
	total       int
	ports       []int
	allowed     map[int]bool
	sigs        *detect.Set
	workers     int
	maxRate     int
	slots       int
	ctrl        *Controller
	meter       *meter
	nmapSem     chan struct{}
	prober      *probe.Prober
	guessProber *probe.Prober
	sizer       *sizer
	timeout     time.Duration
	known       map[string]knownHost
	order       []targets.Target
	packets     *atomic.Int64
	inFlight    *inFlight
	standard    bool

	probesOnce    sync.Once
	probesDB      string
	probesCleanup func()

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
	hctx, stopHeartbeat := context.WithCancel(ctx)
	var packets atomic.Int64
	live := &inFlight{changed: make(chan struct{}, 1)}
	beating := s.heartbeat(hctx, run.ID, live)
	r, err := s.prepare(ctx, run, &packets)
	if err == nil {
		r.inFlight = live
		err = r.execute(ctx)
		r.removeLightProbes()
	}
	stopHeartbeat()
	<-beating
	final := inventory.RunCompleted
	switch {
	case ctx.Err() != nil:
		final = inventory.RunPaused
		err = fmt.Errorf("run %q paused: %w", run.Name, ctx.Err())
	case errors.Is(err, ErrStoreUnavailable):
		final = inventory.RunPaused
		err = fmt.Errorf("run %q paused, resume it once the database is back: %w", run.Name, err)
	case err != nil:
		final = inventory.RunFailed
		err = fmt.Errorf("run %q failed: %w", run.Name, err)
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), StatusRetryFor)
	defer cancel()
	if r != nil {
		if ferr := r.flush(sctx); ferr != nil {
			err = errors.Join(err, fmt.Errorf("run %q: %w", run.Name, ferr))
		}
	}
	if n := packets.Load(); n > 0 {
		if perr := s.Store.AddRunPackets(sctx, run.ID, int(n)); perr != nil {
			err = errors.Join(err, fmt.Errorf("run %q: %w", run.Name, perr))
		}
	}
	if serr := retryStore(sctx, s.clock(), StatusRetryFor, fmt.Sprintf("set status %s", final), func() error {
		return s.Store.SetRunStatus(sctx, run.ID, final)
	}); serr != nil {
		if errors.Is(err, ErrStoreUnavailable) {
			return fmt.Errorf("run %q stopped and its status could not be set to paused, it shows as stalled and asi scan resume continues it once the database is back: %w", run.Name, serr)
		}
		return errors.Join(err, fmt.Errorf("run %q: %w", run.Name, serr))
	}
	return err
}

func (s *Scanner) clock() Clock {
	if s.Clock == nil {
		return realClock{}
	}
	return s.Clock
}

type inFlight struct {
	mu      sync.Mutex
	n       atomic.Int64
	changed chan struct{}
}

func (f *inFlight) add(n int64) {
	if f == nil || n == 0 {
		return
	}
	if n < 0 {
		f.mu.Lock()
		f.n.Add(n)
		f.mu.Unlock()
	} else {
		f.n.Add(n)
	}
	select {
	case f.changed <- struct{}{}:
	default:
	}
}

func (s *Scanner) heartbeat(ctx context.Context, runID int64, live *inFlight) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(HeartbeatInterval)
		defer tick.Stop()
		for {
			live.mu.Lock()
			_ = s.Store.Heartbeat(ctx, runID, int(live.n.Load()))
			live.mu.Unlock()
			select {
			case <-tick.C:
			case <-live.changed:
			case <-ctx.Done():
				return
			}
		}
	}()
	return done
}

func (r *runner) execute(ctx context.Context) error {
	if err := r.Store.SetRunTotal(ctx, r.run.ID, r.total); err != nil {
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

func (r *runner) flush(ctx context.Context) error {
	r.meter.flushing.Lock()
	defer r.meter.flushing.Unlock()
	r.meter.mark(r.clock.Now())
	samples := r.meter.pending()
	if err := retryStore(ctx, r.clock, StoreRetryFor, "rate samples", func() error {
		return r.Store.RecordRateSamples(ctx, r.run.ID, samples)
	}); err != nil {
		return err
	}
	r.meter.done(samples)
	return nil
}

func (s *Scanner) expand(ctx context.Context, st inventory.RunSettings) (*targets.Set, []int, error) {
	ports, err := normalizePorts(st.Ports)
	if err != nil {
		return nil, nil, fmt.Errorf("settings: %w", err)
	}
	set, err := s.TargetSet(ctx, st)
	if err != nil {
		return nil, nil, err
	}
	return set, ports, nil
}

func (s *Scanner) PlanRecheck(ctx context.Context, run inventory.Run) ([]inventory.KnownService, error) {
	set, err := s.TargetSet(ctx, run.Settings)
	if err != nil {
		return nil, err
	}
	_, known, _, err := s.planRecheck(ctx, run, set)
	return known, err
}

func (s *Scanner) planRecheck(ctx context.Context, run inventory.Run, set *targets.Set) (inventory.Run, []inventory.KnownService, []targets.Target, error) {
	base, known, err := s.Store.RecheckPlan(ctx, run, nil)
	if err != nil {
		return inventory.Run{}, nil, nil, err
	}
	want := map[string]bool{}
	for _, k := range known {
		want[k.Address] = true
	}
	found := map[string]targets.Target{}
	for t := range set.All() {
		if a := t.Addr.String(); want[a] {
			found[a] = t
			if len(found) == len(want) {
				break
			}
		}
	}
	var (
		kept  []inventory.KnownService
		order []targets.Target
		added = map[string]bool{}
	)
	for _, k := range known {
		t, ok := found[k.Address]
		if !ok {
			continue
		}
		kept = append(kept, k)
		if !added[k.Address] {
			added[k.Address] = true
			order = append(order, t)
		}
	}
	if len(kept) == 0 {
		return inventory.Run{}, nil, nil, fmt.Errorf("recheck base: %w: no known open service in the targets", inventory.ErrNoRecheckBase)
	}
	return base, kept, order, nil
}

func (s *Scanner) TargetSet(ctx context.Context, st inventory.RunSettings) (*targets.Set, error) {
	include, err := targets.ParseHosts(strings.NewReader(strings.Join(st.Targets, "\n")))
	if err != nil {
		return nil, fmt.Errorf("settings: targets: %w", err)
	}
	exclude, err := targets.ParseHosts(strings.NewReader(strings.Join(st.Excludes, "\n")))
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
	return set, nil
}

func maxRateOf(st inventory.RunSettings) (int, error) {
	rate := st.MaxRate
	if rate < 1 {
		rate = DefaultMaxRate
	}
	if rate < 2 {
		return 0, fmt.Errorf("settings: max rate %d: need at least 2 to share between nmap and the probe", rate)
	}
	return rate, nil
}

func (s *Scanner) Validate(ctx context.Context, st inventory.RunSettings) error {
	_, _, err := s.validated(ctx, st)
	return err
}

func (s *Scanner) validated(ctx context.Context, st inventory.RunSettings) (*detect.Set, int, error) {
	if !inventory.ValidMode(st.Mode) {
		return nil, 0, fmt.Errorf("settings: invalid mode %q", st.Mode)
	}
	if _, err := normalizePorts(st.Ports); err != nil {
		return nil, 0, fmt.Errorf("settings: %w", err)
	}
	if _, err := targets.ParseHosts(strings.NewReader(strings.Join(st.Targets, "\n"))); err != nil {
		return nil, 0, fmt.Errorf("settings: targets: %w", err)
	}
	if _, err := targets.ParseHosts(strings.NewReader(strings.Join(st.Excludes, "\n"))); err != nil {
		return nil, 0, fmt.Errorf("settings: excludes: %w", err)
	}
	var err error
	shared, isShared := s.Signatures.(SharedSignatures)
	var sigs *detect.Set
	if st.SignaturesDir != "" && !(isShared && shared.Dir() != "" && filepath.Clean(shared.Dir()) == filepath.Clean(st.SignaturesDir)) {
		if sigs, err = detect.LoadDir(st.SignaturesDir); err != nil {
			return nil, 0, fmt.Errorf("load signatures: %w", err)
		}
	}
	if s.Signatures != nil {
		var stored []detect.Signature
		if isShared {
			var set *detect.Set
			if set, err = shared.Set(ctx); set != nil {
				stored = set.Signatures
			}
		} else {
			stored, err = s.Signatures.Enabled(ctx)
		}
		if err != nil {
			return nil, 0, fmt.Errorf("load signatures: %w", err)
		}
		if sigs, err = detect.Combine(sigs, stored); err != nil {
			return nil, 0, fmt.Errorf("load signatures: %w", err)
		}
	}
	rate, err := maxRateOf(st)
	if err != nil {
		return nil, 0, err
	}
	switch st.ServiceDetection {
	case "", ServiceDetectionLight, ServiceDetectionStandard:
	default:
		return nil, 0, fmt.Errorf("settings: service detection %q: want %s or %s", st.ServiceDetection, ServiceDetectionLight, ServiceDetectionStandard)
	}
	return sigs, rate, nil
}

func (s *Scanner) prepare(ctx context.Context, run inventory.Run, packets *atomic.Int64) (*runner, error) {
	st := run.Settings
	sigs, rate, err := s.validated(ctx, st)
	if err != nil {
		return nil, err
	}
	set, ports, err := s.expand(ctx, st)
	if err != nil {
		return nil, err
	}
	workers := st.Workers
	if workers < 1 {
		workers = DefaultWorkers
	}
	clock := s.clock()
	nmapBudget := rate / 2
	total := 0
	for range set.All() {
		total++
	}
	slots := NmapSlots(workers, rate, total)
	r := &runner{
		Scanner:  s,
		run:      run,
		clock:    clock,
		set:      set,
		total:    total,
		ports:    ports,
		allowed:  map[int]bool{},
		sigs:     sigs,
		workers:  workers,
		maxRate:  rate,
		slots:    slots,
		nmapSem:  make(chan struct{}, slots),
		sizer:    &sizer{size: InitialGroupSize},
		timeout:  s.GroupTimeout,
		standard: st.ServiceDetection != ServiceDetectionLight,
		packets:  packets,
		finished: map[string]bool{},
		seen:     map[string]bool{},
		failed:   map[string]bool{},
	}
	if r.timeout <= 0 {
		r.timeout = DefaultGroupTimeout
	}
	if st.Recheck() {
		_, known, order, err := s.planRecheck(ctx, run, set)
		if err != nil {
			return nil, err
		}
		r.order = order
		r.known = map[string]knownHost{}
		for _, k := range known {
			h := r.known[k.Address]
			if h.http == nil {
				h.http = map[int]bool{}
			}
			if !slices.Contains(h.ports, k.Port) {
				h.ports = append(h.ports, k.Port)
			}
			h.http[k.Port] = k.HTTP || knownHTTP(k.Service)
			r.known[k.Address] = h
		}
		for a, h := range r.known {
			slices.Sort(h.ports)
			r.known[a] = h
		}
		r.total = len(r.order)
		r.slots = NmapSlots(workers, rate, r.total)
		r.nmapSem = make(chan struct{}, r.slots)
	}
	if st.GroupSize > 0 {
		r.sizer = &sizer{size: st.GroupSize, fixed: true}
	}
	for _, p := range ports {
		r.allowed[p] = true
	}
	limiter := NewLimiter(rate-nmapBudget, clock)
	if !st.NoAdaptive {
		r.ctrl = newController(rate, r.slots, clock)
		r.ctrl.onChange = func(eff int) {
			limiter.SetRate(eff - eff/2)
			r.meter.mark(clock.Now())
		}
	}
	r.meter = newMeter(rate, r.effective)
	observe := func(time.Duration, bool) {}
	if r.ctrl != nil {
		observe = r.ctrl.Observe
	}
	sent := func(t time.Time) { r.meter.add(t, 1) }
	timeout := s.ProbeTimeout
	if st.HTTPTimeoutMS > 0 {
		timeout = time.Duration(st.HTTPTimeoutMS) * time.Millisecond
	}
	if timeout <= 0 {
		timeout = probe.DefaultTimeout
	}
	favicons, err := s.Store.PreviousFavicons(ctx, run.ID)
	if err != nil {
		return nil, fmt.Errorf("run %q: %w", run.Name, err)
	}
	prober := func(timeout time.Duration, observe func(time.Duration, bool)) *probe.Prober {
		return &probe.Prober{
			Timeout: timeout,
			PreviousFavicon: func(address string, port int) string {
				return favicons[inventory.FaviconKey{Address: address, Port: port}]
			},
			Transport: func(target string) http.RoundTripper {
				var next http.RoundTripper
				if s.Transport != nil {
					next = probe.Recording(s.Transport(target))
				} else {
					next = probe.NewTransport(target, timeout)
				}
				return &limitedTransport{limiter: limiter, clock: clock, sent: sent, observe: observe, next: next, packets: r.packets}
			},
		}
	}
	r.prober = prober(timeout, observe)
	r.guessProber = prober(min(timeout, GuessTimeout), func(time.Duration, bool) {})
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

func (r *runner) all() iter.Seq[targets.Target] {
	if r.known != nil {
		return slices.Values(r.order)
	}
	return r.set.All()
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
	next, stop := iter.Pull(r.all())
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
	if skipped(ctx, err) {
		return r.fail(ctx, j, err)
	}
	if !timedOut(ctx, err) {
		return err
	}
	parts := []job{j}
	if half := len(j.targets) / 2; half > 0 {
		parts = []job{{index: j.index, targets: j.targets[:half]}, {index: r.newIndex(), targets: j.targets[half:]}}
	}
	for _, p := range parts {
		err := r.attempt(ctx, p)
		if timedOut(ctx, err) || skipped(ctx, err) {
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

func skipped(ctx context.Context, err error) bool {
	return err != nil && ctx.Err() == nil && errors.Is(err, nmap.ErrNoTargetsScanned)
}

func retryStore(ctx context.Context, clock Clock, window time.Duration, what string, write func() error) error {
	start := clock.Now()
	wait := time.Second
	for {
		err := write()
		if err == nil || ctx.Err() != nil {
			return err
		}
		if clock.Now().Sub(start) >= window {
			return fmt.Errorf("%s: %w for %s: %w", what, ErrStoreUnavailable, window, err)
		}
		select {
		case <-clock.After(wait):
		case <-ctx.Done():
			return ctx.Err()
		}
		wait = min(wait*2, StoreRetryMax)
	}
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
	g := inventory.FailedGroup{Index: j.index, Addresses: addrs, Reason: cause.Error()}
	if err := retryStore(ctx, r.clock, StoreRetryFor, fmt.Sprintf("record failed group %d", j.index), func() error {
		return r.Store.RecordFailedGroup(ctx, r.run.ID, g)
	}); err != nil {
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
	var discovered atomic.Int64
	defer func() { r.inFlight.add(-discovered.Load()) }()
	hosts, err := r.scanHosts(actx, addrs, byAddr, func(n int) {
		discovered.Add(int64(n))
		r.inFlight.add(int64(n))
	})
	if err != nil {
		return fmt.Errorf("group %d: %w", j.index, err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	d := max(r.clock.Now().Sub(start), 0)
	g := inventory.GroupResult{Index: j.index, Addresses: addrs, Hosts: hosts, Duration: d}
	if r.known != nil {
		g.CoveredPorts = make(map[string][]int, len(addrs))
		for _, a := range addrs {
			g.CoveredPorts[a] = slices.Clone(r.known[a].ports)
		}
	}
	r.inFlight.add(-discovered.Swap(0))
	if err := retryStore(ctx, r.clock, StoreRetryFor, fmt.Sprintf("record group %d", j.index), func() error {
		return r.Store.RecordGroup(ctx, r.run.ID, g)
	}); err != nil {
		return err
	}
	r.mu.Lock()
	for _, h := range hosts {
		r.seen[h.Address] = true
	}
	r.mu.Unlock()
	r.sizer.observe(len(addrs), d)
	return r.flush(ctx)
}

func (r *runner) reprobe(ctx context.Context) error {
	prev, err := r.Store.PreviouslyLiveAddresses(ctx, r.run.ID)
	if err != nil {
		return err
	}
	want := map[string]bool{}
	for _, a := range prev {
		ip, err := netip.ParseAddr(a)
		if err != nil {
			continue
		}
		u := ip.Unmap().String()
		if _, known := r.known[u]; r.known != nil && !known {
			continue
		}
		if !r.seen[u] && !r.failed[u] {
			want[u] = true
		}
	}
	if len(want) == 0 {
		return nil
	}
	var missing []string
	byAddr := map[string]targets.Target{}
	for t := range r.all() {
		if a := t.Addr.String(); want[a] {
			missing = append(missing, a)
			byAddr[a] = t
		}
	}
	if len(missing) == 0 {
		return nil
	}
	hosts, err := r.scanHosts(ctx, missing, byAddr, nil)
	if skipped(ctx, err) {
		return nil
	}
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

func (r *runner) effective() int {
	if r.ctrl == nil {
		return r.maxRate
	}
	return r.ctrl.Rate()
}

func (r *runner) nmapOptions(ports []int) nmap.Options {
	share := max(r.effective()/2/r.slots, 1)
	return nmap.Options{ProbePorts: slices.Clone(ports), MaxRate: share, HostTimeout: r.HostTimeout}
}

func (r *runner) lightProbes() string {
	r.probesOnce.Do(func() {
		if lp, ok := r.Runner.(nmap.LightProber); ok {
			if path, cleanup, err := lp.LightProbes(); err == nil {
				r.probesDB, r.probesCleanup = path, cleanup
			}
		}
	})
	return r.probesDB
}

func (r *runner) removeLightProbes() {
	r.probesOnce.Do(func() {})
	if r.probesCleanup != nil {
		r.probesCleanup()
	}
}

func (r *runner) nmapCall(packets int, call func() ([]nmap.Host, error)) ([]nmap.Host, error) {
	if r.packets != nil {
		r.packets.Add(int64(packets))
	}
	start := r.clock.Now()
	hosts, err := call()
	r.meter.spread(start, r.clock.Now(), packets)
	return hosts, err
}

func (r *runner) acquireNmap(ctx context.Context) error {
	select {
	case r.nmapSem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *runner) scanHosts(ctx context.Context, addrs []string, inScope map[string]targets.Target, discovered func(int)) ([]inventory.HostResult, error) {
	if r.known == nil {
		return r.scanBatch(ctx, addrs, r.ports, inScope, discovered)
	}
	var (
		known  []string
		order  []int
		byPort = map[int][]string{}
		sets   = map[string]bool{}
	)
	for _, a := range addrs {
		h, ok := r.known[a]
		if !ok {
			continue
		}
		known = append(known, a)
		sets[fmt.Sprint(h.ports)] = true
		for _, p := range h.ports {
			if _, ok := byPort[p]; !ok {
				order = append(order, p)
			}
			byPort[p] = append(byPort[p], a)
		}
	}
	if len(sets) <= 1 {
		if len(known) == 0 {
			return []inventory.HostResult{}, nil
		}
		return r.scanBatch(ctx, known, r.known[known[0]].ports, inScope, discovered)
	}
	results := make([][]inventory.HostResult, len(order))
	errs := make([]error, len(order))
	var wg sync.WaitGroup
	for i, p := range order {
		wg.Go(func() { results[i], errs[i] = r.scanBatch(ctx, byPort[p], []int{p}, inScope, nil) })
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	if discovered != nil {
		discovered(len(known))
	}
	out := []inventory.HostResult{}
	at := map[string]int{}
	for _, hosts := range results {
		for _, h := range hosts {
			i, ok := at[h.Address]
			if !ok {
				at[h.Address] = len(out)
				out = append(out, h)
				continue
			}
			for _, n := range h.Hostnames {
				if !slices.Contains(out[i].Hostnames, n) {
					out[i].Hostnames = append(out[i].Hostnames, n)
				}
			}
			out[i].Services = append(out[i].Services, h.Services...)
		}
	}
	for i := range out {
		slices.SortStableFunc(out[i].Services, func(a, b inventory.ServiceResult) int { return a.Port - b.Port })
	}
	slices.SortStableFunc(out, func(a, b inventory.HostResult) int {
		return slices.Index(known, a.Address) - slices.Index(known, b.Address)
	})
	return out, nil
}

func (r *runner) scanBatch(ctx context.Context, addrs []string, ports []int, inScope map[string]targets.Target, discovered func(int)) ([]inventory.HostResult, error) {
	if err := r.acquireNmap(ctx); err != nil {
		return nil, err
	}
	opts := r.nmapOptions(ports)
	found, err := r.nmapCall(len(addrs)*(1+len(ports)), func() ([]nmap.Host, error) {
		return r.Runner.Discover(ctx, addrs, opts)
	})
	<-r.nmapSem
	if err != nil {
		return nil, fmt.Errorf("discover: %w", err)
	}
	if discovered != nil {
		discovered(len(addrs))
	}
	type live struct {
		addr      string
		hostnames []string
		ports     []nmap.Port
		notes     []string
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
	opts = r.nmapOptions(ports)
	opts.VersionDB = r.lightProbes()
	opts.NoVersion = slices.DeleteFunc(slices.Clone(ports), func(n int) bool { return !policyPort(n) })
	svc, err := r.nmapCall(len(liveAddrs)*len(ports), func() ([]nmap.Host, error) {
		return r.Runner.Services(ctx, liveAddrs, slices.Clone(ports), opts)
	})
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
			if (proto != "" && proto != "tcp") || p.State != "open" || !r.allowed[p.Number] || !slices.Contains(ports, p.Number) {
				continue
			}
			if !slices.ContainsFunc(l.ports, func(q nmap.Port) bool { return q.Number == p.Number }) {
				l.ports = append(l.ports, p)
			}
		}
	}
	type pass struct {
		stock bool
		ports []int
		addrs []string
	}
	again := map[string]*pass{}
	var keys []string
	for _, h := range hosts {
		var standard, soft []int
		for _, p := range h.ports {
			switch {
			case neverProbe(p):
			case r.standard && (unconfirmed(p) || p.Soft || needsStandard(p)):
				standard = append(standard, p.Number)
			case p.Soft:
				soft = append(soft, p.Number)
			}
		}
		for _, ps := range []pass{{ports: standard}, {stock: true, ports: soft}} {
			if len(ps.ports) == 0 {
				continue
			}
			k := fmt.Sprint(ps.stock, nmap.FormatPorts(ps.ports))
			if again[k] == nil {
				keys = append(keys, k)
				again[k] = &pass{stock: ps.stock, ports: ps.ports}
			}
			again[k].addrs = append(again[k].addrs, h.addr)
		}
	}
	if len(keys) > 0 {
		if err := r.acquireNmap(ctx); err != nil {
			return nil, err
		}
	}
	share := r.nmapOptions(nil).MaxRate
	parallel := max(min(len(keys), share), 1)
	second := make([][]nmap.Host, len(keys))
	errs := make([]error, len(keys))
	timeouts := make([]time.Duration, len(keys))
	slots := make(chan struct{}, parallel)
	var calls sync.WaitGroup
	for i, k := range keys {
		ports, addrs := again[k].ports, again[k].addrs
		opts := r.nmapOptions(ports)
		opts.MaxRate = max(share/parallel, 1)
		opts.Standard = !again[k].stock
		opts.StockProbes = again[k].stock
		opts.HostTimeout = min(time.Duration(len(ports))*SecondPassPerPort, SecondPassHostMax)
		if r.HostTimeout > 0 {
			opts.HostTimeout = min(opts.HostTimeout, r.HostTimeout)
		}
		opts.MaxRetries = SecondPassRetries
		timeouts[i] = opts.HostTimeout
		slots <- struct{}{}
		calls.Go(func() {
			defer func() { <-slots }()
			second[i], errs[i] = r.nmapCall(len(addrs)*len(ports), func() ([]nmap.Host, error) {
				return r.Runner.Services(ctx, addrs, slices.Clone(ports), opts)
			})
		})
	}
	calls.Wait()
	if len(keys) > 0 {
		<-r.nmapSem
	}
	for i, k := range keys {
		ports, addrs, svc := again[k].ports, again[k].addrs, second[i]
		if err := errs[i]; err != nil {
			return nil, fmt.Errorf("second service pass: %w", err)
		}
		for _, h := range svc {
			a, ok := scopedAddr(h.Address, inScope)
			l := byAddr[a]
			if !ok || l == nil || !slices.Contains(addrs, a) {
				continue
			}
			if h.TimedOut {
				l.notes = append(l.notes, fmt.Sprintf("second service pass on ports %s timed out after %s, kept the light pass results", nmap.FormatPorts(ports), timeouts[i]))
				continue
			}
			for _, p := range h.Ports {
				proto := strings.ToLower(p.Protocol)
				if (proto != "" && proto != "tcp") || p.State != "open" || !slices.Contains(ports, p.Number) {
					continue
				}
				i := slices.IndexFunc(l.ports, func(q nmap.Port) bool { return q.Number == p.Number })
				switch {
				case i < 0:
				case unconfirmed(l.ports[i]) || !unconfirmed(p):
					l.ports[i] = p
				case l.ports[i].Banner == "":
					l.ports[i].Banner = p.Banner
				}
			}
		}
	}

	results := make([]inventory.HostResult, len(hosts))
	pending := make([][]int, len(hosts))
	sem := make(chan struct{}, HostConcurrency)
	var wg sync.WaitGroup
	each := func(work func(i int, h *live)) error {
		for i, h := range hosts {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				wg.Wait()
				return ctx.Err()
			}
			wg.Go(func() {
				defer func() { <-sem }()
				work(i, h)
			})
		}
		wg.Wait()
		return ctx.Err()
	}
	hostnameOf := func(addr string) string {
		if names := inScope[addr].Hostnames; len(names) > 0 {
			return names[0]
		}
		return ""
	}
	if err := each(func(i int, h *live) {
		svcs, retry := r.services(ctx, h.addr, hostnameOf(h.addr), h.ports)
		results[i] = inventory.HostResult{Address: h.addr, Hostnames: h.hostnames, Services: svcs, Notes: h.notes}
		pending[i] = retry
	}); err != nil {
		return nil, err
	}
	if err := each(func(i int, h *live) {
		if len(pending[i]) == 0 {
			return
		}
		for _, j := range r.probePorts(ctx, results[i].Services, h.ports, pending[i], h.addr, hostnameOf(h.addr)) {
			if schemes, guess := httpSchemes(h.ports[j]); !guess {
				if svc := &results[i].Services[j]; svc.HTTP == nil {
					svc.HTTP = pausedHTTP(h.addr, hostnameOf(h.addr), svc.Port, schemes[0])
				}
			}
		}
	}); err != nil {
		return nil, err
	}
	for i := range results {
		for j := range results[i].Services {
			results[i].Services[j].Detect(r.sigs, nil, false)
		}
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

func pausedHTTP(addr, hostname string, port int, useTLS bool) *probe.HTTP {
	scheme, def := "http", 80
	if useTLS {
		scheme, def = "https", 443
	}
	host := addr
	if hostname != "" {
		host = hostname
	}
	u := url.URL{Scheme: scheme, Host: net.JoinHostPort(host, strconv.Itoa(port)), Path: "/"}
	if port == def {
		u.Host = host
		if strings.Contains(host, ":") {
			u.Host = "[" + host + "]"
		}
	}
	return &probe.HTTP{Scheme: scheme, URL: u.String(), Headers: map[string]string{}, Cookies: []probe.Cookie{},
		RedirectChain: []string{}, Error: probe.ErrorTimeout}
}

type hostGuard struct {
	mu       sync.Mutex
	timeouts int
	paused   bool
}

func (g *hostGuard) isPaused() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.paused
}

func (g *hostGuard) record(timedOut bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !timedOut {
		g.timeouts = 0
		return
	}
	g.timeouts++
	if g.timeouts >= PauseAfterTimeouts {
		g.paused = true
	}
}

func (r *runner) services(ctx context.Context, addr, hostname string, ports []nmap.Port) ([]inventory.ServiceResult, []int) {
	slices.SortFunc(ports, func(a, b nmap.Port) int { return a.Number - b.Number })
	out := make([]inventory.ServiceResult, len(ports))
	var web []int
	for i, p := range ports {
		product, version := identify(p)
		out[i] = inventory.ServiceResult{
			Port:     p.Number,
			Protocol: "tcp",
			State:    p.State,
			Service:  p.Service,
			Product:  product,
			Version:  version,
		}
		if policyPort(p.Number) {
			out[i].Findings = append(out[i].Findings, inventory.Finding{SignatureID: NotProbedID, Kind: "custom", Name: "Not probed by policy", Confidence: 100,
				Evidence: fmt.Sprintf("port %d (%s) is on the never-probe list: no service detection and no HTTP request", p.Number, p.Service)})
		}
		if r.known != nil && !r.known[addr].http[p.Number] {
			continue
		}
		if schemes, _ := httpSchemes(p); len(schemes) > 0 {
			web = append(web, i)
		}
	}
	return out, r.probePorts(ctx, out, ports, web, addr, hostname)
}

func (r *runner) probePorts(ctx context.Context, out []inventory.ServiceResult, ports []nmap.Port, idx []int, addr, hostname string) []int {
	guard := &hostGuard{}
	sem := make(chan struct{}, PerHostConcurrency)
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		pending []int
	)
	for _, i := range idx {
		wg.Go(func() {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			schemes, guess := httpSchemes(ports[i])
			if !r.probe(ctx, &out[i], addr, hostname, schemes, guess, guard) {
				mu.Lock()
				pending = append(pending, i)
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if !guard.isPaused() {
		return nil
	}
	slices.Sort(pending)
	return pending
}

func (r *runner) probe(ctx context.Context, svc *inventory.ServiceResult, addr, hostname string, schemes []bool, guess bool, guard *hostGuard) bool {
	tlsSeen := !guess && schemes[0] && !strings.EqualFold(svc.Service, "ssl")
	var tlsErr error
	defer func() {
		if tlsSeen && tlsErr != nil && ctx.Err() == nil && (svc.HTTP == nil || svc.HTTP.Scheme != "https") {
			h := probe.FailedHTTP(addr, svc.Port, true, hostname, tlsErr)
			svc.HTTP = &h
		}
		if tlsSeen && svc.HTTP != nil && svc.HTTP.Scheme == "https" && svc.HTTP.Error != "" && strings.EqualFold(svc.Service, "https") {
			svc.Service = "http"
		}
	}()
	for _, useTLS := range schemes {
		if guard.isPaused() {
			return false
		}
		prober := r.prober
		if guess {
			prober = r.guessProber
		}
		sess, err := prober.Probe(ctx, addr, svc.Port, useTLS, hostname)
		var te *probe.TimeoutError
		timedOut := errors.As(err, &te)
		if !guess {
			guard.record(timedOut)
		}
		if h, ok := probe.Observed(err); ok && !guess && (svc.HTTP == nil || svc.HTTP.StatusCode == 0 && h.StatusCode != 0) {
			svc.HTTP = &h
		}
		if err != nil {
			if probe.TLSReply(err) {
				tlsSeen = !guess
			}
			if useTLS {
				tlsErr = err
			}
			if guess && !useTLS && !probe.TLSReply(err) {
				return true
			}
			if !guess && !useTLS && (te != nil || svc.HTTP != nil && svc.HTTP.StatusCode != 0) {
				break
			}
			continue
		}
		if guess {
			svc.Service = sess.HTTP.Scheme
		}
		res := r.sigs.Detect(ctx, sess)
		h := sess.HTTP
		svc.HTTP = &h
		svc.Body = slices.Clone(sess.Body[:min(len(sess.Body), inventory.MaxStoredBody)])
		for _, t := range res.Technologies {
			svc.Technologies = append(svc.Technologies, inventory.Technology(t))
		}
		for _, f := range res.Findings {
			svc.Findings = append(svc.Findings, inventory.Finding(f))
		}
		return true
	}
	return svc.HTTP == nil || svc.HTTP.Error != probe.ErrorTimeout
}

func knownHTTP(service string) bool {
	if name := strings.ToLower(service); name == "" || name == "unknown" {
		return false
	}
	schemes, guess := httpSchemes(nmap.Port{Service: service})
	return len(schemes) > 0 && !guess
}

var neverProbeServices = map[string]bool{
	"modbus": true, "mbap": true, "s7comm": true, "iso-tsap": true, "bacnet": true, "dnp": true, "dnp3": true,
	"iec-104": true, "iec-60870-5-104": true, "enip": true, "ethernetip": true, "ethernetip-1": true,
	"ethernetip-2": true, "opc-ua": true, "opcua": true, "opcua-tcp": true, "fins": true, "omron-fins": true,
	"mqtt": true, "secure-mqtt": true, "jetdirect": true, "pdl-datastream": true, "printer": true,
}

var neverProbePorts = map[int]bool{
	102: true, 502: true, 515: true, 789: true, 1911: true, 1962: true, 2222: true, 2404: true, 4840: true, 4911: true,
	5007: true, 9100: true, 9101: true, 9102: true, 9103: true, 9600: true, 18245: true, 18246: true, 20000: true,
	20547: true, 34962: true, 34963: true, 34964: true, 44818: true, 47808: true,
}

var neverProbeTablePorts = map[int]string{
	1883: "mqtt", 8883: "secure-mqtt", 9104: "jetdirect", 9105: "jetdirect", 9106: "jetdirect", 9107: "jetdirect",
}

func policyPort(n int) bool {
	return neverProbePorts[n] || neverProbeTablePorts[n] != ""
}

func neverProbe(p nmap.Port) bool {
	return neverProbeServices[strings.ToLower(p.Service)] || policyPort(p.Number)
}

func unconfirmed(p nmap.Port) bool {
	switch strings.ToLower(p.Service) {
	case "", "unknown", "tcpwrapped":
		return true
	}
	return p.Guessed
}

func httpSchemes(p nmap.Port) (schemes []bool, guess bool) {
	name := strings.ToLower(p.Service)
	switch {
	case neverProbe(p):
		return nil, false
	case strings.ToLower(p.Tunnel) == "ssl" && strings.Contains(name, "http"), name == "https", name == "ssl", strings.HasPrefix(name, "https-"):
		return []bool{true}, false
	case strings.Contains(name, "http"):
		return []bool{false, true}, false
	case unconfirmed(p):
		if strings.ToLower(p.Tunnel) == "ssl" {
			return []bool{true}, true
		}
		return []bool{false, true}, true
	}
	return nil, false
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
