package scantest

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"sync"
	"time"

	"asi/internal/inventory"
)

type Clock struct {
	mu  sync.Mutex
	now time.Time
}

func NewClock(start time.Time) *Clock { return &Clock{now: start} }

func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *Clock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if t := c.now.Add(d); t.After(c.now) {
		c.now = t
	}
	ch := make(chan time.Time, 1)
	ch <- c.now
	return ch
}

type Request struct {
	Target string
	Method string
	URL    string
	Time   time.Time
}

type Transport struct {
	Handler http.Handler
	Clock   interface{ Now() time.Time }
	Hold    chan struct{}

	mu          sync.Mutex
	requests    []Request
	inFlight    map[string]int
	maxInFlight map[string]int
	total       int
	maxTotal    int
}

func (t *Transport) For(target string) http.RoundTripper {
	return roundTripper{t: t, target: target}
}

func (t *Transport) Requests() []Request {
	t.mu.Lock()
	defer t.mu.Unlock()
	return slices.Clone(t.requests)
}

func (t *Transport) InFlight(target string) (now, peak int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.inFlight[target], t.maxInFlight[target]
}

func (t *Transport) TotalInFlight() (now, peak int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.total, t.maxTotal
}

type roundTripper struct {
	t      *Transport
	target string
}

func (rt roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	t := rt.t
	host := hostOf(rt.target)
	t.mu.Lock()
	if t.inFlight == nil {
		t.inFlight, t.maxInFlight = map[string]int{}, map[string]int{}
	}
	r := Request{Target: rt.target, Method: req.Method, URL: req.URL.String()}
	if t.Clock != nil {
		r.Time = t.Clock.Now()
	}
	t.requests = append(t.requests, r)
	t.inFlight[host]++
	t.maxInFlight[host] = max(t.maxInFlight[host], t.inFlight[host])
	t.total++
	t.maxTotal = max(t.maxTotal, t.total)
	t.mu.Unlock()
	defer func() {
		t.mu.Lock()
		t.inFlight[host]--
		t.total--
		t.mu.Unlock()
	}()
	if t.Hold != nil {
		select {
		case <-t.Hold:
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	}
	h := t.Handler
	if h == nil {
		h = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, "<title>ok</title>")
		})
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req.Clone(context.WithValue(req.Context(), targetKey{}, rt.target)))
	if err := req.Context().Err(); err != nil {
		return nil, err
	}
	resp := rec.Result()
	resp.Request = req
	return resp, nil
}

type targetKey struct{}

func Target(r *http.Request) string {
	s, _ := r.Context().Value(targetKey{}).(string)
	return s
}

func hostOf(target string) string {
	for i := len(target) - 1; i >= 0; i-- {
		if target[i] == ':' {
			return target[:i]
		}
	}
	return target
}

type Store struct {
	Prev           []string
	Known          []inventory.KnownService
	Favicons       map[inventory.FaviconKey]string
	OnRecordGroup  func(g inventory.GroupResult) error
	OnSetStatus    func(status inventory.RunStatus) error
	AfterRecording func(g inventory.GroupResult)

	mu         sync.Mutex
	groups     map[int]inventory.GroupResult
	failed     map[int]inventory.FailedGroup
	late       [][]inventory.HostResult
	statuses   []inventory.RunStatus
	total      int
	heartbeats int
	inFlight   []int
	rates      map[time.Time]inventory.RateSample
	packets    int
}

func (s *Store) RecordRateSamples(ctx context.Context, _ int64, samples []inventory.RateSample) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rates == nil {
		s.rates = map[time.Time]inventory.RateSample{}
	}
	for _, r := range samples {
		cur, ok := s.rates[r.Minute]
		if ok {
			r.Effective = max(r.Effective, cur.Effective)
			r.Sent += cur.Sent
			r.Packets += cur.Packets
		}
		s.rates[r.Minute] = r
	}
	return nil
}

func (s *Store) RateSamples() []inventory.RateSample {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]inventory.RateSample, 0, len(s.rates))
	for _, r := range s.rates {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Minute.Before(out[j].Minute) })
	return out
}

func (s *Store) RecordGroup(ctx context.Context, _ int64, g inventory.GroupResult) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.OnRecordGroup != nil {
		if err := s.OnRecordGroup(g); err != nil {
			return err
		}
	}
	s.mu.Lock()
	if s.groups == nil {
		s.groups = map[int]inventory.GroupResult{}
	}
	s.groups[g.Index] = g
	s.mu.Unlock()
	if s.AfterRecording != nil {
		s.AfterRecording(g)
	}
	return nil
}

func (s *Store) RecordLateHosts(ctx context.Context, _ int64, hosts []inventory.HostResult) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.late = append(s.late, hosts)
	return nil
}

func (s *Store) RunGroups(_ context.Context, _ int64) ([]inventory.GroupInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []inventory.GroupInfo{}
	for _, g := range s.groups {
		addrs := slices.Clone(g.Addresses)
		sort.Strings(addrs)
		out = append(out, inventory.GroupInfo{Index: g.Index, Addresses: addrs, AddressCount: len(addrs), HostsFound: len(g.Hosts), Duration: g.Duration})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out, nil
}

func (s *Store) RecordFailedGroup(ctx context.Context, _ int64, g inventory.FailedGroup) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed == nil {
		s.failed = map[int]inventory.FailedGroup{}
	}
	g.Addresses = slices.Clone(g.Addresses)
	s.failed[g.Index] = g
	return nil
}

func (s *Store) FailedGroups(context.Context, int64) ([]inventory.FailedGroup, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []inventory.FailedGroup{}
	for _, g := range s.failed {
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out, nil
}

func (s *Store) SetRunTotal(_ context.Context, _ int64, total int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.total = total
	return nil
}

func (s *Store) AddressTotal() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.total
}

func (s *Store) SetRunStatus(_ context.Context, _ int64, status inventory.RunStatus) error {
	if s.OnSetStatus != nil {
		if err := s.OnSetStatus(status); err != nil {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.statuses = append(s.statuses, status)
	return nil
}

func (s *Store) Heartbeat(_ context.Context, _ int64, inFlight int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.heartbeats++
	s.inFlight = append(s.inFlight, inFlight)
	return nil
}

func (s *Store) InFlight() []int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.inFlight)
}

func (s *Store) Heartbeats() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.heartbeats
}

func (s *Store) Total() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.total
}

func (s *Store) PreviouslyLiveAddresses(context.Context, int64) ([]string, error) {
	return slices.Clone(s.Prev), nil
}

func (s *Store) PreviousFavicons(context.Context, int64) (map[inventory.FaviconKey]string, error) {
	return maps.Clone(s.Favicons), nil
}

func (s *Store) Export(_ context.Context, run string) (inventory.Export, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := inventory.Export{Schema: inventory.ExportSchema, Run: run, Hosts: []inventory.ExportHost{}}
	for _, h := range s.hosts() {
		e.Hosts = append(e.Hosts, inventory.ExportHost{Address: h.Address, Hostnames: h.Hostnames, Status: inventory.StatusActive})
	}
	return e, nil
}

func (s *Store) Groups() []inventory.GroupResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]inventory.GroupResult, 0, len(s.groups))
	for _, g := range s.groups {
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out
}

func (s *Store) Late() [][]inventory.HostResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.late)
}

func (s *Store) Statuses() []inventory.RunStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.statuses)
}

func (s *Store) Hosts() []inventory.HostResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hosts()
}

func (s *Store) hosts() []inventory.HostResult {
	var out []inventory.HostResult
	for _, g := range s.groups {
		out = append(out, g.Hosts...)
	}
	for _, l := range s.late {
		out = append(out, l...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Address < out[j].Address })
	return out
}

func (s *Store) AddRunPackets(_ context.Context, _ int64, packets int) error {
	if packets < 0 {
		return fmt.Errorf("negative packet count %d", packets)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.packets += packets
	return nil
}

func (s *Store) Packets() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.packets
}

func (s *Store) RecheckPlan(_ context.Context, run inventory.Run, inScope func(string) bool) (inventory.Run, []inventory.KnownService, error) {
	order := map[string]int{}
	for i, a := range run.Settings.Hosts {
		if _, dup := order[a]; !dup {
			order[a] = i
		}
	}
	var out []inventory.KnownService
	for _, k := range s.Known {
		if inScope != nil && !inScope(k.Address) {
			continue
		}
		if len(run.Settings.Ports) > 0 && !slices.Contains(run.Settings.Ports, k.Port) {
			continue
		}
		if _, ok := order[k.Address]; len(order) > 0 && !ok {
			continue
		}
		out = append(out, k)
	}
	sort.SliceStable(out, func(a, b int) bool { return order[out[a].Address] < order[out[b].Address] })
	if len(out) == 0 {
		return inventory.Run{}, nil, fmt.Errorf("recheck base: %w", inventory.ErrNoRecheckBase)
	}
	return inventory.Run{Name: "base", Status: inventory.RunCompleted}, out, nil
}
