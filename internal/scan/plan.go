package scan

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"asi/internal/inventory"
	"asi/internal/probe"
	"asi/internal/targets"
)

const (
	DiscoveryTries       = 2
	ServiceProbesPerPort = 10
	RequestsPerPort      = 2*(2+probe.MaxExtraRequests)*(1+probe.MaxRedirects) + 2
	DefaultLiveShare     = 0.05
	MeasuredLow          = 0.8
	MeasuredHigh         = 1.25
)

var ErrTooMuchWork = errors.New("too much work for one run")

func CheckWork(st inventory.RunSettings) error {
	include, err := targets.ParseHosts(strings.NewReader(strings.Join(st.Targets, "\n")))
	if err != nil {
		return nil
	}
	exclude, err := targets.ParseHosts(strings.NewReader(strings.Join(st.Excludes, "\n")))
	if err != nil {
		return nil
	}
	ports, err := normalizePorts(st.Ports)
	if err != nil {
		return nil
	}
	ceiling := st.MaxWork
	if ceiling == 0 {
		ceiling = DefaultMaxWork
	}
	n, p := targets.Count(include, exclude), uint64(len(ports))
	if n*p > ceiling {
		return fmt.Errorf("%w: the targets expand to %d addresses x %d ports = %d address-ports, more than the ceiling of %d; split the targets or the ports", ErrTooMuchWork, n, p, n*p, ceiling)
	}
	return nil
}

func DiscoveryPackets(addresses, ports int) int {
	return addresses * (1 + ports) * DiscoveryTries
}

func ServicePackets(addresses, ports int) int {
	return addresses * ports * ServiceProbesPerPort
}

type Plan struct {
	Addresses    int
	Ports        []int
	GroupSize    int
	Groups       int
	Packets      int64
	Requests     int64
	MaxRate      int
	Adaptive     bool
	AtMaxRate    time.Duration
	MeasuredRate float64
	AtMeasured   time.Duration
	Slots        int
	MinRate      int
	Recheck      bool
	Base         string
	Services     int
	LiveShare    float64
	EstimateLow  time.Duration
	EstimateHigh time.Duration
}

func (p Plan) MeasuredKnown() bool { return p.MeasuredRate > 0 }

func (s *Scanner) Plan(ctx context.Context, st inventory.RunSettings) (Plan, error) {
	return s.PlanRun(ctx, inventory.Run{Settings: st})
}

func (s *Scanner) PlanRun(ctx context.Context, run inventory.Run) (Plan, error) {
	st := run.Settings
	if err := CheckWork(st); err != nil {
		return Plan{}, fmt.Errorf("settings: %w", err)
	}
	rate, err := maxRateOf(st)
	if err != nil {
		return Plan{}, err
	}
	set, ports, err := s.expand(ctx, st)
	if err != nil {
		return Plan{}, err
	}
	p := Plan{Ports: ports, MaxRate: rate, Adaptive: !st.NoAdaptive, GroupSize: InitialGroupSize, Recheck: st.Recheck()}
	if p.Recheck {
		base, known, order, err := s.planRecheck(ctx, run, set)
		if err != nil {
			return Plan{}, err
		}
		p.Base, p.Services, p.Addresses = base.Name, len(known), len(order)
		perHost := map[string]int{}
		p.Ports = nil
		for _, k := range known {
			perHost[k.Address]++
			if !slices.Contains(p.Ports, k.Port) {
				p.Ports = append(p.Ports, k.Port)
			}
			if k.HTTP || knownHTTP(k.Service) {
				p.Requests += RequestsPerPort
			}
		}
		slices.Sort(p.Ports)
		for _, n := range perHost {
			p.Packets += int64(DiscoveryPackets(1, n)) + int64(ServicePackets(1, n))
		}
	} else {
		for range set.All() {
			p.Addresses++
		}
		p.Packets = int64(DiscoveryPackets(p.Addresses, len(ports))) + int64(ServicePackets(p.Addresses, len(ports)))
		p.Requests = int64(p.Addresses) * int64(len(ports)) * RequestsPerPort
	}
	if st.GroupSize > 0 {
		p.GroupSize = st.GroupSize
	}
	p.Groups = (p.Addresses + p.GroupSize - 1) / p.GroupSize
	p.Slots = NmapSlots(st.Workers, rate, p.Addresses)
	p.MinRate = rate
	if p.Adaptive {
		p.MinRate = MinimumRate(rate, p.Slots)
	}
	nmapRate, httpRate := rate/2, rate-rate/2
	p.AtMaxRate = max(seconds(float64(p.Packets)/float64(nmapRate)), seconds(float64(p.Requests)/float64(httpRate)))
	p.LiveShare = DefaultLiveShare
	p.estimate()
	return p, nil
}

func (p *Plan) Measured(addressesPerSecond float64) {
	if addressesPerSecond <= 0 {
		return
	}
	p.MeasuredRate = addressesPerSecond
	p.AtMeasured = seconds(float64(p.Addresses) / addressesPerSecond)
	p.estimate()
}

func (p *Plan) UseLiveShare(share float64) {
	if share <= 0 || share > 1 {
		return
	}
	p.LiveShare = share
	p.estimate()
}

func (p *Plan) estimate() {
	if p.MeasuredKnown() {
		p.EstimateLow = seconds(p.AtMeasured.Seconds() * MeasuredLow)
		p.EstimateHigh = seconds(p.AtMeasured.Seconds() * MeasuredHigh)
		return
	}
	if p.MaxRate < 1 {
		return
	}
	ports := len(p.Ports)
	live := func(share float64) int { return int(math.Ceil(float64(p.Addresses) * min(share, 1))) }
	rate := float64(p.MaxRate)
	nmapRate, httpRate := float64(max(p.MaxRate/2, 1)), float64(max(p.MaxRate-p.MaxRate/2, 1))
	low := live(p.LiveShare)
	lowPackets := p.Addresses*(1+ports) + ServicePackets(low, ports)
	p.EstimateLow = max(seconds(float64(lowPackets)/rate), seconds(float64(low*ports*2)/rate))
	high := live(2 * p.LiveShare)
	highPackets := DiscoveryPackets(p.Addresses, ports) + ServicePackets(high, ports)
	highRequests := high * ports * 2 * (1 + probe.MaxExtraRequests)
	p.EstimateHigh = max(seconds(float64(highPackets)/nmapRate), seconds(float64(highRequests)/httpRate))
}

func seconds(s float64) time.Duration {
	return time.Duration(s * float64(time.Second)).Round(time.Second)
}
