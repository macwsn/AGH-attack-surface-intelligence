package schedule

import (
	"net/netip"
	"slices"
	"sort"
	"time"

	"asi/internal/inventory"
)

const UnseenRecheckAfter = 24 * time.Hour

type RecheckHost struct {
	Address      string
	Availability inventory.Availability
	LastSeen     time.Time
	LastCovered  time.Time
}

func PickRecheck(now time.Time, period time.Duration, hosts []RecheckHost) []string {
	hour := now.Hour()
	var first, rest []string
	for _, h := range hosts {
		if now.Sub(h.LastCovered) < period {
			continue
		}
		switch h.Availability.Expected(hour) {
		case inventory.ExpectedUp:
			first = append(first, h.Address)
		case inventory.ExpectedDown:
			if now.Sub(h.LastSeen) >= UnseenRecheckAfter {
				rest = append(rest, h.Address)
			}
		default:
			rest = append(rest, h.Address)
		}
	}
	sort.SliceStable(first, func(a, b int) bool { return addressLess(first[a], first[b]) })
	sort.SliceStable(rest, func(a, b int) bool { return addressLess(rest[a], rest[b]) })
	return append(first, rest...)
}

func addressLess(a, b string) bool {
	x, errA := netip.ParseAddr(a)
	y, errB := netip.ParseAddr(b)
	if errA != nil || errB != nil {
		return a < b
	}
	return x.Less(y)
}

func recheckHosts(hosts []inventory.ExportHost, ports []int) []RecheckHost {
	var out []RecheckHost
	for _, h := range hosts {
		known := slices.ContainsFunc(h.Services, func(s inventory.ExportService) bool {
			return s.Protocol == "tcp" && (s.Status == inventory.StatusActive || s.Status == inventory.StatusUnstable) &&
				(len(ports) == 0 || slices.Contains(ports, s.Port))
		})
		if !known {
			continue
		}
		out = append(out, RecheckHost{Address: h.Address, Availability: h.Availability.Profile(),
			LastSeen: h.LastSeen, LastCovered: h.LastCovered})
	}
	return out
}
