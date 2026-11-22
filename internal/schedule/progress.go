package schedule

import (
	"time"

	"asi/internal/inventory"
)

type Progress struct {
	Total   int
	Done    int
	Groups  int
	Hosts   int
	Busy    time.Duration
	Percent int
	Left    time.Duration
	HasLeft bool
}

func ProgressOf(total, workers int, groups []inventory.GroupInfo) Progress {
	p := Progress{Total: total, Groups: len(groups)}
	for _, g := range groups {
		p.Done += g.AddressCount
		p.Hosts += g.HostsFound
		p.Busy += g.Duration
	}
	if total > 0 {
		p.Percent = min(100, p.Done*100/total)
	}
	if p.Done > 0 && p.Busy > 0 && total > p.Done {
		workers = max(workers, 1)
		perAddr := float64(p.Busy) / float64(p.Done)
		p.Left = time.Duration(perAddr * float64(total-p.Done) / float64(workers)).Round(time.Second)
		p.HasLeft = true
	}
	return p
}

func (p Progress) WithInFlight(n int) Progress {
	if n <= 0 || p.Total <= p.Done {
		return p
	}
	p.Done = min(p.Done+n, p.Total)
	p.Percent = min(100, p.Done*100/p.Total)
	return p
}
