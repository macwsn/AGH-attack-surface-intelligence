package scan

import (
	"time"

	"asi/internal/inventory"
)

type Progress struct {
	AddressesTotal     int
	AddressesDone      int
	GroupsDone         int
	GroupsFailed       int
	GroupsTotal        int
	AddressesPerSecond float64
	Remaining          time.Duration
	RemainingKnown     bool
}

func RunProgress(run inventory.Run, groups []inventory.GroupInfo, failed []inventory.FailedGroup) Progress {
	p := Progress{AddressesTotal: run.AddressTotal, GroupsDone: len(groups), GroupsFailed: len(failed)}
	var (
		scanned time.Duration
		last    inventory.GroupInfo
	)
	for _, g := range groups {
		p.AddressesDone += g.AddressCount
		scanned += g.Duration
		if last.AddressCount == 0 || g.CompletedAt.After(last.CompletedAt) {
			last = g
		}
	}
	measured := p.AddressesDone
	for _, g := range failed {
		p.AddressesDone += len(g.Addresses)
	}
	workers := run.Settings.Workers
	if workers < 1 {
		workers = DefaultWorkers
	}
	if scanned > 0 {
		p.AddressesPerSecond = float64(measured) / scanned.Seconds() * float64(workers)
	}
	left := max(p.AddressesTotal-p.AddressesDone, 0)
	if run.Status == inventory.RunCompleted {
		left = 0
	}
	known := run.Status == inventory.RunCompleted || p.AddressesTotal > 0
	size := run.Settings.GroupSize
	if size < 1 {
		size = last.AddressCount
	}
	if size < 1 {
		size = InitialGroupSize
	}
	p.GroupsTotal = p.GroupsDone + p.GroupsFailed + (left+size-1)/size
	switch {
	case !known:
	case left == 0:
		p.RemainingKnown = true
	case p.AddressesPerSecond > 0:
		p.Remaining = time.Duration(float64(left) / p.AddressesPerSecond * float64(time.Second))
		p.RemainingKnown = true
	}
	return p
}

func (p Progress) ETA() string {
	if !p.RemainingKnown {
		return "-"
	}
	return p.Remaining.Round(time.Second).String()
}
