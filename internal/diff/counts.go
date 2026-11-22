package diff

import (
	"context"
	"errors"

	"asi/internal/inventory"
)

const ChartRuns = 20

type RunCounts struct {
	From    string
	To      string
	New     int
	Missing int
	Changed int
}

func Count(d Diff) RunCounts {
	c := RunCounts{From: d.From, To: d.To}
	for _, ch := range d.Changes {
		switch ch.Type {
		case HostNew, ServiceNew, HostReturned, ServiceReturned:
			c.New++
		case HostMissing, ServiceMissing, HostInactive, ServiceInactive:
			c.Missing++
		case ServiceChanged:
			c.Changed++
		}
	}
	return c
}

func Series(ctx context.Context, src Exporter, runs []string, limit int, opts Options) ([]RunCounts, error) {
	if limit > 0 && len(runs) > limit+1 {
		runs = runs[len(runs)-limit-1:]
	}
	series := []RunCounts{}
	var prev inventory.Export
	for i, name := range runs {
		exp, err := src.Export(ctx, name)
		if errors.Is(err, inventory.ErrUnknownRun) {
			return nil, &UnknownRunError{Name: name}
		}
		if err != nil {
			return nil, err
		}
		if i > 0 {
			series = append(series, Count(Compute(prev, exp, opts)))
		}
		prev = exp
	}
	return series, nil
}
