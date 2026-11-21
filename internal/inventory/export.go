package inventory

import (
	"context"
	"fmt"
	"time"
)

func (inv *Inventory) Export(ctx context.Context, asOfRun string) (Export, error) {
	run, hosts, err := inv.state(ctx, asOfRun)
	if err != nil {
		return Export{}, fmt.Errorf("export: %w", err)
	}
	return Export{
		Schema:      ExportSchema,
		GeneratedAt: time.Now().UTC().Truncate(time.Second),
		Run:         run.Name,
		Hosts:       hosts,
	}, nil
}
