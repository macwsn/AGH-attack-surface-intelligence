package inventory

import (
	"context"
	"fmt"
	"math"
	"slices"
	"time"
)

func (inv *Inventory) Export(ctx context.Context, asOfRun string) (Export, error) {
	run, hosts, err := inv.state(ctx, asOfRun)
	if err != nil {
		return Export{}, fmt.Errorf("export: %w", err)
	}
	for i := range hosts {
		hosts[i].InterestScore, _ = Score(hosts[i], run.StartedAt, inv.Interest)
	}
	return Export{
		Schema:          ExportSchema,
		GeneratedAt:     time.Now().UTC().Truncate(time.Second),
		Run:             run.Name,
		Source:          run.Source,
		Hosts:           hosts,
		VolatileHeaders: append(slices.Clone(inv.VolatileHeaders), run.Settings.VolatileHeaders...),
		RunStartedAt:    run.StartedAt,
	}, nil
}

func (inv *Inventory) Report(ctx context.Context, asOfRun string) (Export, error) {
	exp, err := inv.Export(ctx, asOfRun)
	if err != nil {
		return Export{}, err
	}
	for i := range exp.Hosts {
		for j := range exp.Hosts[i].Services {
			exp.Hosts[i].Services[j].Technologies = Reported(exp.Hosts[i].Services[j].Technologies, exp.Hosts[i].Stability)
		}
	}
	return exp, nil
}

func Reported(techs []Technology, stability float64) []Technology {
	out := slices.Clone(techs)
	for i := range out {
		raw := out[i].Confidence
		out[i].Confidence, out[i].ConfidenceRaw = int(math.Round(float64(raw)*stability)), &raw
	}
	return out
}
