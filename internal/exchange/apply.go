package exchange

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"asi/internal/detect"
	"asi/internal/diff"
	"asi/internal/inventory"
)

var ErrNothingToImport = errors.New("exchange: no valid rows to import")

type Options struct {
	Name              string
	Source            inventory.RunSource
	InactiveAfter     int
	DryRun            bool
	Signatures        *detect.Set
	ReplaceUserFields bool
	KeepStored        bool
	Actor             inventory.Editor
}

const (
	AuditImport = "import"
	AuditEntry  = "host.entry"
)

type Report struct {
	Run         string     `json:"run"`
	DryRun      bool       `json:"dry_run"`
	Hosts       int        `json:"hosts"`
	Services    int        `json:"services"`
	Errors      []RowError `json:"errors"`
	Invalid     int        `json:"invalid"`
	Skipped     int        `json:"skipped"`
	NewHosts    int        `json:"new_hosts"`
	NewServices int        `json:"new_services"`
	Changes     diff.Diff  `json:"changes"`
}

func Apply(ctx context.Context, inv *inventory.Inventory, b Batch, opts Options) (Report, error) {
	if opts.Source == "" {
		opts.Source = inventory.SourceImport
	}
	if opts.InactiveAfter <= 0 {
		opts.InactiveAfter = inventory.DefaultInactiveAfter
		latest, err := inv.RunByName(ctx, "")
		switch {
		case err == nil:
			opts.InactiveAfter = latest.InactiveAfter
		case !errors.Is(err, inventory.ErrUnknownRun):
			return Report{Run: opts.Name, DryRun: opts.DryRun}, fmt.Errorf("inactive threshold of the latest run: %w", err)
		}
	}
	if opts.Name == "" {
		opts.Name = string(opts.Source) + "-" + time.Now().UTC().Format("20060102T150405.000000Z")
	}
	rep := Report{Run: opts.Name, DryRun: opts.DryRun, Errors: b.Errors, Invalid: max(b.Invalid, len(b.Errors))}
	if rep.Errors == nil {
		rep.Errors = []RowError{}
	}
	if len(b.Entries) == 0 {
		return rep, ErrNothingToImport
	}
	before, err := inv.Export(ctx, "")
	if err != nil {
		return rep, err
	}
	stored := map[string]inventory.ExportHost{}
	for _, h := range before.Hosts {
		stored[h.Address] = h
	}
	hosts := make([]inventory.HostResult, 0, len(b.Entries))
	addrs := make([]string, 0, len(b.Entries))
	kept := make([]Entry, 0, len(b.Entries))
	for _, e := range b.Entries {
		old, known := stored[e.Host.Address]
		if e.staleHost && known {
			rep.Skipped++
			continue
		}
		h := e.Host
		h.Services = nil
		for _, s := range e.Host.Services {
			if known && e.staleSvc[serviceKey(s.Port, s.Protocol)] &&
				slices.ContainsFunc(old.Services, func(o inventory.ExportService) bool { return o.Port == s.Port && o.Protocol == s.Protocol }) {
				rep.Skipped++
				continue
			}
			stated := e.statedSvc[serviceKey(s.Port, s.Protocol)]
			if known && opts.KeepStored {
				var same bool
				s, same = keepStored(s, old)
				stated = stated || same
			}
			if !slices.ContainsFunc(old.Services, func(o inventory.ExportService) bool { return o.Port == s.Port && o.Protocol == s.Protocol }) {
				rep.NewServices++
			}
			s.Detect(opts.Signatures, s.HTTP, stated)
			h.Services = append(h.Services, s)
		}
		if !known {
			rep.NewHosts++
		}
		kept = append(kept, e)
		hosts = append(hosts, h)
		addrs = append(addrs, h.Address)
		rep.Hosts++
		rep.Services += len(h.Services)
	}
	if len(hosts) == 0 {
		return rep, ErrNothingToImport
	}
	if opts.DryRun {
		rep.Changes = diff.Compute(before, simulate(before, opts.Name, hosts, opts.InactiveAfter), diff.Options{})
		return rep, nil
	}
	run, err := inv.CreateRun(ctx, inventory.RunSpec{Name: opts.Name, InactiveAfter: opts.InactiveAfter, Source: opts.Source,
		Settings: inventory.RunSettings{Targets: addrs}})
	if err != nil {
		return rep, err
	}
	if err := inv.RecordGroup(ctx, run.ID, inventory.GroupResult{Index: 0, Addresses: addrs, Hosts: hosts}); err != nil {
		return rep, errors.Join(err, inv.SetRunStatus(ctx, run.ID, inventory.RunFailed))
	}
	for _, e := range kept {
		if err := applyUserFields(ctx, inv, e, opts.ReplaceUserFields); err != nil {
			return rep, errors.Join(err, inv.SetRunStatus(ctx, run.ID, inventory.RunFailed))
		}
	}
	if err := inv.SetRunStatus(ctx, run.ID, inventory.RunCompleted); err != nil {
		return rep, err
	}
	action, target := AuditImport, run.Name
	if opts.Source == inventory.SourceManual {
		action, target = AuditEntry, strings.Join(addrs, ",")
	}
	if err := inv.Audit(ctx, opts.Actor, action, target); err != nil {
		return rep, err
	}
	after, err := inv.Export(ctx, run.Name)
	if err != nil {
		return rep, err
	}
	rep.Changes = diff.Compute(before, after, diff.Options{})
	return rep, nil
}

func keepStored(s inventory.ServiceResult, old inventory.ExportHost) (inventory.ServiceResult, bool) {
	i := slices.IndexFunc(old.Services, func(o inventory.ExportService) bool { return o.Port == s.Port && o.Protocol == s.Protocol })
	if i < 0 {
		return s, false
	}
	o := old.Services[i]
	s.State = o.State
	if s.HTTP != nil && o.HTTP != nil {
		h := *o.HTTP
		h.Scheme, h.StatusCode, h.Title = s.HTTP.Scheme, s.HTTP.StatusCode, s.HTTP.Title
		s.HTTP = &h
	}
	s.Technologies, s.Findings = slices.Clone(s.Technologies), slices.Clone(s.Findings)
	for j, t := range s.Technologies {
		if k := slices.IndexFunc(o.Technologies, func(x inventory.Technology) bool {
			return strings.EqualFold(x.Name, t.Name) && x.Version == t.Version
		}); k >= 0 {
			s.Technologies[j] = o.Technologies[k]
		}
	}
	for j, f := range s.Findings {
		if k := slices.IndexFunc(o.Findings, func(x inventory.Finding) bool { return x.SignatureID == f.SignatureID }); k >= 0 {
			s.Findings[j] = o.Findings[k]
		}
	}
	return s, s.Product == o.Product && s.Version == o.Version
}

func applyUserFields(ctx context.Context, inv *inventory.Inventory, e Entry, replace bool) error {
	cur, err := inv.GetHostUserFields(ctx, e.Host.Address)
	if err != nil {
		return err
	}
	next := cur
	if replace {
		next.Tags, next.Notes = e.User.Tags, e.User.Notes
	} else {
		next.Tags = union(cur.Tags, e.User.Tags)
		next.Notes = fill(cur.Notes, e.User.Notes)
		next.DisplayName = fill(cur.DisplayName, e.User.DisplayName)
		next.Owner = fill(cur.Owner, e.User.Owner)
		next.Criticality = fill(cur.Criticality, e.User.Criticality)
		next.StatusOverride = fill(cur.StatusOverride, e.User.StatusOverride)
	}
	next.Tags = union(nil, next.Tags)
	if slices.Equal(next.Tags, cur.Tags) && next.Notes == cur.Notes && next.DisplayName == cur.DisplayName &&
		next.Owner == cur.Owner && next.Criticality == cur.Criticality && next.StatusOverride == cur.StatusOverride {
		return nil
	}
	if err := inv.UpdateHostUserFields(ctx, e.Host.Address, next); err != nil {
		return fmt.Errorf("host %s: %w", e.Host.Address, err)
	}
	return nil
}

func fill(cur, v string) string {
	if cur != "" {
		return cur
	}
	return v
}

func simulate(before inventory.Export, name string, hosts []inventory.HostResult, n int) inventory.Export {
	after := before
	after.Run = name
	after.Source = ""
	after.Hosts = slices.Clone(before.Hosts)
	index := map[string]int{}
	for i, h := range after.Hosts {
		index[h.Address] = i
	}
	for _, h := range hosts {
		next := inventory.ExportHost{Address: h.Address, Hostnames: h.Hostnames, Status: inventory.StatusActive, Stability: 1}
		seen := map[string]bool{}
		for _, s := range h.Services {
			seen[fmt.Sprintf("%d/%s", s.Port, s.Protocol)] = true
			next.Services = append(next.Services, inventory.ExportService{Port: s.Port, Protocol: s.Protocol, State: s.State,
				Status: inventory.StatusActive, Service: s.Service, Product: s.Product, Version: s.Version, HTTP: s.HTTP,
				Technologies: s.Technologies, Findings: s.Findings, Stability: 1})
		}
		i, ok := index[h.Address]
		if !ok {
			index[h.Address] = len(after.Hosts)
			after.Hosts = append(after.Hosts, next)
			continue
		}
		for _, s := range after.Hosts[i].Services {
			if seen[fmt.Sprintf("%d/%s", s.Port, s.Protocol)] {
				continue
			}
			s.MissedRuns++
			if s.Status == inventory.StatusInactive || s.MissedRuns >= n {
				s.Status = inventory.StatusInactive
			} else {
				s.Status = inventory.StatusUnstable
			}
			next.Services = append(next.Services, s)
		}
		next.Tags, next.Notes = after.Hosts[i].Tags, after.Hosts[i].Notes
		after.Hosts[i] = next
	}
	return after
}

type Filter struct {
	Status string
	Query  string
	Tag    string
}

func (f Filter) Apply(exp inventory.Export) inventory.Export {
	q := strings.ToLower(strings.TrimSpace(f.Query))
	out := exp
	out.Hosts = []inventory.ExportHost{}
	for _, h := range exp.Hosts {
		if f.Status != "" && string(h.Status) != f.Status {
			continue
		}
		if f.Tag != "" && !slices.Contains(h.Tags, f.Tag) {
			continue
		}
		if q != "" && !strings.Contains(h.Address, q) && !slices.ContainsFunc(h.Hostnames, func(n string) bool {
			return strings.Contains(strings.ToLower(n), q)
		}) {
			continue
		}
		out.Hosts = append(out.Hosts, h)
	}
	return out
}
