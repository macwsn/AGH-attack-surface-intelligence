package diff

import (
	"net/netip"
	"slices"
	"sort"
	"strings"

	"asi/internal/inventory"
)

const Schema = "asi.diff/v1"

const (
	HostNew         = "host_new"
	HostMissing     = "host_missing"
	HostReturned    = "host_returned"
	HostInactive    = "host_inactive"
	ServiceNew      = "service_new"
	ServiceMissing  = "service_missing"
	ServiceReturned = "service_returned"
	ServiceInactive = "service_inactive"
	ServiceChanged  = "service_changed"
)

var DefaultVolatileHeaders = inventory.DefaultVolatileHeaders

type Options struct {
	VolatileHeaders []string
}

type Diff struct {
	Schema  string   `json:"schema"`
	From    string   `json:"from"`
	To      string   `json:"to"`
	Changes []Change `json:"changes"`
}

type Change struct {
	Type     string        `json:"type"`
	Address  string        `json:"address"`
	Port     *int          `json:"port,omitempty"`
	Protocol string        `json:"protocol,omitempty"`
	Fields   []FieldChange `json:"fields,omitempty"`
	Note     string        `json:"note,omitempty"`
}

type FieldChange struct {
	Field string `json:"field"`
	Old   any    `json:"old"`
	New   any    `json:"new"`
}

type statusTypes struct {
	isNew, missing, returned, inactive string
}

var (
	hostTypes    = statusTypes{HostNew, HostMissing, HostReturned, HostInactive}
	serviceTypes = statusTypes{ServiceNew, ServiceMissing, ServiceReturned, ServiceInactive}
)

const ExpectedUpNote = "expected up at this hour"

func Compute(from, to inventory.Export, opts Options) Diff {
	volatile := map[string]bool{}
	for _, h := range DefaultVolatileHeaders {
		volatile[h] = true
	}
	for _, h := range slices.Concat(opts.VolatileHeaders, from.VolatileHeaders, to.VolatileHeaders) {
		volatile[strings.ToLower(strings.TrimSpace(h))] = true
	}

	fromHosts := make(map[string]inventory.ExportHost, len(from.Hosts))
	for _, h := range from.Hosts {
		fromHosts[h.Address] = h
	}

	changes := []Change{}
	for _, th := range to.Hosts {
		if to.Source == inventory.SourceScan && !th.ScanCovered {
			continue
		}
		fh, ok := fromHosts[th.Address]
		var fromStatus inventory.Status
		if ok {
			fromStatus = fh.Status
		}
		if t := transition(ok, fromStatus, th.Status, hostTypes); t != "" {
			c := Change{Type: t, Address: th.Address}
			if t == HostMissing && th.Availability != nil && th.Availability.Expected == "up" {
				c.Note = ExpectedUpNote
			}
			changes = append(changes, c)
			continue
		}
		changes = append(changes, serviceChanges(th.Address, fh.Services, th.Services, volatile)...)
	}

	sort.SliceStable(changes, func(i, j int) bool { return less(changes[i], changes[j]) })
	return Diff{Schema: Schema, From: from.Run, To: to.Run, Changes: changes}
}

func transition(existed bool, from, to inventory.Status, types statusTypes) string {
	switch {
	case !existed:
		return types.isNew
	case from != inventory.StatusInactive && to == inventory.StatusInactive:
		return types.inactive
	case from == inventory.StatusActive && to == inventory.StatusUnstable:
		return types.missing
	case from != inventory.StatusActive && to == inventory.StatusActive:
		return types.returned
	}
	return ""
}

type serviceKey struct {
	port     int
	protocol string
}

func serviceChanges(address string, from, to []inventory.ExportService, volatile map[string]bool) []Change {
	fromServices := make(map[serviceKey]inventory.ExportService, len(from))
	for _, s := range from {
		fromServices[serviceKey{s.Port, s.Protocol}] = s
	}
	var changes []Change
	for _, ts := range to {
		fs, ok := fromServices[serviceKey{ts.Port, ts.Protocol}]
		port := ts.Port
		c := Change{Address: address, Port: &port, Protocol: ts.Protocol}
		var fromStatus inventory.Status
		if ok {
			fromStatus = fs.Status
		}
		if t := transition(ok, fromStatus, ts.Status, serviceTypes); t != "" {
			c.Type = t
			changes = append(changes, c)
			continue
		}
		if fs.Status != inventory.StatusActive || ts.Status != inventory.StatusActive {
			continue
		}
		if fields := changedFields(fs, ts, volatile); len(fields) > 0 {
			c.Type = ServiceChanged
			c.Fields = fields
			changes = append(changes, c)
		}
	}
	return changes
}

func changedFields(from, to inventory.ExportService, volatile map[string]bool) []FieldChange {
	probed := !inventory.ProbeFailed(from) && !inventory.ProbeFailed(to)
	old, oldShown := inventory.ServiceFields(from, volatile)
	cur, curShown := inventory.ServiceFields(to, volatile)
	learned := map[string]bool{}
	for _, f := range to.Volatile {
		learned[f.Field] = true
	}
	var fields []FieldChange
	for _, name := range inventory.ChangedFields(old, cur, probed) {
		if learned[name] {
			continue
		}
		fields = append(fields, FieldChange{Field: name, Old: oldShown[name], New: curShown[name]})
	}
	return fields
}

func less(a, b Change) bool {
	if a.Address != b.Address {
		return addressLess(a.Address, b.Address)
	}
	ap, bp := -1, -1
	if a.Port != nil {
		ap = *a.Port
	}
	if b.Port != nil {
		bp = *b.Port
	}
	if ap != bp {
		return ap < bp
	}
	if a.Protocol != b.Protocol {
		return a.Protocol < b.Protocol
	}
	return a.Type < b.Type
}

func addressLess(a, b string) bool {
	aa, errA := netip.ParseAddr(a)
	ba, errB := netip.ParseAddr(b)
	if errA == nil && errB == nil {
		return aa.Less(ba)
	}
	if (errA == nil) != (errB == nil) {
		return errA == nil
	}
	return a < b
}
