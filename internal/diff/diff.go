package diff

import (
	"net/netip"
	"reflect"
	"sort"
	"strings"

	"asi/internal/inventory"
	"asi/internal/probe"
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

var DefaultVolatileHeaders = []string{
	"date", "expires", "last-modified", "etag", "age", "set-cookie", "content-length", "x-request-id", "cf-ray",
}

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

func Compute(from, to inventory.Export, opts Options) Diff {
	volatile := map[string]bool{}
	for _, h := range DefaultVolatileHeaders {
		volatile[h] = true
	}
	for _, h := range opts.VolatileHeaders {
		volatile[strings.ToLower(strings.TrimSpace(h))] = true
	}

	fromHosts := make(map[string]inventory.ExportHost, len(from.Hosts))
	for _, h := range from.Hosts {
		fromHosts[h.Address] = h
	}

	changes := []Change{}
	for _, th := range to.Hosts {
		fh, ok := fromHosts[th.Address]
		var fromStatus inventory.Status
		if ok {
			fromStatus = fh.Status
		}
		if t := transition(ok, fromStatus, th.Status, hostTypes); t != "" {
			changes = append(changes, Change{Type: t, Address: th.Address})
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
	old := fieldValues(from, volatile)
	cur := fieldValues(to, volatile)
	names := map[string]bool{}
	for k := range old {
		names[k] = true
	}
	for k := range cur {
		names[k] = true
	}
	var fields []FieldChange
	for name := range names {
		o, n := old[name], cur[name]
		if reflect.DeepEqual(o, n) {
			continue
		}
		fields = append(fields, FieldChange{Field: name, Old: o, New: n})
	}
	sort.Slice(fields, func(i, j int) bool { return fields[i].Field < fields[j].Field })
	return fields
}

func fieldValues(s inventory.ExportService, volatile map[string]bool) map[string]any {
	v := map[string]any{
		"service":             s.Service,
		"product":             s.Product,
		"version":             s.Version,
		"technologies":        technologySet(s.Technologies),
		"findings":            findingSet(s.Findings),
		"http.status_code":    nil,
		"http.title":          nil,
		"http.cookies":        nil,
		"http.redirect_chain": nil,
		"http.tls.sha256":     nil,
		"http.favicon_sha256": nil,
	}
	if s.HTTP == nil {
		return v
	}
	v["http.status_code"] = s.HTTP.StatusCode
	v["http.title"] = s.HTTP.Title
	v["http.cookies"] = cookieSet(s.HTTP.Cookies)
	chain := []string{}
	chain = append(chain, s.HTTP.RedirectChain...)
	v["http.redirect_chain"] = chain
	if s.HTTP.TLS != nil {
		v["http.tls.sha256"] = s.HTTP.TLS.SHA256
	}
	v["http.favicon_sha256"] = s.HTTP.FaviconSHA256
	for name, value := range s.HTTP.Headers {
		name = strings.ToLower(name)
		if volatile[name] {
			continue
		}
		v["http.headers."+name] = value
	}
	return v
}

func cookieSet(cookies []probe.Cookie) []string {
	names := make([]string, 0, len(cookies))
	for _, c := range cookies {
		names = append(names, c.Name)
	}
	return set(names)
}

func technologySet(techs []inventory.Technology) []string {
	items := make([]string, 0, len(techs))
	for _, t := range techs {
		item := t.Name
		if t.Version != "" {
			item += " " + t.Version
		}
		items = append(items, item)
	}
	return set(items)
}

func findingSet(findings []inventory.Finding) []string {
	ids := make([]string, 0, len(findings))
	for _, f := range findings {
		ids = append(ids, f.SignatureID)
	}
	return set(ids)
}

func set(items []string) []string {
	sort.Strings(items)
	out := []string{}
	for i, s := range items {
		if i > 0 && items[i-1] == s {
			continue
		}
		out = append(out, s)
	}
	return out
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
