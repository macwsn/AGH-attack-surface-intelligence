//go:build integration

package inventory_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"asi/internal/diff"
	"asi/internal/inventory"
	"asi/internal/probe"
	"asi/internal/store"
	"asi/internal/store/storetest"
)

func openExportInventory(t *testing.T) *inventory.Inventory {
	t.Helper()
	ctx := context.Background()
	s, err := store.Open(ctx, storetest.DatabaseURL(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(s.Close)
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatalf("master key: %v", err)
	}
	k, err := store.NewKeyring(master)
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	return inventory.New(s, k)
}

func createRun(t *testing.T, inv *inventory.Inventory, name string) inventory.Run {
	t.Helper()
	r, err := inv.CreateRun(context.Background(), inventory.RunSpec{Name: name})
	if err != nil {
		t.Fatalf("CreateRun %s: %v", name, err)
	}
	return r
}

func record(t *testing.T, inv *inventory.Inventory, r inventory.Run, g inventory.GroupResult) {
	t.Helper()
	if err := inv.RecordGroup(context.Background(), r.ID, g); err != nil {
		t.Fatalf("RecordGroup %s/%d: %v", r.Name, g.Index, err)
	}
}

func export(t *testing.T, inv *inventory.Inventory, run string) inventory.Export {
	t.Helper()
	e, err := inv.Export(context.Background(), run)
	if err != nil {
		t.Fatalf("Export(%q): %v", run, err)
	}
	return e
}

func host(t *testing.T, e inventory.Export, address string) inventory.ExportHost {
	t.Helper()
	for _, h := range e.Hosts {
		if h.Address == address {
			return h
		}
	}
	t.Fatalf("export of run %q has no host %s", e.Run, address)
	return inventory.ExportHost{}
}

func web(title string, headers map[string]string) inventory.ServiceResult {
	h := map[string]string{"server": "nginx"}
	for k, v := range headers {
		h[k] = v
	}
	return inventory.ServiceResult{
		Port: 80, Protocol: "tcp", State: "open", Service: "http", Product: "nginx", Version: "1.25.3",
		HTTP: &probe.HTTP{Scheme: "http", URL: "http://10.0.0.5/", StatusCode: 200, Title: title, Headers: h,
			Cookies: []probe.Cookie{{Name: "sid", HTTPOnly: true}}, RedirectChain: []string{}},
		Technologies: []inventory.Technology{{Name: "nginx", Category: "web-server", Version: "1.25.3", Confidence: 90, Source: "builtin"}},
	}
}

func TestExportCurrent(t *testing.T) {
	inv := openExportInventory(t)
	if e := export(t, inv, ""); e.Schema != inventory.ExportSchema || e.Hosts == nil || len(e.Hosts) != 0 {
		t.Fatalf("empty inventory export = %+v", e)
	}
	r1 := createRun(t, inv, "r1")
	record(t, inv, r1, inventory.GroupResult{Index: 0, Addresses: []string{"10.0.0.10", "10.0.0.9", "10.0.0.5"}, Hosts: []inventory.HostResult{
		{Address: "10.0.0.10", Services: []inventory.ServiceResult{
			{Port: 443, Protocol: "tcp", State: "open", Service: "https"},
			{Port: 22, Protocol: "udp", State: "open"},
			{Port: 22, Protocol: "tcp", State: "open", Service: "ssh"},
		}},
		{Address: "10.0.0.9"},
		{Address: "10.0.0.5", Hostnames: []string{"web.example"}, Services: []inventory.ServiceResult{web("Home", nil)}},
	}})
	r2 := createRun(t, inv, "r2")
	record(t, inv, r2, inventory.GroupResult{Index: 0, Addresses: []string{"10.0.0.5"}, Hosts: []inventory.HostResult{
		{Address: "10.0.0.5", Services: []inventory.ServiceResult{web("Home", nil)}},
	}})

	e := export(t, inv, "")
	if e.Schema != "asi.export/v1" || e.Run != "r2" {
		t.Fatalf("schema/run = %q/%q", e.Schema, e.Run)
	}
	var got []string
	for _, h := range e.Hosts {
		got = append(got, h.Address)
	}
	if strings.Join(got, ",") != "10.0.0.5,10.0.0.9,10.0.0.10" {
		t.Errorf("hosts not in numeric order: %v", got)
	}
	h10 := host(t, e, "10.0.0.10")
	for _, s := range h10.Services {
		if s.HTTP != nil || s.Technologies == nil || s.Findings == nil {
			t.Errorf("service %d/%s: http=%v techs=%v findings=%v", s.Port, s.Protocol, s.HTTP, s.Technologies, s.Findings)
		}
	}
	if len(h10.Services) != 3 || h10.Services[0].Port != 22 || h10.Services[0].Protocol != "tcp" ||
		h10.Services[1].Protocol != "udp" || h10.Services[2].Port != 443 {
		t.Errorf("services not sorted by port, protocol: %+v", h10.Services)
	}
	if h9 := host(t, e, "10.0.0.9"); h9.Hostnames == nil || h9.Tags == nil || h9.Services == nil {
		t.Errorf("nil arrays on host without services: %+v", h9)
	}
	if h5 := host(t, e, "10.0.0.5"); h5.Status != inventory.StatusActive || h5.Services[0].HTTP == nil ||
		h5.Services[0].HTTP.Title != "Home" || h5.Services[0].HTTP.Cookies[0].Name != "sid" {
		t.Errorf("host 10.0.0.5 = %+v", h5)
	}

	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, null := range []string{`"hostnames":null`, `"tags":null`, `"services":null`, `"technologies":null`, `"findings":null`, `"hosts":null`} {
		if strings.Contains(string(b), null) {
			t.Errorf("export contains %s", null)
		}
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, err := time.Parse(time.RFC3339, doc["generated_at"].(string)); err != nil {
		t.Errorf("generated_at not RFC3339: %v", err)
	}
}

func TestExportAsOfRun(t *testing.T) {
	inv := openExportInventory(t)
	r1 := createRun(t, inv, "r1")
	record(t, inv, r1, inventory.GroupResult{Index: 0, Addresses: []string{"10.0.0.5", "10.0.0.6"}, Hosts: []inventory.HostResult{
		{Address: "10.0.0.5", Services: []inventory.ServiceResult{web("v1", nil)}},
	}})
	r2 := createRun(t, inv, "r2")
	record(t, inv, r2, inventory.GroupResult{Index: 0, Addresses: []string{"10.0.0.5", "10.0.0.6"}, Hosts: []inventory.HostResult{
		{Address: "10.0.0.5", Services: []inventory.ServiceResult{web("v2", nil)}},
		{Address: "10.0.0.6"},
	}})

	e1 := export(t, inv, "r1")
	if e1.Run != "r1" || len(e1.Hosts) != 1 {
		t.Fatalf("Export(r1) run=%q hosts=%+v", e1.Run, e1.Hosts)
	}
	a := host(t, e1, "10.0.0.5")
	if a.Services[0].HTTP.Title != "v1" {
		t.Errorf("Export(r1) title = %q, want v1", a.Services[0].HTTP.Title)
	}
	if !a.LastSeen.Equal(r1.StartedAt) || !a.Services[0].LastSeen.Equal(r1.StartedAt) {
		t.Errorf("Export(r1) last_seen = %v/%v, want %v", a.LastSeen, a.Services[0].LastSeen, r1.StartedAt)
	}

	for _, name := range []string{"r2", ""} {
		e := export(t, inv, name)
		if e.Run != "r2" || len(e.Hosts) != 2 {
			t.Fatalf("Export(%q) run=%q hosts=%+v", name, e.Run, e.Hosts)
		}
		a := host(t, e, "10.0.0.5")
		if a.Services[0].HTTP.Title != "v2" {
			t.Errorf("Export(%q) title = %q, want v2", name, a.Services[0].HTTP.Title)
		}
		if !a.FirstSeen.Equal(r1.StartedAt) || !a.LastSeen.Equal(r2.StartedAt) {
			t.Errorf("Export(%q) first/last seen = %v/%v", name, a.FirstSeen, a.LastSeen)
		}
		host(t, e, "10.0.0.6")
	}
}

func TestExportUnknownRun(t *testing.T) {
	inv := openExportInventory(t)
	createRun(t, inv, "r1")
	_, err := inv.Export(context.Background(), "nope")
	if err == nil {
		t.Fatal("Export of unknown run returned no error")
	}
	if !errors.Is(err, inventory.ErrUnknownRun) {
		t.Errorf("error = %v, want ErrUnknownRun", err)
	}
}

func TestDiffOfRecordedRuns(t *testing.T) {
	inv := openExportInventory(t)
	group := func(title string, volatile map[string]string) inventory.GroupResult {
		return inventory.GroupResult{Index: 0, Addresses: []string{"10.0.0.5"}, Hosts: []inventory.HostResult{
			{Address: "10.0.0.5", Hostnames: []string{"web.example"}, Services: []inventory.ServiceResult{web(title, volatile)}},
		}}
	}
	r1 := createRun(t, inv, "r1")
	record(t, inv, r1, group("Intranet v1", map[string]string{"date": "Mon, 01 Jan 2026 10:00:00 GMT", "etag": `"a1"`}))
	r2 := createRun(t, inv, "r2")
	record(t, inv, r2, group("Intranet v1", map[string]string{"date": "Tue, 02 Jan 2026 11:00:00 GMT", "etag": `"b2"`}))
	r3 := createRun(t, inv, "r3")
	record(t, inv, r3, group("Intranet v2", map[string]string{"date": "Wed, 03 Jan 2026 12:00:00 GMT", "etag": `"b2"`}))

	d := diff.Compute(export(t, inv, "r1"), export(t, inv, "r2"), diff.Options{})
	if d.From != "r1" || d.To != "r2" || len(d.Changes) != 0 {
		t.Fatalf("r1→r2 diff = %+v, want no changes", d)
	}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal diff: %v", err)
	}
	if !strings.Contains(string(b), `"changes":[]`) {
		t.Errorf("empty diff JSON = %s", b)
	}

	d = diff.Compute(export(t, inv, "r2"), export(t, inv, "r3"), diff.Options{})
	if len(d.Changes) != 1 {
		t.Fatalf("r2→r3 changes = %+v, want exactly one", d.Changes)
	}
	c := d.Changes[0]
	if c.Type != diff.ServiceChanged || c.Address != "10.0.0.5" || c.Port == nil || *c.Port != 80 || c.Protocol != "tcp" {
		t.Errorf("change = %+v", c)
	}
	if len(c.Fields) != 1 || c.Fields[0].Field != "http.title" || c.Fields[0].Old != "Intranet v1" || c.Fields[0].New != "Intranet v2" {
		t.Errorf("fields = %+v", c.Fields)
	}
}
