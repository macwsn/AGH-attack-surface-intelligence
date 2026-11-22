package diff

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"asi/internal/inventory"
	"asi/internal/probe"
)

const (
	active   = inventory.StatusActive
	unstable = inventory.StatusUnstable
	inactive = inventory.StatusInactive
)

func export(run string, hosts ...inventory.ExportHost) inventory.Export {
	return inventory.Export{Schema: "asi.export/v1", Run: run, Hosts: hosts}
}

func host(address string, status inventory.Status, services ...inventory.ExportService) inventory.ExportHost {
	return inventory.ExportHost{Address: address, Status: status, Hostnames: []string{}, Tags: []string{}, Services: services}
}

func svc(port int, status inventory.Status) inventory.ExportService {
	return inventory.ExportService{
		Port: port, Protocol: "tcp", State: "open", Status: status,
		Service: "http", Product: "nginx", Version: "1.27.5",
		Technologies: []inventory.Technology{}, Findings: []inventory.Finding{},
	}
}

func webSvc(port int, status inventory.Status) inventory.ExportService {
	s := svc(port, status)
	s.HTTP = &probe.HTTP{
		Scheme: "https", URL: "https://172.30.0.18/", StatusCode: 200, Title: "Intranet v1",
		Headers: map[string]string{
			"server": "nginx", "x-powered-by": "PHP/7.4.3",
			"date": "Mon, 01 Jan 2026 00:00:00 GMT", "etag": `"a1"`, "expires": "0", "last-modified": "x",
			"age": "1", "set-cookie": "PHPSESSID=abc", "content-length": "100", "x-request-id": "r1", "cf-ray": "c1",
			"x-trace": "t1",
		},
		Cookies:       []probe.Cookie{{Name: "PHPSESSID", HTTPOnly: true}, {Name: "lang"}},
		RedirectChain: []string{"https://172.30.0.18/login"},
		TLS: &probe.TLS{
			SubjectCN: "intranet", IssuerCN: "ca", SANs: []string{},
			NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z", SHA256: "aa", SelfSigned: true,
		},
		FaviconSHA256: "f1",
	}
	s.Technologies = []inventory.Technology{
		{Name: "WordPress", Category: "cms", Version: "6.4.2", Confidence: 95, Source: "builtin"},
		{Name: "PHP", Category: "language", Confidence: 80, Source: "builtin"},
	}
	s.Findings = []inventory.Finding{
		{SignatureID: "admin-panel-login", Kind: "admin-panel", Confidence: 80, Evidence: "e1"},
		{SignatureID: "staging-host", Kind: "staging", Confidence: 60, Evidence: "e2"},
	}
	return s
}

func types(d Diff) []string {
	out := []string{}
	for _, c := range d.Changes {
		out = append(out, c.Type)
	}
	return out
}

// REQ-DIFF-001
func TestDiffJSONShape(t *testing.T) {
	from := export("lab-1",
		host("172.30.0.18", active, webSvc(80, active)),
		host("172.30.0.9", active),
	)
	toWeb := webSvc(80, active)
	toWeb.HTTP.Title = "Intranet v2"
	to := export("lab-2",
		host("172.30.0.18", active, toWeb),
		host("172.30.0.9", unstable),
		host("172.30.0.100", active),
	)

	d := Compute(from, to, Options{})
	got, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"schema":"asi.diff/v1","from":"lab-1","to":"lab-2","changes":[` +
		`{"type":"host_missing","address":"172.30.0.9"},` +
		`{"type":"service_changed","address":"172.30.0.18","port":80,"protocol":"tcp","fields":[{"field":"http.title","old":"Intranet v1","new":"Intranet v2"}]},` +
		`{"type":"host_new","address":"172.30.0.100"}]}`
	if string(got) != want {
		t.Fatalf("json:\n got %s\nwant %s", got, want)
	}

	var generic map[string]any
	if err := json.Unmarshal(got, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, c := range generic["changes"].([]any) {
		m := c.(map[string]any)
		if _, ok := m["port"]; ok == (m["type"] == HostNew || m["type"] == HostMissing) {
			t.Errorf("port key presence wrong in %v", m)
		}
	}

	reordered := export("lab-2", to.Hosts[2], to.Hosts[0], to.Hosts[1])
	again, err := json.Marshal(Compute(from, reordered, Options{}))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Equal(got, again) {
		t.Fatalf("not deterministic:\n%s\n%s", got, again)
	}

	empty, err := json.Marshal(Compute(from, from, Options{}))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if want := `{"schema":"asi.diff/v1","from":"lab-1","to":"lab-1","changes":[]}`; string(empty) != want {
		t.Fatalf("empty diff: got %s want %s", empty, want)
	}
}

// REQ-DIFF-002 REQ-DIFF-003
func TestChangeTypes(t *testing.T) {
	const addr = "10.0.0.1"
	cases := []struct {
		name     string
		from, to []inventory.ExportHost
		want     string
	}{
		{"host_new", nil, []inventory.ExportHost{host(addr, active)}, HostNew},
		{"host_missing", []inventory.ExportHost{host(addr, active)}, []inventory.ExportHost{host(addr, unstable)}, HostMissing},
		{"host_returned from unstable", []inventory.ExportHost{host(addr, unstable)}, []inventory.ExportHost{host(addr, active)}, HostReturned},
		{"host_returned from inactive", []inventory.ExportHost{host(addr, inactive)}, []inventory.ExportHost{host(addr, active)}, HostReturned},
		{"host_inactive from unstable", []inventory.ExportHost{host(addr, unstable)}, []inventory.ExportHost{host(addr, inactive)}, HostInactive},
		{"host_inactive from active", []inventory.ExportHost{host(addr, active)}, []inventory.ExportHost{host(addr, inactive)}, HostInactive},
		{"host unstable in both", []inventory.ExportHost{host(addr, unstable, svc(80, unstable))}, []inventory.ExportHost{host(addr, unstable, svc(80, unstable))}, ""},
		{"host inactive in both", []inventory.ExportHost{host(addr, inactive, svc(80, inactive))}, []inventory.ExportHost{host(addr, inactive, svc(80, inactive))}, ""},
		{"service_new", []inventory.ExportHost{host(addr, active)}, []inventory.ExportHost{host(addr, active, svc(80, active))}, ServiceNew},
		{"service_missing", []inventory.ExportHost{host(addr, active, svc(80, active))}, []inventory.ExportHost{host(addr, active, svc(80, unstable))}, ServiceMissing},
		{"service_returned from unstable", []inventory.ExportHost{host(addr, active, svc(80, unstable))}, []inventory.ExportHost{host(addr, active, svc(80, active))}, ServiceReturned},
		{"service_returned from inactive", []inventory.ExportHost{host(addr, active, svc(80, inactive))}, []inventory.ExportHost{host(addr, active, svc(80, active))}, ServiceReturned},
		{"service_inactive", []inventory.ExportHost{host(addr, active, svc(80, unstable))}, []inventory.ExportHost{host(addr, active, svc(80, inactive))}, ServiceInactive},
		{"service unstable in both", []inventory.ExportHost{host(addr, active, svc(80, unstable))}, []inventory.ExportHost{host(addr, active, svc(80, unstable))}, ""},
		{"service inactive in both", []inventory.ExportHost{host(addr, active, svc(80, inactive))}, []inventory.ExportHost{host(addr, active, svc(80, inactive))}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := Compute(export("r1", tc.from...), export("r2", tc.to...), Options{})
			if tc.want == "" {
				if len(d.Changes) != 0 {
					t.Fatalf("want no changes, got %+v", d.Changes)
				}
				return
			}
			if len(d.Changes) != 1 || d.Changes[0].Type != tc.want {
				t.Fatalf("want exactly one %s, got %v", tc.want, types(d))
			}
			c := d.Changes[0]
			if c.Address != addr {
				t.Errorf("address = %q", c.Address)
			}
			isHost := tc.want == HostNew || tc.want == HostMissing || tc.want == HostReturned || tc.want == HostInactive
			if isHost && (c.Port != nil || c.Protocol != "") {
				t.Errorf("host-level change carries port/protocol: %+v", c)
			}
			if !isHost && (c.Port == nil || *c.Port != 80 || c.Protocol != "tcp") {
				t.Errorf("service-level change lacks port/protocol: %+v", c)
			}
		})
	}
}

// REQ-DIFF-004
func TestHostLevelSuppressesServiceLevel(t *testing.T) {
	const addr = "10.0.0.2"
	cases := []struct {
		name     string
		from, to []inventory.ExportHost
		want     string
	}{
		{"host_new with services", nil,
			[]inventory.ExportHost{host(addr, active, svc(80, active), svc(443, active))}, HostNew},
		{"host_missing with services going unstable",
			[]inventory.ExportHost{host(addr, active, svc(80, active), svc(443, active))},
			[]inventory.ExportHost{host(addr, unstable, svc(80, unstable), svc(443, unstable))}, HostMissing},
		{"host_returned with returning and new services",
			[]inventory.ExportHost{host(addr, inactive, svc(80, inactive))},
			[]inventory.ExportHost{host(addr, active, svc(80, active), svc(8080, active))}, HostReturned},
		{"host_inactive with services going inactive",
			[]inventory.ExportHost{host(addr, unstable, svc(80, unstable), svc(443, active))},
			[]inventory.ExportHost{host(addr, inactive, svc(80, inactive), svc(443, inactive))}, HostInactive},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := Compute(export("r1", tc.from...), export("r2", tc.to...), Options{})
			if got := types(d); !reflect.DeepEqual(got, []string{tc.want}) {
				t.Fatalf("want only [%s], got %v", tc.want, got)
			}
		})
	}
}

// REQ-DIFF-005
func TestServiceChangedFields(t *testing.T) {
	const addr = "172.30.0.18"
	cases := []struct {
		name   string
		mutate func(s *inventory.ExportService)
		want   []FieldChange
	}{
		{"title", func(s *inventory.ExportService) { s.HTTP.Title = "Intranet v2" },
			[]FieldChange{{"http.title", "Intranet v1", "Intranet v2"}}},
		{"service", func(s *inventory.ExportService) { s.Service = "https" },
			[]FieldChange{{"service", "http", "https"}}},
		{"product", func(s *inventory.ExportService) { s.Product = "apache" },
			[]FieldChange{{"product", "nginx", "apache"}}},
		{"version", func(s *inventory.ExportService) { s.Version = "1.27.6" },
			[]FieldChange{{"version", "1.27.5", "1.27.6"}}},
		{"status code", func(s *inventory.ExportService) { s.HTTP.StatusCode = 403 },
			[]FieldChange{{"http.status_code", 200, 403}}},
		{"header changed", func(s *inventory.ExportService) { s.HTTP.Headers["x-powered-by"] = "PHP/8.2.0" },
			[]FieldChange{{"http.headers.x-powered-by", "PHP/7.4.3", "PHP/8.2.0"}}},
		{"header added", func(s *inventory.ExportService) { s.HTTP.Headers["x-frame-options"] = "DENY" },
			[]FieldChange{{"http.headers.x-frame-options", nil, "DENY"}}},
		{"header removed", func(s *inventory.ExportService) { delete(s.HTTP.Headers, "server") },
			[]FieldChange{{"http.headers.server", "nginx", nil}}},
		{"cookies", func(s *inventory.ExportService) {
			s.HTTP.Cookies = append(s.HTTP.Cookies, probe.Cookie{Name: "csrftoken"})
		}, []FieldChange{{"http.cookies", []string{"PHPSESSID", "lang"}, []string{"PHPSESSID", "csrftoken", "lang"}}}},
		{"redirect chain", func(s *inventory.ExportService) {
			s.HTTP.RedirectChain = []string{"https://172.30.0.18/login", "https://172.30.0.18/sso"}
		}, []FieldChange{{"http.redirect_chain", []string{"https://172.30.0.18/login"}, []string{"https://172.30.0.18/login", "https://172.30.0.18/sso"}}}},
		{"tls sha256", func(s *inventory.ExportService) { s.HTTP.TLS.SHA256 = "bb" },
			[]FieldChange{{"http.tls.sha256", "aa", "bb"}}},
		{"favicon", func(s *inventory.ExportService) { s.HTTP.FaviconSHA256 = "f2" },
			[]FieldChange{{"http.favicon_sha256", "f1", "f2"}}},
		{"technologies", func(s *inventory.ExportService) {
			s.Technologies = append(s.Technologies, inventory.Technology{Name: "jQuery", Version: "3.7.1"})
		}, []FieldChange{{"technologies", []string{"PHP", "WordPress 6.4.2"}, []string{"PHP", "WordPress 6.4.2", "jQuery 3.7.1"}}}},
		{"technology version", func(s *inventory.ExportService) { s.Technologies[0].Version = "6.5.0" },
			[]FieldChange{{"technologies", []string{"PHP", "WordPress 6.4.2"}, []string{"PHP", "WordPress 6.5.0"}}}},
		{"findings", func(s *inventory.ExportService) { s.Findings = s.Findings[:1] },
			[]FieldChange{{"findings", []string{"admin-panel-login", "staging-host"}, []string{"admin-panel-login"}}}},
		{"several fields sorted by name", func(s *inventory.ExportService) {
			s.Version = "1.27.6"
			s.HTTP.Title = "Intranet v2"
			s.HTTP.StatusCode = 302
		}, []FieldChange{
			{"http.status_code", 200, 302},
			{"http.title", "Intranet v1", "Intranet v2"},
			{"version", "1.27.5", "1.27.6"},
		}},
		{"reordered sets", func(s *inventory.ExportService) {
			s.HTTP.Cookies[0], s.HTTP.Cookies[1] = s.HTTP.Cookies[1], s.HTTP.Cookies[0]
			s.Technologies[0], s.Technologies[1] = s.Technologies[1], s.Technologies[0]
			s.Findings[0], s.Findings[1] = s.Findings[1], s.Findings[0]
		}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			to := webSvc(443, active)
			tc.mutate(&to)
			d := Compute(
				export("r1", host(addr, active, webSvc(443, active))),
				export("r2", host(addr, active, to)),
				Options{},
			)
			if tc.want == nil {
				if len(d.Changes) != 0 {
					t.Fatalf("want no changes, got %+v", d.Changes)
				}
				return
			}
			if len(d.Changes) != 1 || d.Changes[0].Type != ServiceChanged {
				t.Fatalf("want one service_changed, got %+v", d.Changes)
			}
			if !reflect.DeepEqual(d.Changes[0].Fields, tc.want) {
				t.Fatalf("fields:\n got %#v\nwant %#v", d.Changes[0].Fields, tc.want)
			}
		})
	}

	t.Run("json values", func(t *testing.T) {
		to := webSvc(443, active)
		to.HTTP.StatusCode = 404
		to.HTTP.Headers["x-frame-options"] = "DENY"
		d := Compute(export("r1", host(addr, active, webSvc(443, active))), export("r2", host(addr, active, to)), Options{})
		got, err := json.Marshal(d.Changes[0].Fields)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		want := `[{"field":"http.headers.x-frame-options","old":null,"new":"DENY"},{"field":"http.status_code","old":200,"new":404}]`
		if string(got) != want {
			t.Fatalf("json:\n got %s\nwant %s", got, want)
		}
	})
}

// REQ-DIFF-006
func TestVolatileIgnored(t *testing.T) {
	const addr = "172.30.0.18"
	to := webSvc(443, active)
	for name, value := range map[string]string{
		"date": "Tue, 02 Jan 2026 00:00:00 GMT", "expires": "-1", "last-modified": "y", "etag": `"b2"`,
		"age": "99", "set-cookie": "PHPSESSID=def", "content-length": "250", "x-request-id": "r2", "cf-ray": "c2",
		"x-trace": "t2",
	} {
		to.HTTP.Headers[name] = value
	}
	to.HTTP.Cookies = []probe.Cookie{{Name: "lang", Secure: true, SameSite: "Strict"}, {Name: "PHPSESSID", HTTPOnly: false}}
	to.HTTP.TLS.NotBefore = "2026-06-01T00:00:00Z"
	to.HTTP.TLS.NotAfter = "2027-06-01T00:00:00Z"
	to.HTTP.TLS.SubjectCN = "renamed"
	to.HTTP.TLS.IssuerCN = "other-ca"

	from := export("r1", host(addr, active, webSvc(443, active)))
	toExport := export("r2", host(addr, active, to))

	d := Compute(from, toExport, Options{VolatileHeaders: []string{"x-trace"}})
	if len(d.Changes) != 0 {
		t.Fatalf("volatile differences produced changes: %+v", d.Changes)
	}

	d = Compute(from, toExport, Options{})
	want := []FieldChange{{"http.headers.x-trace", "t1", "t2"}}
	if len(d.Changes) != 1 || d.Changes[0].Type != ServiceChanged || !reflect.DeepEqual(d.Changes[0].Fields, want) {
		t.Fatalf("want one service_changed on x-trace, got %+v", d.Changes)
	}
}

// REQ-DIFF-006
func TestIdenticalStatesEmpty(t *testing.T) {
	state := func() inventory.Export {
		return export("r1",
			host("172.30.0.18", active, webSvc(443, active), svc(22, active)),
			host("172.30.0.9", unstable, svc(80, unstable)),
			host("172.30.0.10", inactive),
		)
	}
	d := Compute(state(), state(), Options{})
	if d.Changes == nil || len(d.Changes) != 0 {
		t.Fatalf("want empty non-nil changes, got %#v", d.Changes)
	}
	got, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Contains(got, []byte(`"changes":[]`)) {
		t.Fatalf("changes not []: %s", got)
	}
}

func TestHostMissingExpectedUpNote(t *testing.T) {
	const addr = "10.0.0.1"
	run := func(av *inventory.ExportAvailability) string {
		to := host(addr, unstable)
		to.Availability = av
		d := Compute(inventory.Export{Run: "r1", Hosts: []inventory.ExportHost{host(addr, active)}},
			inventory.Export{Run: "r2", Hosts: []inventory.ExportHost{to}}, Options{})
		b, err := json.Marshal(d.Changes)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return string(b)
	}
	if got, want := run(&inventory.ExportAvailability{Expected: "up"}), `[{"type":"host_missing","address":"10.0.0.1","note":"expected up at this hour"}]`; got != want {
		t.Fatalf("expected up: got %s want %s", got, want)
	}
	for _, av := range []*inventory.ExportAvailability{nil, {}, {Expected: "down"}} {
		if got, want := run(av), `[{"type":"host_missing","address":"10.0.0.1"}]`; got != want {
			t.Fatalf("no note for %+v: got %s want %s", av, got, want)
		}
	}
}

// REQ-DIFF-003
func TestServiceLifecycleOnHostThatStaysUp(t *testing.T) {
	A, U, I := inventory.StatusActive, inventory.StatusUnstable, inventory.StatusInactive
	states := []inventory.Export{
		export("r1", host("127.0.0.1", A, svc(3001, A), svc(8787, A))),
		export("r2", host("127.0.0.1", A, svc(3001, A), svc(8787, U))),
		export("r3", host("127.0.0.1", A, svc(3001, A), svc(8787, I))),
		export("r4", host("127.0.0.1", A, svc(3001, A), svc(8787, I))),
		export("r5", host("127.0.0.1", A, svc(3001, A), svc(8787, A))),
	}
	want := []string{ServiceMissing, ServiceInactive, "", ServiceReturned}
	for i, w := range want {
		d := Compute(states[i], states[i+1], Options{})
		if w == "" {
			if len(d.Changes) != 0 {
				t.Fatalf("%s->%s: %+v, want no change", d.From, d.To, d.Changes)
			}
			continue
		}
		if len(d.Changes) != 1 || d.Changes[0].Type != w || d.Changes[0].Port == nil || *d.Changes[0].Port != 8787 {
			t.Fatalf("%s->%s: %+v, want one %s on port 8787", d.From, d.To, d.Changes, w)
		}
	}
}

func TestDownHourMissKeepsStatusNoChange(t *testing.T) {
	const addr = "10.0.0.1"
	to := host(addr, active, svc(80, active))
	to.Availability = &inventory.ExportAvailability{Expected: "down"}
	d := Compute(inventory.Export{Run: "r1", Hosts: []inventory.ExportHost{host(addr, active, svc(80, active))}},
		inventory.Export{Run: "r2", Hosts: []inventory.ExportHost{to}}, Options{})
	if len(d.Changes) != 0 {
		t.Fatalf("want no changes, got %+v", d.Changes)
	}
}

// REQ-DIFF-009
func TestResponseTimeNeverChanges(t *testing.T) {
	const addr = "172.30.0.18"
	from := webSvc(443, active)
	from.HTTP.TTFBMS, from.HTTP.ResponseMS = 12, 20
	to := webSvc(443, active)
	to.HTTP.TTFBMS, to.HTTP.ResponseMS = 4100, 9000
	d := Compute(export("r1", host(addr, active, from)), export("r2", host(addr, active, to)), Options{})
	if len(d.Changes) != 0 {
		t.Fatalf("response time produced changes: %+v", d.Changes)
	}
}

// REQ-DIFF-009
func TestProbeTimeoutIsNotAChange(t *testing.T) {
	const addr = "172.30.0.18"
	good := webSvc(443, active)
	slow := svc(443, active)
	slow.HTTP = &probe.HTTP{Scheme: "https", URL: "https://172.30.0.18/", Headers: map[string]string{}, Cookies: []probe.Cookie{}, RedirectChain: []string{}, ResponseMS: 10000, Error: probe.ErrorTimeout}
	for _, pair := range [][2]inventory.ExportService{{good, slow}, {slow, good}} {
		d := Compute(export("r1", host(addr, active, pair[0])), export("r2", host(addr, active, pair[1])), Options{})
		if len(d.Changes) != 0 {
			t.Fatalf("timed-out probe produced changes: %+v", d.Changes)
		}
	}
	slow.Version = "1.28.0"
	d := Compute(export("r1", host(addr, active, good)), export("r2", host(addr, active, slow)), Options{})
	want := []FieldChange{{"version", "1.27.5", "1.28.0"}}
	if len(d.Changes) != 1 || !reflect.DeepEqual(d.Changes[0].Fields, want) {
		t.Fatalf("want only the version change, got %+v", d.Changes)
	}
}

// REQ-DIFF-014
func TestNormalizedHeaderChangeShowsRawValues(t *testing.T) {
	from, to := webSvc(443, active), webSvc(443, active)
	from.HTTP.Headers = map[string]string{"content-security-policy": "script-src 'nonce-YWFhYWFhYWE='"}
	to.HTTP.Headers = map[string]string{"content-security-policy": "script-src 'nonce-YmJiYmJiYmI=' 'self'"}
	d := Compute(export("r1", host("10.0.0.1", active, from)), export("r2", host("10.0.0.1", active, to)), Options{})
	want := []FieldChange{{Field: "http.headers.content-security-policy", Old: from.HTTP.Headers["content-security-policy"], New: to.HTTP.Headers["content-security-policy"]}}
	if len(d.Changes) != 1 || !reflect.DeepEqual(d.Changes[0].Fields, want) {
		t.Fatalf("changes = %+v, want one change with the raw headers %+v", d.Changes, want)
	}
}

// REQ-DIFF-015
func TestLearnedVolatileFieldIsNotAChange(t *testing.T) {
	from, to := webSvc(443, active), webSvc(443, active)
	to.HTTP.Title, to.Version = "Intranet v2", "2.0"
	to.Volatile = []inventory.VolatileField{{Field: "http.title", Values: []any{"Intranet v1", "Intranet v2"}}}
	d := Compute(export("r1", host("10.0.0.1", active, from)), export("r2", host("10.0.0.1", active, to)), Options{})
	if len(d.Changes) != 1 || len(d.Changes[0].Fields) != 1 || d.Changes[0].Fields[0].Field != "version" {
		t.Fatalf("changes = %+v, want only the version change: the title is volatile", d.Changes)
	}
}

// REQ-DIFF-016
func TestUnstableFaviconIsNotAChange(t *testing.T) {
	from, to := webSvc(443, active), webSvc(443, active)
	to.HTTP.FaviconSHA256, to.HTTP.FaviconUnstable = "f2", true
	if d := Compute(export("r1", host("10.0.0.1", active, from)), export("r2", host("10.0.0.1", active, to)), Options{}); len(d.Changes) != 0 {
		t.Fatalf("changes = %+v, want none for an unstable favicon", d.Changes)
	}
	to.HTTP.FaviconUnstable = false
	if d := Compute(export("r1", host("10.0.0.1", active, from)), export("r2", host("10.0.0.1", active, to)), Options{}); len(d.Changes) != 1 {
		t.Fatalf("changes = %+v, want the stable favicon change", d.Changes)
	}
}

func TestVolatileHeadersFromRunSettingsNeverProduceAChange(t *testing.T) {
	from := export("v1", host("172.30.0.18", inventory.StatusActive, webSvc(443, inventory.StatusActive)))
	to := export("v2", host("172.30.0.18", inventory.StatusActive, webSvc(443, inventory.StatusActive)))
	to.Hosts[0].Services[0].HTTP.Headers = map[string]string{}
	for k, v := range from.Hosts[0].Services[0].HTTP.Headers {
		to.Hosts[0].Services[0].HTTP.Headers[k] = v
	}
	to.Hosts[0].Services[0].HTTP.Headers["x-trace"] = "t2"
	if got := Compute(from, to, Options{}).Changes; len(got) != 1 {
		t.Fatalf("control: changes = %+v, want one service_changed for x-trace", got)
	}
	to.VolatileHeaders = []string{" X-Trace "}
	if got := Compute(from, to, Options{}).Changes; len(got) != 0 {
		t.Errorf("header listed in the run settings produced changes %+v", got)
	}
}

func TestScanDiffSkipsHostsNeverCoveredByAScan(t *testing.T) {
	imported := host("198.51.100.5", inventory.StatusActive, svc(80, inventory.StatusActive))
	scanned := host("192.0.2.1", inventory.StatusActive, svc(80, inventory.StatusActive))
	scanned.ScanCovered = true
	to := export("s2", imported, scanned)
	to.Source = inventory.SourceScan
	got := Compute(export("s1"), to, Options{}).Changes
	if len(got) != 1 || got[0].Address != "192.0.2.1" || got[0].Type != HostNew {
		t.Errorf("scan diff changes = %+v, want only host_new 192.0.2.1", got)
	}
	to.Source = inventory.SourceImport
	if got := Compute(export("s1"), to, Options{}).Changes; len(got) != 2 {
		t.Errorf("import diff changes = %+v, want host_new for both hosts", got)
	}
}
