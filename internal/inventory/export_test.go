package inventory

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"asi/internal/probe"
)

func keysOf(t *testing.T, v any) []string {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("expected JSON object, got %T", v)
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func requireKeys(t *testing.T, what string, v any, want ...string) {
	t.Helper()
	got := map[string]bool{}
	for _, k := range keysOf(t, v) {
		got[k] = true
	}
	for _, k := range want {
		if !got[k] {
			t.Errorf("%s: missing key %q (have %v)", what, k, keysOf(t, v))
		}
	}
}

func requireArray(t *testing.T, what string, v any) []any {
	t.Helper()
	a, ok := v.([]any)
	if !ok {
		t.Fatalf("%s: expected JSON array, got %T (%v)", what, v, v)
	}
	return a
}

func TestExportJSONShape(t *testing.T) {
	ts := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	e := Export{
		Schema: ExportSchema, GeneratedAt: ts, Run: "r1",
		Hosts: []ExportHost{{
			Address: "10.0.0.1", Hostnames: []string{}, Status: StatusActive, FirstSeen: ts, LastSeen: ts,
			Stability: 1, Tags: []string{}, Services: []ExportService{
				{Port: 22, Protocol: "tcp", State: "open", Status: StatusActive, Service: "ssh", FirstSeen: ts, LastSeen: ts,
					Technologies: []Technology{}, Findings: []Finding{}},
				{Port: 443, Protocol: "tcp", State: "open", Status: StatusActive, Service: "http", FirstSeen: ts, LastSeen: ts,
					HTTP: &probe.HTTP{Scheme: "https", URL: "https://10.0.0.1/", StatusCode: 200, Title: "t",
						Headers: map[string]string{"server": "nginx"}, Cookies: []probe.Cookie{{Name: "sid", HTTPOnly: true}},
						RedirectChain: []string{}, TLS: &probe.TLS{SHA256: "ab", SANs: []string{}}, FaviconSHA256: "ff", FaviconMMH3: -1},
					Technologies: []Technology{{Name: "nginx", Category: "web-server", Version: "1.25", Confidence: 90, Source: "builtin"}},
					Findings:     []Finding{{SignatureID: "s", Kind: "admin-panel", Name: "n", Confidence: 80, Evidence: "e"}}},
			},
		}},
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	requireKeys(t, "export", doc, "schema", "generated_at", "run", "hosts")
	if doc["schema"] != "asi.export/v1" || doc["run"] != "r1" {
		t.Errorf("schema/run = %v/%v", doc["schema"], doc["run"])
	}
	if _, err := time.Parse(time.RFC3339, doc["generated_at"].(string)); err != nil {
		t.Errorf("generated_at not RFC3339: %v", err)
	}
	hosts := requireArray(t, "hosts", doc["hosts"])
	host := hosts[0]
	requireKeys(t, "host", host, "address", "hostnames", "status", "first_seen", "last_seen", "missed_runs",
		"stability", "interest_score", "tags", "notes", "services")
	hm := host.(map[string]any)
	for _, k := range []string{"hostnames", "tags", "services"} {
		requireArray(t, "host."+k, hm[k])
	}
	if _, err := time.Parse(time.RFC3339, hm["first_seen"].(string)); err != nil {
		t.Errorf("first_seen not RFC3339: %v", err)
	}
	services := requireArray(t, "services", hm["services"])
	for i, s := range services {
		requireKeys(t, "service", s, "port", "protocol", "state", "status", "service", "product", "version",
			"first_seen", "last_seen", "http", "technologies", "findings")
		sm := s.(map[string]any)
		requireArray(t, "technologies", sm["technologies"])
		requireArray(t, "findings", sm["findings"])
		if i == 0 && sm["http"] != nil {
			t.Errorf("non-HTTP service http = %v, want null", sm["http"])
		}
	}
	sm := services[1].(map[string]any)
	requireKeys(t, "http", sm["http"], "scheme", "url", "status_code", "title", "headers", "cookies",
		"redirect_chain", "tls", "favicon_sha256", "favicon_mmh3")
	cookie := requireArray(t, "cookies", sm["http"].(map[string]any)["cookies"])[0]
	if got, want := keysOf(t, cookie), []string{"http_only", "name", "same_site", "secure"}; !reflect.DeepEqual(got, want) {
		t.Errorf("cookie keys = %v, want %v (no value)", got, want)
	}
	requireKeys(t, "technology", requireArray(t, "technologies", sm["technologies"])[0],
		"name", "category", "version", "confidence", "source")
	requireKeys(t, "finding", requireArray(t, "findings", sm["findings"])[0],
		"signature_id", "kind", "name", "version", "confidence", "evidence")
	if strings.Contains(string(b), `"value"`) {
		t.Errorf("export contains a value key: %s", b)
	}
}
