package inventory

import (
	"encoding/json"
	"reflect"
	"strconv"
	"testing"

	"asi/internal/probe"
)

// REQ-DIFF-014
func TestNormalizeHeader(t *testing.T) {
	cases := []struct {
		name, value, want string
	}{
		{"content-security-policy",
			"script-src 'self' 'unsafe-inline' 'nonce-bD9hZmI3NjQ1ZTkxYzM4YQ==' 'strict-dynamic'; connect-src 'self'; frame-src https://www.adminer.org; object-src 'none'; base-uri 'none'; form-action 'self'",
			"script-src 'self' 'unsafe-inline' 'nonce-<volatile>' 'strict-dynamic'; connect-src 'self'; frame-src https://www.adminer.org; object-src 'none'; base-uri 'none'; form-action 'self'"},
		{"Content-Security-Policy", "script-src 'nonce-abc' 'NONCE-x1'", "script-src 'nonce-<volatile>' 'nonce-<volatile>'"},
		{"content-security-policy-report-only", "script-src 'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=' 'sha384-abc' 'sha512-def'",
			"script-src 'sha256-<volatile>' 'sha384-<volatile>' 'sha512-<volatile>'"},
		{"x-csrf-token", "4f0c2d7e9a1b3c5d7e9f1a2b3c4d5e6f", "<volatile>"},
		{"x-correlation-id", "123e4567-e89b-12d3-a456-426614174000", "<volatile>"},
		{"x-request-token", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0", "<volatile>.<volatile>"},
		{"x-generated", "2026-11-21T14:05:09.123Z", "<volatile>"},
		{"x-served-at", "Sat, 21 Nov 2026 14:05:09 GMT", "<volatile>"},
		{"x-timestamp", "1763733909", "<volatile>"},
		{"x-timestamp-ms", "t=1763733909123", "t=<volatile>"},
		{"server", "Apache/2.4.58 (Ubuntu)", "Apache/2.4.58 (Ubuntu)"},
		{"strict-transport-security", "max-age=31536000; includeSubDomains", "max-age=31536000; includeSubDomains"},
		{"x-powered-by", "PHP/8.2.12", "PHP/8.2.12"},
		{"content-type", "text/html; charset=UTF-8", "text/html; charset=UTF-8"},
		{"content-security-policy", "default-src 'self'; img-src *", "default-src 'self'; img-src *"},
		{"x-frame-options", "SAMEORIGIN", "SAMEORIGIN"},
	}
	for _, c := range cases {
		if got := NormalizeHeader(c.name, c.value); got != c.want {
			t.Errorf("NormalizeHeader(%q, %q) = %q, want %q", c.name, c.value, got, c.want)
		}
	}
}

func TestServiceFieldsKeepRawHeaderForDisplay(t *testing.T) {
	raw := "script-src 'nonce-Nzg5YWJjZGVmMDEyMzQ1Ng=='"
	s := ExportService{HTTP: &probe.HTTP{Headers: map[string]string{"content-security-policy": raw}}}
	compared, shown := ServiceFields(s, nil)
	if compared["http.headers.content-security-policy"] != "script-src 'nonce-<volatile>'" {
		t.Errorf("compared = %v", compared["http.headers.content-security-policy"])
	}
	if shown["http.headers.content-security-policy"] != raw || s.HTTP.Headers["content-security-policy"] != raw {
		t.Errorf("shown = %v, stored = %v, want the raw header", shown["http.headers.content-security-policy"], s.HTTP.Headers["content-security-policy"])
	}
}

// REQ-DIFF-016
func TestUnstableFaviconIsNotCompared(t *testing.T) {
	stable := ExportService{HTTP: &probe.HTTP{FaviconSHA256: "aa"}}
	unstable := ExportService{HTTP: &probe.HTTP{FaviconSHA256: "bb", FaviconUnstable: true}}
	other := ExportService{HTTP: &probe.HTTP{FaviconSHA256: "cc"}}
	a, _ := ServiceFields(stable, nil)
	b, _ := ServiceFields(unstable, nil)
	c, _ := ServiceFields(other, nil)
	if got := ChangedFields(a, b, true); len(got) != 0 {
		t.Errorf("stable -> unstable favicon changed %v", got)
	}
	if got := ChangedFields(b, a, true); len(got) != 0 {
		t.Errorf("unstable -> stable favicon changed %v", got)
	}
	if got := ChangedFields(a, c, true); !reflect.DeepEqual(got, []string{FaviconField}) {
		t.Errorf("stable -> different stable favicon = %v, want %s", got, FaviconField)
	}
}

func titledService(title string) ExportService {
	return ExportService{Service: "http", HTTP: &probe.HTTP{StatusCode: 200, Title: title, Headers: map[string]string{}}}
}

func roundTrip(t *testing.T, st FieldState) *FieldState {
	t.Helper()
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	var out FieldState
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return &out
}

func volatileAfter(t *testing.T, titles []string) [][]VolatileField {
	t.Helper()
	var prev *FieldState
	var out [][]VolatileField
	for _, title := range titles {
		st := Learn(prev, titledService(title))
		out = append(out, st.Volatile())
		prev = roundTrip(t, st)
	}
	return out
}

func isVolatile(v []VolatileField, field string) bool {
	for _, f := range v {
		if f.Field == field {
			return true
		}
	}
	return false
}

// REQ-DIFF-015
func TestLearnVolatility(t *testing.T) {
	const f = "http.title"
	cases := []struct {
		name   string
		titles []string
		want   []bool
	}{
		{"stable", []string{"a", "a", "a", "a"}, []bool{false, false, false, false}},
		{"two changes are reported", []string{"a", "b", "c", "c", "d"}, []bool{false, false, false, false, false}},
		{"third change in a row marks volatile", []string{"a", "b", "c", "d", "e"}, []bool{false, false, false, true, true}},
		{"interrupted run of changes starts over", []string{"a", "b", "c", "c", "d", "e", "f"}, []bool{false, false, false, false, false, false, true}},
		{"stays volatile while stable for fewer than 3 runs", []string{"a", "b", "c", "d", "d", "d", "e"}, []bool{false, false, false, true, true, true, true}},
		{"stable for 3 runs then a change is reported again", []string{"a", "b", "c", "d", "d", "d", "d", "e"}, []bool{false, false, false, true, true, true, true, false}},
		{"after re-arming needs 3 changes again", []string{"a", "b", "c", "d", "d", "d", "d", "e", "f", "g"}, []bool{false, false, false, true, true, true, true, false, false, true}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := volatileAfter(t, c.titles)
			for i := range c.want {
				if isVolatile(got[i], f) != c.want[i] {
					t.Fatalf("run %d (%v): volatile = %v, want %v (all: %v)", i, c.titles[:i+1], !c.want[i], c.want[i], got)
				}
			}
		})
	}
}

func TestLearnKeepsLastValues(t *testing.T) {
	var titles []string
	for i := range 6 {
		titles = append(titles, "t"+strconv.Itoa(i))
	}
	got := volatileAfter(t, titles)
	last := got[len(got)-1]
	if len(last) != 1 || last[0].Field != "http.title" || !reflect.DeepEqual(last[0].Values, []any{"t3", "t4", "t5"}) {
		t.Fatalf("volatile = %+v, want http.title with the last 3 values", last)
	}
}

func TestLearnIgnoresFailedProbes(t *testing.T) {
	var prev *FieldState
	for i := range 6 {
		s := titledService("t" + strconv.Itoa(i))
		if i%2 == 1 {
			s.HTTP = &probe.HTTP{Error: probe.ErrorTimeout}
		}
		st := Learn(prev, s)
		if v := st.Volatile(); len(v) != 0 {
			t.Fatalf("run %d: volatile = %+v, want none: only product and version are compared against a failed probe", i, v)
		}
		prev = roundTrip(t, st)
	}
}

// REQ-DIFF-015
func TestLearnVolatileHeaderThatDisappears(t *testing.T) {
	const f = "http.headers.x-build"
	values := []string{"a1", "b2", "c3", "d4", "", "", "", "", "e5", "f6"}
	want := []bool{false, false, false, true, true, true, true, true, false, false}
	var prev *FieldState
	for i, v := range values {
		s := titledService("t")
		if v != "" {
			s.HTTP.Headers["x-build"] = v
		}
		st := Learn(prev, s)
		if got := isVolatile(st.Volatile(), f); got != want[i] {
			t.Fatalf("run %d (x-build %q): volatile = %v, want %v (track %+v)", i, v, got, want[i], st.Track[f])
		}
		prev = roundTrip(t, st)
	}
}
