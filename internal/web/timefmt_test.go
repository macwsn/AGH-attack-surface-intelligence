package web

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"asi/internal/inventory"
)

// REQ-WEB-009: AC4 of T-803xb7cwjk
func TestZonedTime(t *testing.T) {
	warsaw, err := time.LoadLocation("Europe/Warsaw")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 21, 22, 42, 0, 0, time.UTC)
	if got := zonedTime(at, warsaw); got != "2026-11-21 23:42 CET" {
		t.Errorf("zonedTime in Warsaw = %q, want 2026-11-21 23:42 CET", got)
	}
	if got := zonedTime(at, zoneOf("America/New_York")); got != "2026-11-21 17:42 EST" {
		t.Errorf("zonedTime of a New York run in winter = %q, want EST", got)
	}
	if got := zonedTime(time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC), zoneOf("America/New_York")); got != "2026-07-01 08:00 EDT" {
		t.Errorf("zonedTime of a New York run in summer = %q, want EDT", got)
	}
	if got := zonedTime(time.Time{}, warsaw); got != "" {
		t.Errorf("zero time = %q, want empty", got)
	}
	zone := regexp.MustCompile(`\d{2}:\d{2} ([A-Z]{2,5}|[+-]\d{2,4})$`)
	for _, s := range []string{isoTime(at), formatTime(&at), zonedTime(at, zoneOf("")), zonedTime(at, zoneOf("Asia/Kolkata"))} {
		if !zone.MatchString(s) {
			t.Errorf("%q lacks a zone abbreviation", s)
		}
	}
	now := at.Add(3 * time.Minute)
	if got := ago(at, now); got != "3 minutes ago" {
		t.Errorf("ago = %q, want relative text for a recent time", got)
	}
}

// REQ-WEB-057: AC4 of T-803xb7cwjk
func TestRecentTimeIsRelativeWithZonedTitle(t *testing.T) {
	now := time.Date(2026, 11, 21, 22, 45, 0, 0, time.UTC)
	seen := now.Add(-3 * time.Minute)
	v := newDashboardView(inventory.Dashboard{Findings: []inventory.DashboardFinding{{Address: "10.0.0.1", Port: 80, Protocol: "tcp",
		Kind: "admin-panel", Name: "Admin", FirstSeen: seen}}}, changeSummary{Changes: map[string]int{}}, now)
	if len(v.Findings) != 1 {
		t.Fatalf("findings = %+v", v.Findings)
	}
	f := v.Findings[0]
	if f.Seen != "3 minutes ago" || f.SeenExact != zonedTime(seen, nil) {
		t.Errorf("finding seen %q title %q, want \"3 minutes ago\" with title %q", f.Seen, f.SeenExact, zonedTime(seen, nil))
	}
	if !regexp.MustCompile(`\d{2}:\d{2} ([A-Z]{2,5}|[+-]\d{2,4})$`).MatchString(f.SeenExact) {
		t.Errorf("title %q lacks a zone abbreviation", f.SeenExact)
	}
}

// REQ-WEB-057: AC4 of T-803xb7cwjk
func TestNoBareTimeLayoutsOutsideHelper(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	bare := regexp.MustCompile(`Format\("2006|\.Local\(\)\.Format|"15:04"`)
	for _, f := range files {
		if f == "timefmt.go" || strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			if bare.MatchString(line) {
				t.Errorf("%s:%d formats a time outside timefmt.go: %s", f, i+1, strings.TrimSpace(line))
			}
		}
	}
}

// REQ-WEB-037: AC4 of T-803xb7cwjk
func TestTemplatesFormatTimesThroughHelper(t *testing.T) {
	pages, err := filepath.Glob("*.html")
	if err != nil {
		t.Fatal(err)
	}
	bare := regexp.MustCompile(`\.Format "[0-9]|"2006-|"15:04`)
	for _, f := range pages {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			if bare.MatchString(line) {
				t.Errorf("%s:%d formats a time without the zoned helper: %s", f, i+1, strings.TrimSpace(line))
			}
		}
	}
	tmpl, err := parsePages(files)
	if err != nil || tmpl == nil {
		t.Fatalf("pages with the zoned func: %v", err)
	}
}
