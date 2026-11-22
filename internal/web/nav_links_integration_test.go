//go:build integration

package web

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"asi/internal/auth"
	"asi/internal/inventory"
	"asi/internal/schedule"
)

// REQ-WEB-021: AC5 of T-803xb7cwjk
func TestHostPageLinksTimeline(t *testing.T) {
	site := seedInventorySite(t)
	_, body := get(t, site.clients[auth.RoleViewer], site.url+"/hosts/10.0.0.1")
	if !strings.Contains(body, `<a class="btn" href="/hosts/10.0.0.1/timeline">Timeline</a>`) {
		t.Errorf("host page does not link its timeline:\n%s", body)
	}
}

// REQ-SCHEDULE-008: AC5 of T-803xb7cwjk
func TestScansListShowsLastRunDurationAndNextStart(t *testing.T) {
	inv, sched, h, fa := truthSite(t)
	ctx := context.Background()
	actor := auth.Actor{Username: "test", Addr: "local"}
	mk := func(name string) schedule.Definition {
		d, err := sched.Store.CreateDefinition(ctx, actor, schedule.Definition{Name: name, InactiveAfter: 3,
			Settings: inventory.RunSettings{Targets: []string{"10.0.0.0/30"}, Ports: []int{80}, MaxRate: 100, Workers: 1},
			Schedule: schedule.Schedule{Timezone: "America/New_York", Frequency: schedule.Frequency{Kind: schedule.FrequencyDaily}}})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	ran, never := mk("ran"), mk("never")
	if err := sched.Store.SetEnabled(ctx, actor, ran.ID, true); err != nil {
		t.Fatal(err)
	}
	run, err := sched.Store.StartRun(ctx, ran.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := inv.SetRunStatus(ctx, run.ID, inventory.RunCompleted); err != nil {
		t.Fatal(err)
	}
	body := do(h, http.MethodGet, "/scans", nil, fa.session(t, "alice")).Body.String()
	row := func(name string) string {
		m := regexp.MustCompile(`(?s)<tr[^>]*>\s*<td><a href="/scans/\d+">` + name + `</a></td>.*?</tr>`).FindString(body)
		if m == "" {
			t.Fatalf("scans list has no row for %s:\n%s", name, body)
		}
		return m
	}
	r := row(ran.Name)
	for _, re := range []string{`<span class="status[^"]*">Completed</span>`, `<td class="num">\d+ s</td>`, `<td class="nowrap">\d{4}-\d{2}-\d{2} \d{2}:\d{2} E[SD]T</td>`} {
		if !regexp.MustCompile(re).MatchString(r) {
			t.Errorf("row of a scan with a run does not match %s:\n%s", re, r)
		}
	}
	if n := row(never.Name); strings.Count(n, `<span class="muted">-</span>`) != 3 || !strings.Contains(n, "Never") {
		t.Errorf("row of a scan without runs, disabled, wants Never and three dashes:\n%s", n)
	}
	if !strings.Contains(body, `<th class="num">Duration</th><th>Next start</th>`) {
		t.Errorf("scans list lacks the Duration and Next start columns")
	}
}
