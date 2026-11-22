//go:build integration

package web

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"asi/internal/inventory"
)

// REQ-SCAN-009: AC2 of T-803xb7cwjk
func TestRunPagePollingFollowsRunState(t *testing.T) {
	inv, _, h, fa := truthSite(t)
	ctx := context.Background()
	addrs := []string{"10.63.0.1", "10.63.0.2", "10.63.0.3", "10.63.0.4"}
	run := truthRun(t, inv, "paused-run", inventory.SourceScan, inventory.RunPaused, addrs, nil)
	page := fmt.Sprintf("/runs/%d", run.ID)
	poll := `hx-get="` + page + `" hx-trigger="every 3s" hx-select="#run-live" hx-swap="outerHTML"`

	rec := do(h, http.MethodGet, page, nil, fa.session(t, "alice"))
	if body := rec.Body.String(); rec.Code != http.StatusOK || !strings.Contains(body, poll) {
		t.Fatalf("paused run page = %d, lacks %q:\n%s", rec.Code, poll, body)
	}
	rec = do(h, http.MethodGet, "/", nil, fa.session(t, "alice"))
	if body := section(rec.Body.String(), "Latest run"); !pollAttr.MatchString(rec.Body.String()) || !strings.Contains(rec.Body.String(), `hx-select="#latest-run"`) {
		t.Errorf("dashboard does not poll the latest run while it is paused:\n%s", body)
	}

	if err := inv.SetRunStatus(ctx, run.ID, inventory.RunRunning); err != nil {
		t.Fatal(err)
	}
	if err := inv.Heartbeat(ctx, run.ID, 2); err != nil {
		t.Fatal(err)
	}
	rec = do(h, http.MethodGet, page, nil, fa.session(t, "alice"))
	body := rec.Body.String()
	for _, want := range []string{poll, `<span class="value">50%</span><span class="label">Done</span>`, `<span class="value">2 / 4</span><span class="label">Addresses scanned</span>`} {
		if !strings.Contains(body, want) {
			t.Errorf("running run page with 2 addresses in flight lacks %q:\n%s", want, body)
		}
	}
	rec = do(h, http.MethodGet, "/", nil, fa.session(t, "alice"))
	if latest := section(rec.Body.String(), "Latest run"); !strings.Contains(latest, `<dt>Addresses covered</dt><dd class="num">2</dd>`) {
		t.Errorf("dashboard does not count the addresses in flight:\n%s", latest)
	}

	if err := inv.RecordGroup(ctx, run.ID, inventory.GroupResult{Index: 0, Addresses: addrs[:2], Hosts: []inventory.HostResult{}, Duration: time.Second}); err != nil {
		t.Fatal(err)
	}
	rec = do(h, http.MethodGet, page, nil, fa.session(t, "alice"))
	if body := rec.Body.String(); !strings.Contains(body, `<span class="value">2 / 4</span><span class="label">Addresses scanned</span>`) {
		t.Errorf("recording the group that was in flight counts its addresses twice:\n%s", body)
	}

	if body := rec.Body.String(); !regexp.MustCompile(`<p class="muted">Estimate: (about 1 min or less|about \d+(-\d+)? (min|h)) left, from the speed of the finished groups\.</p>`).MatchString(body) {
		t.Errorf("running run page with a finished group lacks the remaining-time estimate range:\n%s", body)
	}

	unauth := httptest.NewRequest(http.MethodGet, page, nil)
	unauth.Header.Set("HX-Request", "true")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, unauth)
	if rr.Code != http.StatusUnauthorized || strings.Contains(rr.Body.String(), "<html") {
		t.Errorf("unauthenticated poll = %d, want 401 without a page:\n%s", rr.Code, rr.Body.String())
	}

	if err := inv.SetRunStatus(ctx, run.ID, inventory.RunCompleted); err != nil {
		t.Fatal(err)
	}
	rec = do(h, http.MethodGet, page, nil, fa.session(t, "alice"))
	body = rec.Body.String()
	if pollAttr.MatchString(body) || strings.Contains(body, "hx-get=") {
		t.Errorf("completed run page still polls:\n%s", body)
	}
	if !strings.Contains(body, `id="run-live"`) {
		t.Errorf("completed run page lacks the swap target #run-live, so the last poll cannot replace the live block")
	}
	rec = do(h, http.MethodGet, "/", nil, fa.session(t, "alice"))
	if pollAttr.MatchString(rec.Body.String()) {
		t.Errorf("dashboard still polls after the run completed")
	}
	if regexp.MustCompile(`style\s*=`).MatchString(body) {
		t.Errorf("run page uses inline styles")
	}
}
