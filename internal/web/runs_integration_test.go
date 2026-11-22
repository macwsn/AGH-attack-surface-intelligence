//go:build integration

package web

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"asi/internal/inventory"
	"asi/internal/scan"
	"asi/internal/schedule"
	"asi/internal/store"
	"asi/internal/store/storetest"
)

// REQ-SCAN-009
func TestRunPageShowsProgress(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, storetest.DatabaseURL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if _, err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	keys, err := store.NewKeyring(master)
	if err != nil {
		t.Fatal(err)
	}
	inv := inventory.New(st, keys)
	run, err := inv.CreateRun(ctx, inventory.RunSpec{Name: "nightly", Settings: inventory.RunSettings{Workers: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if err := inv.SetRunTotal(ctx, run.ID, 40); err != nil {
		t.Fatal(err)
	}
	if err := inv.RecordGroup(ctx, run.ID, inventory.GroupResult{Index: 0, Addresses: []string{"10.50.0.1", "10.50.0.2"}, Duration: time.Second}); err != nil {
		t.Fatal(err)
	}
	if err := inv.RecordFailedGroup(ctx, run.ID, inventory.FailedGroup{Index: 1, Addresses: []string{"10.50.0.3", "10.50.0.4"}, Reason: "group 1: context deadline exceeded"}); err != nil {
		t.Fatal(err)
	}

	fa := newFakeAuth()
	sched := &schedule.Scheduler{Store: schedule.NewStore(st, keys), Scanner: &scan.Scanner{Store: inv}}
	h, err := New(Deps{Store: st, Keyring: keys, Auth: fa, Scans: sched})
	if err != nil {
		t.Fatal(err)
	}
	rec := do(h, http.MethodGet, "/runs?name=nightly", nil, fa.session(t, "alice"))
	if want := fmt.Sprintf("/runs/%d", run.ID); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != want {
		t.Fatalf("GET /runs?name=nightly = %d %q, want 303 %q", rec.Code, rec.Header().Get("Location"), want)
	}
	rec = do(h, http.MethodGet, rec.Header().Get("Location"), nil, fa.session(t, "alice"))
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /runs/%d = %d:\n%s", run.ID, rec.Code, body)
	}
	for _, want := range []string{
		`<span class="value">2.0</span><span class="label">Addresses per second</span>`,
		`<span class="value">1 / 20</span><span class="label">Groups done</span>`,
		`<span class="value">18 s</span><span class="label">Estimated time left</span>`,
		`<div class="figure is-alert"><span class="value">1</span><span class="label">Failed groups</span>`,
		`<td>group 1: context deadline exceeded</td>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("run page lacks %s", want)
		}
	}
	if strings.Contains(body, "style=") {
		t.Error("run page uses inline styles")
	}
	if rec := do(h, http.MethodGet, "/runs?name=nope", nil, fa.session(t, "alice")); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown run = %d, want 404", rec.Code)
	}
	for _, path := range []string{"/runs?name=nightly"} {
		if rec := do(h, http.MethodGet, path, nil, fa.session(t, "victor")); rec.Code != http.StatusForbidden {
			t.Errorf("viewer GET %s = %d, want 403", path, rec.Code)
		}
	}
	if rec := do(h, http.MethodGet, fmt.Sprintf("/runs/%d", run.ID), nil, fa.session(t, "victor")); rec.Code != http.StatusOK {
		t.Errorf("viewer GET /runs/%d = %d, want 200", run.ID, rec.Code)
	}
	if rec := do(h, http.MethodGet, "/runs/by-name/nightly", nil, fa.session(t, "alice")); rec.Code != http.StatusNotFound {
		t.Fatalf("GET /runs/by-name/nightly = %d, want 404", rec.Code)
	}
}

// REQ-SCAN-024
func TestRunPageShowsStalledRun(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, storetest.DatabaseURL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if _, err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	keys, err := store.NewKeyring(master)
	if err != nil {
		t.Fatal(err)
	}
	inv := inventory.New(st, keys)
	fa := newFakeAuth()
	sched := &schedule.Scheduler{Store: schedule.NewStore(st, keys), Scanner: &scan.Scanner{Store: inv}}
	h, err := New(Deps{Store: st, Keyring: keys, Auth: fa, Scans: sched})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, beat, want, not string
	}{
		{"alive", "now()", `<span class="status active">Running</span>`, "Stalled (process gone)"},
		{"gone", "now() - interval '61 seconds'", "Stalled (process gone)", `<span class="status active">Running</span>`},
	} {
		run, err := inv.CreateRun(ctx, inventory.RunSpec{Name: tc.name, Settings: inventory.RunSettings{Workers: 1}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.Pool.Exec(ctx, `UPDATE runs SET heartbeat_at = `+tc.beat+` WHERE id = $1`, run.ID); err != nil {
			t.Fatal(err)
		}
		rec := do(h, http.MethodGet, fmt.Sprintf("/runs/%d", run.ID), nil, fa.session(t, "alice"))
		body := rec.Body.String()
		if rec.Code != http.StatusOK || !strings.Contains(body, tc.want) || strings.Contains(body, tc.not) {
			t.Fatalf("%s: GET /runs/%d = %d, want %q and not %q:\n%s", tc.name, run.ID, rec.Code, tc.want, tc.not, body)
		}
	}
}
