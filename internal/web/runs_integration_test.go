//go:build integration

package web

import (
	"context"
	"crypto/rand"
	"net/http"
	"strings"
	"testing"
	"time"

	"asi/internal/inventory"
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
	h, err := New(Deps{Store: st, Keyring: keys, Auth: fa})
	if err != nil {
		t.Fatal(err)
	}
	rec := do(h, http.MethodGet, "/runs/by-name/nightly", nil, fa.session(t, "victor"))
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /runs/by-name/nightly = %d:\n%s", rec.Code, body)
	}
	for _, want := range []string{
		`<span class="value">2.0</span><span class="label">Addresses per second</span>`,
		`<span class="value">1 / 20</span><span class="label">Groups done</span>`,
		`<span class="value">18s</span><span class="label">Estimated time left</span>`,
		`<td>group 1: context deadline exceeded</td>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("run page lacks %s", want)
		}
	}
	if strings.Contains(body, "style=") {
		t.Error("run page uses inline styles")
	}
	if rec := do(h, http.MethodGet, "/runs/by-name/nope", nil, fa.session(t, "victor")); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown run = %d, want 404", rec.Code)
	}
}
