//go:build integration

package web

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"asi/internal/auth"
	"asi/internal/inventory"
	"asi/internal/store"
	"asi/internal/store/storetest"
)

// REQ-WEB-025
func TestAvailabilityPageFromCoveringRuns(t *testing.T) {
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
	day := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	n := 0
	cover := func(at time.Time, seen bool) {
		t.Helper()
		n++
		run, err := inv.CreateRun(ctx, inventory.RunSpec{Name: fmt.Sprintf("r%d", n), InactiveAfter: 3,
			Settings: inventory.RunSettings{Targets: []string{"10.60.0.0/30"}, Ports: []int{22}, Workers: 1}})
		if err != nil {
			t.Fatal(err)
		}
		g := inventory.GroupResult{Index: 0, Addresses: []string{"10.60.0.1", "10.60.0.2"}, Duration: time.Second}
		if seen {
			g.Hosts = append(g.Hosts, inventory.HostResult{Address: "10.60.0.1",
				Services: []inventory.ServiceResult{{Port: 22, Protocol: "tcp", State: "open", Service: "ssh"}}})
		}
		if n == 1 {
			g.Hosts = append(g.Hosts, inventory.HostResult{Address: "10.60.0.2"})
		}
		if err := inv.RecordGroup(ctx, run.ID, g); err != nil {
			t.Fatal(err)
		}
		if _, err := st.Pool.Exec(ctx, `UPDATE run_groups SET completed_at = $2 WHERE run_id = $1`, run.ID, at); err != nil {
			t.Fatal(err)
		}
		if err := inv.SetRunStatus(ctx, run.ID, inventory.RunCompleted); err != nil {
			t.Fatal(err)
		}
	}
	for d := 0; d < 3; d++ {
		for h := 8; h <= 17; h++ {
			cover(day.AddDate(0, 0, d).Add(time.Duration(h)*time.Hour+30*time.Minute), true)
		}
		cover(day.AddDate(0, 0, d).Add(2*time.Hour), false)
	}

	fa := newFakeAuth()
	fa.passwords["olga"] = "olga-password-1"
	fa.roles["olga"] = auth.Principal{Username: "olga", Role: auth.RoleOperator, Permissions: []auth.Permission{auth.PermScanRun}}
	h, err := New(Deps{Store: st, Keyring: keys, Auth: fa})
	if err != nil {
		t.Fatal(err)
	}
	victor := fa.session(t, "victor")
	rec := do(h, http.MethodGet, "/hosts/10.60.0.1/availability", nil, victor)
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("availability page = %d:\n%s", rec.Code, body)
	}
	strip := body[strings.Index(body, `<span class="presence">`):]
	strip = strip[:strings.Index(strip, "</span>")]
	if got := strings.Count(strip, "<i"); got != 24 {
		t.Errorf("strip has %d cells, want 24:\n%s", got, strip)
	}
	for _, want := range []string{`<i class="seen" title="08:00 up 83%">`, `<i class="seen" title="17:00 up 83%">`,
		`<i class="missed" title="02:00 up 17%">`, `<i title="18:00 up 50%">`, "Usually up 08:00-18:00", `<dd class="num">33</dd>`} {
		if !strings.Contains(body, want) {
			t.Errorf("availability page lacks %s:\n%s", want, body)
		}
	}
	if regexp.MustCompile(`style\s*=`).MatchString(body) {
		t.Error("availability page uses inline styles")
	}

	rec = do(h, http.MethodGet, "/hosts/10.60.0.2/availability", nil, victor)
	if body := rec.Body.String(); rec.Code != http.StatusOK || !strings.Contains(body, "No regular hours yet") || !strings.Contains(body, `class="presence"`) {
		t.Errorf("non-periodic host = %d:\n%s", rec.Code, body)
	}
	for _, addr := range []string{"10.60.0.3", "10.99.0.1", "not-an-address"} {
		if rec := do(h, http.MethodGet, "/hosts/"+addr+"/availability", nil, victor); rec.Code != http.StatusNotFound {
			t.Errorf("GET availability of %s = %d, want 404", addr, rec.Code)
		}
	}
	if rec := do(h, http.MethodGet, "/hosts/10.60.0.1/availability", nil, fa.session(t, "olga")); rec.Code != http.StatusForbidden {
		t.Errorf("user without inventory.read = %d, want 403", rec.Code)
	}
}

// REQ-WEB-025
func TestAvailabilityPageRecordedHostWithoutSamples(t *testing.T) {
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
	if _, err := st.Pool.Exec(ctx, `INSERT INTO hosts (address) VALUES ('10.61.0.7')`); err != nil {
		t.Fatal(err)
	}
	fa := newFakeAuth()
	h, err := New(Deps{Store: st, Keyring: keys, Auth: fa})
	if err != nil {
		t.Fatal(err)
	}
	victor := fa.session(t, "victor")
	rec := do(h, http.MethodGet, "/hosts/10.61.0.7/availability", nil, victor)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "No availability data yet") || strings.Contains(body, `class="presence"`) {
		t.Errorf("recorded host without samples = %d:\n%s", rec.Code, body)
	}
	if rec := do(h, http.MethodGet, "/hosts/10.61.0.8/availability", nil, victor); rec.Code != http.StatusNotFound {
		t.Errorf("GET availability of unrecorded host = %d, want 404", rec.Code)
	}
}
