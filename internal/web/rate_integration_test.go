//go:build integration

package web

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"asi/internal/auth"
	"asi/internal/inventory"
	"asi/internal/scan"
	"asi/internal/scan/nmap"
	"asi/internal/scan/nmap/nmaptest"
	"asi/internal/scan/scantest"
	"asi/internal/schedule"
	"asi/internal/store"
	"asi/internal/store/storetest"
)

// REQ-SCAN-020, REQ-SCAN-021
func TestScanPreviewAndRunRate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
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
	svc := auth.NewService(st, auth.Config{})
	if err := svc.CreateUser(ctx, auth.Actor{Username: "test", Addr: "local"}, "alice", "alice-password-123", auth.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	clock := scantest.NewClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	runner := &nmaptest.Runner{DiscoverFunc: func(ctx context.Context, _ []string, _ nmap.Options) ([]nmap.Host, error) {
		<-clock.After(30 * time.Second)
		return nil, nil
	}}
	inv := inventory.New(st, keys)
	sched := &schedule.Scheduler{Store: schedule.NewStore(st, keys), Scanner: &scan.Scanner{Store: inv, Runner: runner, Clock: clock}, Logf: t.Logf}
	sched.Start(ctx)
	t.Cleanup(sched.Wait)
	h, err := New(Deps{Store: st, Keyring: keys, Auth: svc, Scans: sched})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	d, err := sched.Store.CreateDefinition(ctx, auth.Actor{Username: "test", Addr: "local"}, schedule.Definition{
		Name: "campus", InactiveAfter: 3,
		Settings: inventory.RunSettings{Targets: []string{"10.0.0.0/24"}, Excludes: []string{"10.0.0.254"}, Ports: []int{80, 443}, MaxRate: 50, Workers: 1},
		Schedule: schedule.Schedule{Timezone: "UTC", Frequency: schedule.Frequency{Kind: schedule.FrequencyDaily}},
	})
	if err != nil {
		t.Fatal(err)
	}
	scanPath := "/scans/" + strconv.FormatInt(d.ID, 10)

	alice := signIn(t, srv.URL, "alice", "alice-password-123")
	if code, body := alice.get(scanPath); code != 200 || !strings.Contains(body, `href="`+scanPath+`/preview">Preview</a>`) {
		t.Fatalf("scan page = %d, want a Preview button:\n%s", code, body)
	}
	code, body := alice.get(scanPath + "/preview")
	for _, want := range []string{
		`<span class="value">253</span><span class="label">Addresses after excludes</span>`,
		`<dd class="addr">80, 443</dd>`,
		`<span class="value">4</span><span class="label">Groups</span>`,
		`<span class="value">6` + "\u2009" + `578</span><span class="label">Packets at most</span>`,
		`<span class="value">43` + "\u2009" + `516</span><span class="label">HTTP requests at most</span>`,
		`<span class="value">about 1-2 min</span><span class="label">Estimated duration</span>`,
		"No completed run of this scan yet.",
		"Nothing was sent to make this preview.",
	} {
		if code != 200 || !strings.Contains(body, want) {
			t.Fatalf("preview = %d, lacks %q:\n%s", code, want, body)
		}
	}
	if c := runner.Calls(); len(c) != 0 {
		t.Fatalf("preview called nmap: %v", c)
	}

	code, loc, _ := alice.post(scanPath+"/start", nil)
	m := regexp.MustCompile(`^/runs/(\d+)\?msg=started$`).FindStringSubmatch(loc)
	if code != http.StatusSeeOther || m == nil {
		t.Fatalf("start = %d %s", code, loc)
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		runs, err := sched.Store.Runs(ctx, d.ID, 1)
		if err != nil {
			t.Fatal(err)
		}
		if len(runs) == 1 && runs[0].Status == inventory.RunCompleted {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("run did not complete: %+v", runs)
		}
		time.Sleep(20 * time.Millisecond)
	}
	runID := m[1]
	samples, err := inv.RateSamples(ctx, mustInt(t, runID))
	if err != nil || len(samples) < 2 {
		t.Fatalf("rate samples = %+v, %v; want several minutes", samples, err)
	}
	for _, s := range samples {
		if s.Configured != 50 || s.Effective != 50 || s.PerSecond() > 50 {
			t.Fatalf("sample %+v: want limit 50 and actual at most 50/s", s)
		}
	}
	rs := scan.SummarizeRate(samples)
	code, body = alice.get("/runs/" + runID)
	for _, want := range []string{
		`<dt>Max rate</dt><dd class="num">50 per second</dd>`,
		`<dt>Adaptive rate</dt><dd>On</dd>`,
		`<dt>Peak sent</dt><dd class="num">` + fmt.Sprintf("%.1f", rs.Peak) + ` per second</dd>`,
		`<dt>Average sent</dt><dd class="num">` + fmt.Sprintf("%.1f", rs.Average) + ` per second</dd>`,
		`<svg class="chart" role="img" aria-label="Packets and requests sent per second`,
		`<rect class="sent" `,
		`<polyline class="limit" points="0,4 10,4`,
	} {
		if code != 200 || !strings.Contains(body, want) {
			t.Fatalf("run page = %d, lacks %q:\n%s", code, want, body)
		}
	}
	if strings.Contains(body, "style=") {
		t.Fatalf("run page has an inline style:\n%s", body)
	}

	_, body = alice.get(scanPath + "/preview")
	if !strings.Contains(body, `addresses per second, from run <a class="addr" href="/runs/`+runID+`">`) || strings.Contains(body, "No completed run") {
		t.Fatalf("preview after a run lacks the measured speed:\n%s", body)
	}
}

func mustInt(t *testing.T, s string) int64 {
	t.Helper()
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return n
}
