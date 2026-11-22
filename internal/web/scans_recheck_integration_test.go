//go:build integration

package web

import (
	"context"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
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

// REQ-WEB-026
func TestScanPagesRecheck(t *testing.T) {
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
	runner := &nmaptest.Runner{
		DiscoverFunc: func(_ context.Context, addrs []string, _ nmap.Options) ([]nmap.Host, error) {
			if slices.Contains(addrs, "10.70.0.5") {
				return []nmap.Host{{Address: "10.70.0.5", Up: true}}, nil
			}
			return nil, nil
		},
		ServicesFunc: func(_ context.Context, addrs []string, _ []int, _ nmap.Options) ([]nmap.Host, error) {
			if slices.Contains(addrs, "10.70.0.5") {
				return []nmap.Host{{Address: "10.70.0.5", Up: true, Ports: []nmap.Port{{Number: 22, Protocol: "tcp", State: "open", Service: "ssh"}}}}, nil
			}
			return nil, nil
		},
	}
	inv := inventory.New(st, keys)
	sched := &schedule.Scheduler{Store: schedule.NewStore(st, keys), Scanner: &scan.Scanner{Store: inv, Runner: runner, Clock: scantest.NewClock(time.Unix(0, 0))}, Logf: t.Logf}
	sched.Start(ctx)
	t.Cleanup(sched.Wait)
	h, err := New(Deps{Store: st, Keyring: keys, Auth: svc, Scans: sched})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	alice := signIn(t, srv.URL, "alice", "alice-password-123")

	if _, body := alice.get("/scans/new"); !strings.Contains(body, `name="recheck_every"`) || !strings.Contains(body, "Recheck every") {
		t.Fatalf("new form lacks the recheck field:\n%s", body)
	}
	form := url.Values{
		"name": {"rhythm"}, "targets": {"10.70.0.0/29"}, "excludes": {""}, "ports": {"22"},
		"max_rate": {"50"}, "workers": {"1"}, "inactive_after": {"3"}, "signatures_dir": {""},
		"timezone": {"UTC"}, "windows": {""}, "frequency": {"daily"}, "recheck_every": {"24h"},
	}
	code, _, body := alice.post("/scans", form)
	if code != http.StatusUnprocessableEntity || !strings.Contains(body, `name="recheck_every" value="24h" aria-invalid="true"`) ||
		!strings.Contains(body, `<span class="problem">&#34;24h&#34; must be shorter than the full scan frequency`) {
		t.Fatalf("recheck not shorter than daily = %d:\n%s", code, body)
	}
	form.Set("recheck_every", "30s")
	if code, _, body := alice.post("/scans", form); code != http.StatusUnprocessableEntity || !strings.Contains(body, `<span class="problem">&#34;30s&#34; must be a duration of at least`) {
		t.Fatalf("recheck below 1m = %d:\n%s", code, body)
	}
	var defs int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM scan_definitions`).Scan(&defs); err != nil || defs != 0 {
		t.Fatalf("invalid forms stored %d definitions (%v)", defs, err)
	}
	form.Set("recheck_every", "1h")
	code, loc, _ := alice.post("/scans", form)
	if code != http.StatusSeeOther {
		t.Fatalf("create = %d %s", code, loc)
	}
	scanPath := strings.TrimSuffix(loc, "?msg=created")
	if _, body := alice.get(scanPath + "/edit"); !strings.Contains(body, `name="recheck_every" value="1h"`) {
		t.Errorf("edit form lacks the stored recheck interval:\n%s", body)
	}
	if _, body := alice.get(scanPath); !strings.Contains(body, "Start scan now") || !strings.Contains(body, `name="mode" value="recheck"`) ||
		!strings.Contains(body, "Start recheck") || !strings.Contains(body, "Every <span class=\"num\">1h</span>") {
		t.Errorf("scan page lacks the recheck control:\n%s", body)
	}

	runCount := func() int {
		var n int
		if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM runs`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if code, _, body := alice.post(scanPath+"/start", url.Values{"mode": {"bogus"}}); code != http.StatusBadRequest || runCount() != 0 {
		t.Fatalf("mode=bogus = %d, %d runs:\n%s", code, runCount(), body)
	}
	code, _, body = alice.post(scanPath+"/start", url.Values{"mode": {"recheck"}})
	if code != http.StatusUnprocessableEntity || !strings.Contains(body, "no earlier run to recheck") || !strings.Contains(body, `class="notice error"`) || runCount() != 0 {
		t.Fatalf("recheck without base = %d, %d runs:\n%s", code, runCount(), body)
	}
	if len(runner.Calls()) != 0 {
		t.Fatalf("recheck without base called nmap %d times", len(runner.Calls()))
	}

	waitDone := func(loc string) {
		t.Helper()
		m := runPath.FindStringSubmatch(loc)
		if m == nil {
			t.Fatalf("start redirected to %q", loc)
		}
		deadline := time.Now().Add(10 * time.Second)
		for {
			if _, body := alice.get("/runs/" + m[1]); strings.Contains(body, "Completed") {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("run %s never completed", m[1])
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	code, loc, _ = alice.post(scanPath+"/start", nil)
	if code != http.StatusSeeOther {
		t.Fatalf("full start = %d", code)
	}
	waitDone(loc)
	code, loc, _ = alice.post(scanPath+"/start", url.Values{"mode": {"recheck"}})
	if code != http.StatusSeeOther {
		t.Fatalf("recheck start = %d", code)
	}
	waitDone(loc)

	var modes []string
	rows, err := st.Pool.Query(ctx, `SELECT COALESCE(settings->>'mode', '') FROM runs ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var m string
		if err := rows.Scan(&m); err != nil {
			t.Fatal(err)
		}
		modes = append(modes, m)
	}
	if rows.Err() != nil || !slices.Equal(modes, []string{inventory.ModeFull, inventory.ModeRecheck}) {
		t.Fatalf("run modes = %v (%v)", modes, rows.Err())
	}
	var starts int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE actor = 'alice' AND action = 'scan.start'`).Scan(&starts); err != nil || starts != 2 {
		t.Errorf("scan.start audit entries = %d (%v), want 2", starts, err)
	}

	if _, err := st.Pool.Exec(ctx, `UPDATE runs SET packets = CASE WHEN settings->>'mode' = 'recheck' THEN 100 ELSE 2000 END`); err != nil {
		t.Fatal(err)
	}
	_, body = alice.get(scanPath)
	for _, want := range []string{"<th>Mode</th>", "<th class=\"num\">Packets</th>", "<th class=\"num\">Saving</th>",
		"<td>Full</td>", "<td>Recheck</td>", `<td class="num">2000</td><td class="num">—</td>`, `<td class="num">100</td><td class="num">95%</td>`} {
		if !strings.Contains(body, want) {
			t.Errorf("scan page lacks %s:\n%s", want, body)
		}
	}
	if regexp.MustCompile(`style\s*=`).MatchString(body) {
		t.Error("scan page uses inline styles")
	}
}

// REQ-WEB-026
func TestRecheckSavingWithoutFullRun(t *testing.T) {
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
	ss := schedule.NewStore(st, keys)
	actor := auth.Actor{Username: "test", Addr: "local"}
	d, err := ss.CreateDefinition(ctx, actor, schedule.Definition{Name: "solo", InactiveAfter: 3,
		Settings: inventory.RunSettings{Targets: []string{"10.80.0.0/30"}, Excludes: []string{}, Ports: []int{22}, MaxRate: 50, Workers: 1},
		Schedule: schedule.Schedule{Frequency: schedule.Frequency{Kind: schedule.FrequencyDaily}}})
	if err != nil {
		t.Fatal(err)
	}
	finish := func(r schedule.Run, packets int) {
		t.Helper()
		if _, err := st.Pool.Exec(ctx, `UPDATE runs SET status = 'completed', finished_at = now(), packets = $2 WHERE id = $1`, r.ID, packets); err != nil {
			t.Fatal(err)
		}
	}
	r1, err := ss.StartRunMode(ctx, d.ID, time.Now(), inventory.ModeRecheck, nil)
	if err != nil {
		t.Fatal(err)
	}
	finish(r1, 40)
	r2, err := ss.StartRunMode(ctx, d.ID, time.Now(), inventory.ModeFull, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE runs SET status = 'failed', finished_at = now(), packets = 5 WHERE id = $1`, r2.ID); err != nil {
		t.Fatal(err)
	}
	r3, err := ss.StartRunMode(ctx, d.ID, time.Now(), inventory.ModeRecheck, nil)
	if err != nil {
		t.Fatal(err)
	}
	finish(r3, 30)

	fa := newFakeAuth()
	h, err := New(Deps{Store: st, Keyring: keys, Auth: fa, Scans: &schedule.Scheduler{Store: ss, Scanner: &scan.Scanner{Store: inventory.New(st, keys)}}})
	if err != nil {
		t.Fatal(err)
	}
	page := "/scans/" + strconv.FormatInt(d.ID, 10)
	rec := do(h, http.MethodGet, page, nil, fa.session(t, "alice"))
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("scan page = %d:\n%s", rec.Code, body)
	}
	for _, want := range []string{`<td class="num">40</td><td class="num">—</td>`, `<td class="num">5</td><td class="num">—</td>`,
		`<td class="num">30</td><td class="num">—</td>`} {
		if !strings.Contains(body, want) {
			t.Errorf("scan page lacks %s:\n%s", want, body)
		}
	}
	if strings.Contains(body, "%</td>") {
		t.Errorf("recheck without an earlier completed full run shows a saving:\n%s", body)
	}

	full, err := ss.StartRunMode(ctx, d.ID, time.Now(), inventory.ModeFull, nil)
	if err != nil {
		t.Fatal(err)
	}
	finish(full, 2000)
	for range runListLimit + 1 {
		r, err := ss.StartRunMode(ctx, d.ID, time.Now(), inventory.ModeRecheck, nil)
		if err != nil {
			t.Fatal(err)
		}
		finish(r, 100)
	}
	body = do(h, http.MethodGet, page, nil, fa.session(t, "alice")).Body.String()
	if got := strings.Count(body, `<td class="num">100</td><td class="num">95%</td>`); got != runListLimit {
		t.Errorf("rechecks whose full run is older than the listed runs show the saving %d times, want %d:\n%s", got, runListLimit, body)
	}
}

// REQ-SCAN-020 REQ-SCAN-021
func TestPreviewRecheckAndEstimatedRate(t *testing.T) {
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
	host := "10.71.0.5"
	runner := &nmaptest.Runner{
		DiscoverFunc: func(_ context.Context, addrs []string, _ nmap.Options) ([]nmap.Host, error) {
			if slices.Contains(addrs, host) {
				return []nmap.Host{{Address: host, Up: true}}, nil
			}
			return nil, nil
		},
		ServicesFunc: func(_ context.Context, addrs []string, _ []int, _ nmap.Options) ([]nmap.Host, error) {
			if slices.Contains(addrs, host) {
				return []nmap.Host{{Address: host, Up: true, Ports: []nmap.Port{
					{Number: 22, Protocol: "tcp", State: "open", Service: "ssh"},
					{Number: 80, Protocol: "tcp", State: "open", Service: "http"}}}}, nil
			}
			return nil, nil
		},
	}
	clock := scantest.NewClock(time.Unix(0, 0))
	tr := &scantest.Transport{Clock: clock}
	inv := inventory.New(st, keys)
	sched := &schedule.Scheduler{Store: schedule.NewStore(st, keys), Scanner: &scan.Scanner{Store: inv, Runner: runner, Clock: clock, Transport: tr.For}, Logf: t.Logf}
	sched.Start(ctx)
	t.Cleanup(sched.Wait)
	h, err := New(Deps{Store: st, Keyring: keys, Auth: svc, Scans: sched})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	alice := signIn(t, srv.URL, "alice", "alice-password-123")

	code, loc, _ := alice.post("/scans", url.Values{
		"name": {"lowrate"}, "targets": {"10.71.0.0/29"}, "excludes": {""}, "ports": {"22,80"},
		"max_rate": {"6"}, "workers": {"4"}, "inactive_after": {"3"}, "signatures_dir": {""},
		"timezone": {"UTC"}, "windows": {""}, "frequency": {"daily"}, "recheck_every": {"1h"},
	})
	if code != http.StatusSeeOther {
		t.Fatalf("create = %d %s", code, loc)
	}
	scanPath := strings.TrimSuffix(loc, "?msg=created")
	if _, body := alice.get(scanPath); !strings.Contains(body, `href="`+scanPath+`/preview?mode=recheck">Preview recheck</a>`) {
		t.Fatalf("scan page lacks the recheck preview:\n%s", body)
	}
	if code, body := alice.get(scanPath + "/preview?mode=recheck"); code != http.StatusUnprocessableEntity || !strings.Contains(body, "Run a full scan of this definition first") {
		t.Fatalf("recheck preview without base = %d:\n%s", code, body)
	}
	if code, _ := alice.get(scanPath + "/preview?mode=bogus"); code != http.StatusBadRequest {
		t.Fatalf("preview mode=bogus = %d", code)
	}
	code, body := alice.get(scanPath + "/preview")
	for _, want := range []string{
		`<dt>Mode</dt><dd>Full</dd>`,
		`<dt>Lowest rate</dt><dd class="num">6 per second: nmap sends at least one packet per second per slot (nmap slots: 3)</dd>`,
	} {
		if code != 200 || !strings.Contains(body, want) || strings.Contains(body, "Recheck: only") {
			t.Fatalf("full preview = %d, lacks %q:\n%s", code, want, body)
		}
	}

	code, loc, _ = alice.post(scanPath+"/start", nil)
	m := runPath.FindStringSubmatch(loc)
	if code != http.StatusSeeOther || m == nil {
		t.Fatalf("start = %d %s", code, loc)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, body := alice.get("/runs/" + m[1]); strings.Contains(body, "Completed") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("run %s never completed", m[1])
		}
		time.Sleep(20 * time.Millisecond)
	}
	runs, err := sched.Store.Runs(ctx, mustInt(t, strings.TrimPrefix(scanPath, "/scans/")), 1)
	if err != nil || len(runs) != 1 {
		t.Fatalf("runs = %+v, %v", runs, err)
	}

	code, body = alice.get(scanPath + "/preview?mode=recheck")
	for _, want := range []string{
		"Recheck: only the 2 known open services of run " + runs[0].Name + " are planned",
		`<span class="value">1</span><span class="label">Hosts with known services</span>`,
		`<dt>Mode</dt><dd>Recheck of 2 known services from run ` + runs[0].Name + `</dd>`,
		`<dt>Lowest rate</dt><dd class="num">2 per second: nmap sends at least one packet per second per slot (nmap slots: 1)</dd>`,
	} {
		if code != 200 || !strings.Contains(body, want) {
			t.Fatalf("recheck preview = %d, lacks %q:\n%s", code, want, body)
		}
	}
	if regexp.MustCompile(`style\s*=`).MatchString(body) {
		t.Fatalf("recheck preview has an inline style:\n%s", body)
	}

	samples, err := inv.RateSamples(ctx, runs[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	rs := scan.SummarizeRate(samples)
	if rs.Requests == 0 || rs.Packets == 0 || rs.Requests+rs.Packets != runs[0].Packets {
		t.Fatalf("stored samples: %d requests + %d estimated packets, run packets %d", rs.Requests, rs.Packets, runs[0].Packets)
	}
	code, body = alice.get("/runs/" + m[1])
	for _, want := range []string{
		`<dt>HTTP requests</dt><dd class="num">` + strconv.Itoa(rs.Requests) + ` measured</dd>`,
		`<dt>nmap packets</dt><dd class="num">` + strconv.Itoa(rs.Packets) + ` estimated, peak `,
		`<dt>Lowest rate</dt><dd class="num">6 per second: nmap sends at least one packet per second per slot (nmap slots: 3)</dd>`,
		"nmap packets are estimated from the addresses and ports of each nmap call",
		"HTTP requests (measured) plus nmap packets (estimated)",
	} {
		if code != 200 || !strings.Contains(body, want) {
			t.Fatalf("run page = %d, lacks %q:\n%s", code, want, body)
		}
	}
	if regexp.MustCompile(`style\s*=`).MatchString(body) {
		t.Fatalf("run page has an inline style:\n%s", body)
	}
}
