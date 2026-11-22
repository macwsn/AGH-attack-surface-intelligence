//go:build integration

package inventory_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"asi/internal/detect"
	"asi/internal/diff"
	"asi/internal/inventory"
	"asi/internal/probe"
	"asi/internal/store"
	"asi/internal/store/storetest"
)

func openHuntInventory(t *testing.T) (*inventory.Inventory, *store.Store, *store.Keyring) {
	t.Helper()
	ctx := context.Background()
	s, err := store.Open(ctx, storetest.DatabaseURL(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(s.Close)
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatalf("master key: %v", err)
	}
	k, err := store.NewKeyring(master)
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	return inventory.New(s, k), s, k
}

func grafanaService(title, body string) inventory.ServiceResult {
	svc := web(title, nil)
	svc.HTTP.Cookies = []probe.Cookie{{Name: "grafana_session"}}
	if body != "" {
		svc.Body = []byte(body)
	}
	return svc
}

func hunt(t *testing.T, inv *inventory.Inventory, src string, since time.Time) (inventory.Hunt, []inventory.HuntResult) {
	t.Helper()
	ctx := context.Background()
	sig, err := detect.ParseOne([]byte(src))
	if err != nil {
		t.Fatalf("ParseOne: %v", err)
	}
	h, err := inv.RunHunt(ctx, inventory.HuntSpec{Signature: sig, Source: src, Since: since, Actor: "eddie", Addr: "10.9.9.9"})
	if err != nil {
		t.Fatalf("RunHunt: %v", err)
	}
	var out []inventory.HuntResult
	if err := inv.HuntResults(ctx, h.ID, 0, 0, func(r inventory.HuntResult) error { out = append(out, r); return nil }); err != nil {
		t.Fatalf("HuntResults: %v", err)
	}
	return h, out
}

const huntSignature = `id: grafana-hunt
name: Grafana
kind: technology
confidence: 90
match:
  all:
    - {type: status, value: 200}
    - {type: title_regex, value: Grafana}
    - {type: header, name: Server, value: nginx}
    - {type: cookie, name: '^grafana_'}
  any:
    - {type: body_regex, value: 'Grafana v[0-9.]+'}
version: {type: body_regex, value: 'Grafana v([0-9.]+)', group: 1}
`

// REQ-SIGNATURES-006 REQ-SIGNATURES-007 REQ-SIGNATURES-010 REQ-SIGNATURES-011
func TestRetroHuntOverHistory(t *testing.T) {
	ctx := context.Background()
	inv, s, keys := openHuntInventory(t)
	group := func(hosts ...inventory.HostResult) inventory.GroupResult {
		g := inventory.GroupResult{Index: 0, Hosts: hosts}
		for _, h := range hosts {
			g.Addresses = append(g.Addresses, h.Address)
		}
		return g
	}
	svc := func(addr string, s inventory.ServiceResult) inventory.HostResult {
		return inventory.HostResult{Address: addr, Services: []inventory.ServiceResult{s}}
	}
	ssh := inventory.HostResult{Address: "10.0.0.4", Services: []inventory.ServiceResult{{Port: 22, Protocol: "tcp", State: "open", Service: "ssh"}}}
	big := "<title>x</title>Grafana v9.1 " + strings.Repeat("a", 70<<10)
	r1 := createRun(t, inv, "r1")
	record(t, inv, r1, group(svc("10.0.0.1", grafanaService("Grafana", big)), svc("10.0.0.2", grafanaService("Other", "Grafana v1")),
		svc("10.0.0.3", grafanaService("Grafana", "")), ssh))
	r2 := createRun(t, inv, "r2")
	record(t, inv, r2, group(svc("10.0.0.1", grafanaService("Grafana", "Grafana v9.2")), svc("10.0.0.2", grafanaService("Other", "Grafana v1")), ssh))
	r3 := createRun(t, inv, "r3")
	record(t, inv, r3, group(svc("10.0.0.1", grafanaService("Login", "Grafana v9.3")), svc("10.0.0.2", grafanaService("Grafana", "Grafana v10.0")), ssh))
	if _, err := s.Pool.Exec(ctx, `UPDATE runs SET started_at = now() - make_interval(days => 3 - id::int) WHERE id IN ($1, $2, $3)`, r1.ID, r2.ID, r3.ID); err != nil {
		t.Fatal(err)
	}

	var sealed []byte
	if err := s.Pool.QueryRow(ctx, `SELECT so.http_body FROM service_observations so JOIN services sv ON sv.id = so.service_id
		JOIN hosts h ON h.id = sv.host_id WHERE h.address = '10.0.0.1' AND so.run_id = $1`, r1.ID).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("Grafana v9.1")) {
		t.Fatal("the stored body is plain text")
	}
	plain, err := keys.Decrypt(sealed)
	if err != nil || len(plain) != inventory.MaxStoredBody || !bytes.HasPrefix(plain, []byte(big[:100])) {
		t.Fatalf("stored body = %d bytes, %v; want the first %d bytes", len(plain), err, inventory.MaxStoredBody)
	}

	h, got := hunt(t, inv, huntSignature, time.Time{})
	want := []inventory.HuntResult{
		{Address: "10.0.0.2", Port: 80, Protocol: "tcp", Evaluable: true, FirstRun: "r3", LastRun: "r3", InLatest: true, Version: "10.0"},
		{Address: "10.0.0.1", Port: 80, Protocol: "tcp", Evaluable: true, FirstRun: "r1", LastRun: "r2", Version: "9.2"},
		{Address: "10.0.0.3", Port: 80, Protocol: "tcp"},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("hunt results:\n%+v\nwant:\n%+v", got, want)
	}
	if h.Matched != 2 || h.InLatest != 1 || h.NotEvaluable != 1 || h.Observations != 7 || h.LatestRun != "r3" {
		t.Fatalf("hunt = %+v", h)
	}

	_, got = hunt(t, inv, huntSignature, time.Now().Add(-12*time.Hour))
	if len(got) != 1 || got[0].Address != "10.0.0.2" || got[0].FirstRun != "r3" {
		t.Fatalf("hunt since 12h = %+v, want only 10.0.0.2 from r3", got)
	}

	ph, got := hunt(t, inv, strings.Replace(huntSignature, "match:", "request: {path: /api/health}\nmatch:", 1), time.Time{})
	if ph.Matched != 0 || ph.NotEvaluable != 3 || len(got) != 3 || slices.ContainsFunc(got, func(r inventory.HuntResult) bool { return r.Evaluable }) {
		t.Fatalf("hunt with a request path = %+v %+v, want 3 services not evaluable", ph, got)
	}

	n, err := inv.RecordHuntFindings(ctx, h.ID, "eddie", "10.9.9.9")
	if err != nil || n != 1 {
		t.Fatalf("RecordHuntFindings = %d, %v; want 1", n, err)
	}
	if n, err := inv.RecordHuntFindings(ctx, h.ID, "eddie", "10.9.9.9"); err != nil || n != 0 {
		t.Fatalf("RecordHuntFindings again = %d, %v; want 0", n, err)
	}
	e3 := export(t, inv, "r3")
	f := host(t, e3, "10.0.0.2").Services[0].Findings
	if len(f) != 1 || f[0].SignatureID != "grafana-hunt" || f[0].Source != inventory.SourceRetroHunt || f[0].Version != "10.0" || !strings.Contains(f[0].Evidence, "title matches") {
		t.Fatalf("findings of 10.0.0.2 in r3 = %+v", f)
	}
	if f := host(t, e3, "10.0.0.1").Services[0].Findings; len(f) != 0 {
		t.Fatalf("10.0.0.1 does not match in r3 but has findings %+v", f)
	}
	d := diff.Compute(export(t, inv, "r2"), e3, diff.Options{})
	var fields []string
	for _, c := range d.Changes {
		if c.Address == "10.0.0.2" {
			for _, fc := range c.Fields {
				fields = append(fields, fc.Field)
			}
		}
	}
	if !slices.Contains(fields, "findings") {
		t.Fatalf("diff r2→r3 fields of 10.0.0.2 = %v, want findings", fields)
	}

	createRun(t, inv, "r4")
	if _, err := inv.RecordHuntFindings(ctx, h.ID, "eddie", "10.9.9.9"); !errors.Is(err, inventory.ErrStaleHunt) {
		t.Fatalf("RecordHuntFindings after a newer run = %v, want ErrStaleHunt", err)
	}
	var audits []string
	rows, err := s.Pool.Query(ctx, `SELECT actor || ' ' || action || ' ' || target || ' ' || address FROM audit_log ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			t.Fatal(err)
		}
		audits = append(audits, a)
	}
	rows.Close()
	hunted := "eddie signature.hunt grafana-hunt 10.9.9.9"
	recorded := "eddie signature.hunt.record grafana-hunt 10.9.9.9"
	if want := []string{hunted, hunted, hunted, recorded, recorded}; !slices.Equal(audits, want) {
		t.Fatalf("audit log = %q, want %q", audits, want)
	}
}

// REQ-SIGNATURES-006
func TestRetroHuntScale(t *testing.T) {
	const hosts, runs, bodySize = 20000, 10, 512
	ctx := context.Background()
	inv, s, keys := openHuntInventory(t)
	seal := func(b []byte) []byte {
		out, err := keys.Encrypt(b)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	headers := seal([]byte(`{"server":"nginx"}`))
	cookies := seal([]byte(`[{"name":"grafana_session"}]`))
	plainBody := seal(bytes.Repeat([]byte("p"), bodySize))
	grafanaBody := seal(append([]byte("Grafana v11.2.0 "), bytes.Repeat([]byte("g"), bodySize)...))
	seed := []string{
		fmt.Sprintf(`INSERT INTO runs (name, inactive_after, status) SELECT 'p' || i, 3, 'completed' FROM generate_series(1, %d) i`, runs),
		`INSERT INTO run_groups (run_id, group_index) SELECT id, 0 FROM runs`,
		fmt.Sprintf(`INSERT INTO hosts (address) SELECT '10.' || (i >> 16) || '.' || ((i >> 8) & 255) || '.' || (i & 255) FROM generate_series(1, %d) i`, hosts),
		`INSERT INTO services (host_id, port, protocol) SELECT id, 80, 'tcp' FROM hosts`,
	}
	for _, q := range seed {
		if _, err := s.Pool.Exec(ctx, q); err != nil {
			t.Fatalf("seed %q: %v", q, err)
		}
	}
	if _, err := s.Pool.Exec(ctx, `INSERT INTO service_observations (run_id, group_index, service_id, state, service, http, http_headers, http_cookies, http_body)
		SELECT r.id, 0, sv.id, 'open', 'http',
			jsonb_build_object('scheme', 'http', 'url', 'http://x/', 'status_code', 200,
				'title', CASE WHEN sv.id % 10 = 0 OR (sv.id % 10 = 1 AND r.id <= 5) THEN 'Grafana' ELSE 'nginx' END),
			$1, $2, CASE WHEN sv.id % 10 IN (0, 1) THEN $3::bytea ELSE $4::bytea END
		FROM runs r CROSS JOIN services sv`, headers, cookies, grafanaBody, plainBody); err != nil {
		t.Fatalf("seed observations: %v", err)
	}
	sig, err := detect.ParseOne([]byte(huntSignature))
	if err != nil {
		t.Fatal(err)
	}

	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)
	var (
		peak uint64
		wg   sync.WaitGroup
	)
	done := make(chan struct{})
	wg.Go(func() {
		var m runtime.MemStats
		for {
			select {
			case <-done:
				return
			case <-time.After(20 * time.Millisecond):
			}
			runtime.ReadMemStats(&m)
			peak = max(peak, m.HeapAlloc)
		}
	})
	start := time.Now()
	h, err := inv.RunHunt(ctx, inventory.HuntSpec{Signature: sig, Source: huntSignature, Actor: "eddie"})
	elapsed := time.Since(start)
	close(done)
	wg.Wait()
	if err != nil {
		t.Fatalf("RunHunt: %v", err)
	}
	t.Logf("hunt over %d observations: %s, peak heap %d MiB above %d MiB", h.Observations, elapsed, (peak-min(peak, base.HeapAlloc))>>20, base.HeapAlloc>>20)
	if h.Observations != hosts*runs || h.Matched != hosts/5 {
		t.Fatalf("hunt = %+v, want %d observations and %d matches", h, hosts*runs, hosts/5)
	}
	if elapsed >= 10*time.Second {
		t.Fatalf("hunt took %s, want under 10 s", elapsed)
	}
	if grown := peak - min(peak, base.HeapAlloc); grown > 64<<20 {
		t.Fatalf("heap grew by %d MiB during the hunt over %d MiB of stored bodies, want streaming under 64 MiB", grown>>20, hosts*runs*bodySize>>20)
	}
	latest := 0
	if err := inv.HuntResults(ctx, h.ID, 0, 0, func(r inventory.HuntResult) error {
		if r.InLatest {
			latest++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if latest != hosts/10 || h.InLatest != latest {
		t.Fatalf("%d results match in the latest run, want %d", latest, hosts/10)
	}
}

// REQ-SIGNATURES-007
func TestBodyRetentionPerService(t *testing.T) {
	ctx := context.Background()
	inv, s, _ := openHuntInventory(t)
	inv.BodyRetention = 2
	bodies := func() map[string][]string {
		rows, err := s.Pool.Query(ctx, `SELECT h.address, r.name FROM service_observations so
			JOIN services sv ON sv.id = so.service_id JOIN hosts h ON h.id = sv.host_id JOIN runs r ON r.id = so.run_id
			WHERE so.http_body IS NOT NULL ORDER BY h.address, so.run_id`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[string][]string{}
		for rows.Next() {
			var addr, run string
			if err := rows.Scan(&addr, &run); err != nil {
				t.Fatal(err)
			}
			out[addr] = append(out[addr], run)
		}
		return out
	}
	for i := 1; i <= 4; i++ {
		run := createRun(t, inv, fmt.Sprintf("r%d", i))
		hosts := []inventory.HostResult{{Address: "10.0.1.1", Services: []inventory.ServiceResult{grafanaService("Grafana", fmt.Sprintf("Grafana v9.%d", i))}}}
		if i == 1 {
			hosts = append(hosts, inventory.HostResult{Address: "10.0.1.2", Services: []inventory.ServiceResult{grafanaService("Grafana", "Grafana v8.0")}})
		}
		g := inventory.GroupResult{Index: 0, Hosts: hosts}
		for _, h := range hosts {
			g.Addresses = append(g.Addresses, h.Address)
		}
		record(t, inv, run, g)
		if got := bodies()["10.0.1.1"]; len(got) != min(i, 3) {
			t.Fatalf("before run r%d finishes: bodies of 10.0.1.1 in %v", i, got)
		}
		if err := inv.SetRunStatus(ctx, run.ID, inventory.RunCompleted); err != nil {
			t.Fatalf("SetRunStatus r%d: %v", i, err)
		}
		got := bodies()
		var want []string
		for j := max(1, i-1); j <= i; j++ {
			want = append(want, fmt.Sprintf("r%d", j))
		}
		if !slices.Equal(got["10.0.1.1"], want) || !slices.Equal(got["10.0.1.2"], []string{"r1"}) {
			t.Fatalf("after run r%d: bodies = %v, want 10.0.1.1 in %v and 10.0.1.2 in [r1]", i, got, want)
		}
	}

	h, got := hunt(t, inv, huntSignature, time.Time{})
	want := []inventory.HuntResult{
		{Address: "10.0.1.1", Port: 80, Protocol: "tcp", Evaluable: true, FirstRun: "r3", LastRun: "r4", InLatest: true, Version: "9.4"},
		{Address: "10.0.1.2", Port: 80, Protocol: "tcp", Evaluable: true, FirstRun: "r1", LastRun: "r1", Version: "8.0"},
	}
	if !slices.Equal(got, want) || h.Matched != 2 || h.NotEvaluable != 0 {
		t.Fatalf("hunt over kept bodies = %+v %+v, want %+v", h, got, want)
	}
}

func TestRetroHuntLatestIsRelativeToTheLatestRunThatCoversTheService(t *testing.T) {
	ctx := context.Background()
	inv, _, _ := openHuntInventory(t)
	runIn := func(name, target string, g inventory.GroupResult) {
		r, err := inv.CreateRun(ctx, inventory.RunSpec{Name: name, Settings: inventory.RunSettings{Targets: []string{target}}})
		if err != nil {
			t.Fatalf("CreateRun %s: %v", name, err)
		}
		record(t, inv, r, g)
		if err := inv.SetRunStatus(ctx, r.ID, inventory.RunCompleted); err != nil {
			t.Fatal(err)
		}
	}
	runIn("lan-1", "10.0.2.0/29", inventory.GroupResult{Index: 0, Addresses: []string{"10.0.2.1"},
		Hosts: []inventory.HostResult{{Address: "10.0.2.1", Services: []inventory.ServiceResult{grafanaService("Grafana", "Grafana v9.1")}}}})
	runIn("dmz-1", "10.0.3.0/29", inventory.GroupResult{Index: 0, Addresses: []string{"10.0.3.1"}})
	broken, err := inv.CreateRun(ctx, inventory.RunSpec{Name: "lan-broken", Settings: inventory.RunSettings{Targets: []string{"10.0.2.0/29"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := inv.SetRunStatus(ctx, broken.ID, inventory.RunFailed); err != nil {
		t.Fatal(err)
	}

	h, got := hunt(t, inv, huntSignature, time.Time{})
	if h.LatestRun != "lan-broken" || h.InLatest != 1 || len(got) != 1 || !got[0].InLatest || got[0].LastRun != "lan-1" {
		t.Fatalf("hunt = %+v %+v, want the match in lan-1 reported as latest: dmz-1 does not cover 10.0.2.1 and lan-broken never scanned", h, got)
	}
	n, err := inv.RecordHuntFindings(ctx, h.ID, "eddie", "10.9.9.9")
	if err != nil || n != 1 {
		t.Fatalf("RecordHuntFindings = %d, %v, want 1 finding on the lan-1 observation", n, err)
	}

	runIn("lan-2", "10.0.2.0/29", inventory.GroupResult{Index: 0, Addresses: []string{"10.0.2.1"},
		Hosts: []inventory.HostResult{{Address: "10.0.2.1", Services: []inventory.ServiceResult{grafanaService("Login", "nothing")}}}})
	if h, got := hunt(t, inv, huntSignature, time.Time{}); h.InLatest != 0 || len(got) != 1 || got[0].InLatest {
		t.Fatalf("hunt after lan-2 = %+v %+v, want no match in the latest covering run", h, got)
	}
}
