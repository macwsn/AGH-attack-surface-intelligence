//go:build integration

package inventory_test

import (
	"context"
	"crypto/rand"
	"errors"
	"math"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"asi/internal/diff"
	"asi/internal/inventory"
	"asi/internal/store"
	"asi/internal/store/storetest"
)

func openRhythm(t *testing.T) (*inventory.Inventory, *store.Store) {
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
		t.Fatal(err)
	}
	k, err := store.NewKeyring(master)
	if err != nil {
		t.Fatal(err)
	}
	return inventory.New(s, k), s
}

func tcp(ports ...int) []inventory.ServiceResult {
	out := make([]inventory.ServiceResult, len(ports))
	for i, p := range ports {
		out[i] = inventory.ServiceResult{Port: p, Protocol: "tcp", State: "open", Service: "svc"}
	}
	return out
}

func runWith(t *testing.T, inv *inventory.Inventory, name string, n int, st inventory.RunSettings) inventory.Run {
	t.Helper()
	r, err := inv.CreateRun(context.Background(), inventory.RunSpec{Name: name, InactiveAfter: n, Settings: st})
	if err != nil {
		t.Fatalf("CreateRun %s: %v", name, err)
	}
	return r
}

func complete(t *testing.T, inv *inventory.Inventory, r inventory.Run) {
	t.Helper()
	if err := inv.SetRunStatus(context.Background(), r.ID, inventory.RunCompleted); err != nil {
		t.Fatal(err)
	}
}

func stampGroups(t *testing.T, s *store.Store, r inventory.Run, at time.Time) {
	t.Helper()
	if _, err := s.Pool.Exec(context.Background(), `UPDATE run_groups SET completed_at = $2 WHERE run_id = $1`, r.ID, at); err != nil {
		t.Fatal(err)
	}
}

func knownKeys(ks []inventory.KnownService) []string {
	out := []string{}
	for _, k := range ks {
		out = append(out, k.Address+":"+strconv.Itoa(k.Port))
	}
	return out
}

func TestRecheckBaseAndKnownServices(t *testing.T) {
	ctx := context.Background()
	inv, s := openRhythm(t)
	st := inventory.RunSettings{Targets: []string{"10.0.0.0/24"}, Excludes: []string{"10.0.0.1", "10.0.0.250"}, Ports: []int{21, 22, 80, 443}}
	newRun := inventory.Run{Settings: inventory.RunSettings{Targets: st.Targets, Excludes: []string{"10.0.0.250", "10.0.0.1"},
		Ports: st.Ports, Mode: inventory.ModeRecheck}}

	if _, _, err := inv.RecheckPlan(ctx, newRun, nil); !errors.Is(err, inventory.ErrNoRecheckBase) ||
		!strings.Contains(err.Error(), "no earlier run to recheck") {
		t.Fatalf("recheck without runs: %v", err)
	}

	r1 := runWith(t, inv, "r1", 1, st)
	record(t, inv, r1, inventory.GroupResult{Index: 0, Hosts: []inventory.HostResult{
		{Address: "10.0.0.5", Services: tcp(21, 80, 443)},
	}})
	if _, err := inv.RecheckBase(ctx, newRun); !errors.Is(err, inventory.ErrNoRecheckBase) {
		t.Fatalf("running run used as base: %v", err)
	}
	complete(t, inv, r1)

	r2 := runWith(t, inv, "r2", 1, st)
	record(t, inv, r2, inventory.GroupResult{Index: 0, Hosts: []inventory.HostResult{
		{Address: "10.0.0.5", Services: tcp(80, 443)},
		{Address: "10.0.0.9", Services: tcp(22)},
		{Address: "10.0.0.7", Services: tcp(8080)},
	}})
	complete(t, inv, r2)
	other := runWith(t, inv, "other", 1, inventory.RunSettings{Targets: []string{"192.0.2.0/24"}, Ports: st.Ports})
	record(t, inv, other, inventory.GroupResult{Index: 0, Hosts: []inventory.HostResult{{Address: "192.0.2.1", Services: tcp(22)}}})
	complete(t, inv, other)

	base, known, err := inv.RecheckPlan(ctx, newRun, nil)
	if err != nil {
		t.Fatalf("RecheckPlan: %v", err)
	}
	if base.Name != "r2" {
		t.Errorf("base = %s, want r2 (latest completed run with equal targets and excludes)", base.Name)
	}
	if got, want := knownKeys(known), []string{"10.0.0.5:80", "10.0.0.5:443", "10.0.0.9:22"}; !reflect.DeepEqual(got, want) {
		t.Errorf("known = %v, want %v (inactive 10.0.0.5:21 and 10.0.0.7:8080 outside the ports left out)", got, want)
	}

	_, known, err = inv.RecheckPlan(ctx, newRun, func(a string) bool { return a != "10.0.0.9" })
	if err != nil || !reflect.DeepEqual(knownKeys(known), []string{"10.0.0.5:80", "10.0.0.5:443"}) {
		t.Errorf("known in scope = %v, %v", knownKeys(known), err)
	}
	ordered := newRun
	ordered.Settings.Hosts = []string{"10.0.0.9", "10.0.0.5"}
	if _, known, err = inv.RecheckPlan(ctx, ordered, nil); err != nil ||
		!reflect.DeepEqual(knownKeys(known), []string{"10.0.0.9:22", "10.0.0.5:80", "10.0.0.5:443"}) {
		t.Errorf("known in host order = %v, %v", knownKeys(known), err)
	}
	none := newRun
	none.Settings.Ports = []int{6379}
	if _, _, err := inv.RecheckPlan(ctx, none, nil); !errors.Is(err, inventory.ErrNoRecheckBase) {
		t.Errorf("recheck with no known service in the ports: %v", err)
	}

	var defID int64
	if err := s.Pool.QueryRow(ctx, `INSERT INTO scan_definitions (name, inactive_after, settings, schedule)
		VALUES ('d', 3, '{}', '{}') RETURNING id`).Scan(&defID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `UPDATE runs SET definition_id = $1 WHERE name = 'r1'`, defID); err != nil {
		t.Fatal(err)
	}
	scheduled := runWith(t, inv, "d-2", 3, newRun.Settings)
	if _, err := s.Pool.Exec(ctx, `UPDATE runs SET definition_id = $1 WHERE id = $2`, defID, scheduled.ID); err != nil {
		t.Fatal(err)
	}
	if base, err := inv.RecheckBase(ctx, scheduled); err != nil || base.Name != "r1" {
		t.Errorf("definition base = %s, %v, want r1 (latest completed run of the definition)", base.Name, err)
	}
	lone := runWith(t, inv, "lone", 3, newRun.Settings)
	if _, err := s.Pool.Exec(ctx, `INSERT INTO scan_definitions (name, inactive_after, settings, schedule)
		VALUES ('e', 3, '{}', '{}')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `UPDATE runs SET definition_id = (SELECT id FROM scan_definitions WHERE name = 'e') WHERE id = $1`, lone.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := inv.RecheckBase(ctx, lone); !errors.Is(err, inventory.ErrNoRecheckBase) {
		t.Errorf("definition without completed run: %v", err)
	}
}

func TestRecheckCoversOnlyContactedServices(t *testing.T) {
	ctx := context.Background()
	inv, _ := openRhythm(t)
	const a, b = "10.0.0.1", "10.0.0.2"
	r1 := runWith(t, inv, "r1", 3, inventory.RunSettings{})
	record(t, inv, r1, inventory.GroupResult{Index: 0, Addresses: []string{a, b, "10.0.0.3"}, Hosts: []inventory.HostResult{
		{Address: a, Services: tcp(22, 80)},
		{Address: b, Services: tcp(22)},
	}})
	complete(t, inv, r1)
	r2 := runWith(t, inv, "r2", 3, inventory.RunSettings{Mode: inventory.ModeRecheck})
	record(t, inv, r2, inventory.GroupResult{Index: 0, Addresses: []string{a}, CoveredPorts: map[string][]int{a: {80}},
		Hosts: []inventory.HostResult{{Address: a, Services: tcp(80)}}})
	complete(t, inv, r2)

	e1, e2 := export(t, inv, "r1"), export(t, inv, "r2")
	if len(e2.Hosts) != 2 {
		t.Fatalf("hosts as of r2 = %d, want 2 (never-seen 10.0.0.3 not listed)", len(e2.Hosts))
	}
	b1, b2 := host(t, e1, b), host(t, e2, b)
	if b1.Status != b2.Status || b1.MissedRuns != b2.MissedRuns || b1.Stability != b2.Stability ||
		b2.Services[0].Status != b1.Services[0].Status || b2.Services[0].MissedRuns != 0 {
		t.Errorf("uncontacted host B changed: r1 %+v, r2 %+v", b1, b2)
	}
	a2 := host(t, e2, a)
	if a2.Status != inventory.StatusActive || a2.Services[0].Port != 22 || a2.Services[0].Status != inventory.StatusActive ||
		a2.Services[0].MissedRuns != 0 || a2.Services[0].Stability != 1 {
		t.Errorf("uncontacted service A:22 counted: %+v", a2.Services)
	}
	if d := diff.Compute(e1, e2, diff.Options{}); len(d.Changes) != 0 {
		t.Errorf("diff r1 -> r2 = %+v, want no change", d.Changes)
	}

	r3 := runWith(t, inv, "r3", 3, inventory.RunSettings{Mode: inventory.ModeRecheck})
	record(t, inv, r3, inventory.GroupResult{Index: 0, Addresses: []string{b}, CoveredPorts: map[string][]int{b: {22}}})
	complete(t, inv, r3)
	e3 := export(t, inv, "r3")
	if b3 := host(t, e3, b); b3.Status != inventory.StatusUnstable || b3.MissedRuns != 1 {
		t.Errorf("contacted host B down: %+v, want unstable with missed_runs 1", b3)
	}
	if a3 := host(t, e3, a); a3.Status != inventory.StatusActive || a3.MissedRuns != 0 {
		t.Errorf("host A as of r3: %+v", a3)
	}
	d := diff.Compute(e2, e3, diff.Options{})
	missing := false
	for _, c := range d.Changes {
		if c.Address == a {
			t.Errorf("change for uncontacted host A: %+v", c)
		}
		missing = missing || (c.Type == diff.HostMissing && c.Address == b)
	}
	if !missing {
		t.Errorf("diff r2 -> r3 = %+v, want host_missing for B", d.Changes)
	}

	r4, err := inv.CreateRun(ctx, inventory.RunSpec{Name: "r4", Settings: inventory.RunSettings{Mode: "fast"}})
	if err == nil {
		t.Errorf("CreateRun with mode fast = %+v, want error", r4)
	}
}

func TestRunPackets(t *testing.T) {
	ctx := context.Background()
	inv, _ := openRhythm(t)
	r := runWith(t, inv, "p", 3, inventory.RunSettings{})
	if r.Packets != 0 {
		t.Errorf("new run packets = %d", r.Packets)
	}
	if err := inv.AddRunPackets(ctx, r.ID, 40); err != nil {
		t.Fatal(err)
	}
	if err := inv.AddRunPackets(ctx, r.ID, 2); err != nil {
		t.Fatal(err)
	}
	if got, err := inv.RunByName(ctx, "p"); err != nil || got.Packets != 42 {
		t.Errorf("packets = %d, %v, want 42", got.Packets, err)
	}
	if err := inv.SetRunPackets(ctx, r.ID, 7); err != nil {
		t.Fatal(err)
	}
	if got, _ := inv.RunByName(ctx, "p"); got.Packets != 7 {
		t.Errorf("packets after set = %d", got.Packets)
	}
	if err := inv.AddRunPackets(ctx, r.ID, -1); err == nil {
		t.Error("negative packets accepted")
	}
	if err := inv.SetRunPackets(ctx, r.ID+100, 1); !errors.Is(err, inventory.ErrUnknownRun) {
		t.Errorf("unknown run: %v", err)
	}
}

type step struct {
	hour int
	seen bool
}

func playHistory(t *testing.T, inv *inventory.Inventory, s *store.Store, prefix string, day time.Time, steps []step, addr string) []string {
	t.Helper()
	var names []string
	for i, st := range steps {
		name := prefix + strconv.Itoa(i+1)
		r := runWith(t, inv, name, 3, inventory.RunSettings{})
		g := inventory.GroupResult{Index: 0, Addresses: []string{addr}}
		if st.seen {
			g.Hosts = []inventory.HostResult{{Address: addr, Services: tcp(80)}}
		}
		record(t, inv, r, g)
		stampGroups(t, s, r, day.AddDate(0, 0, i).Add(time.Duration(st.hour)*time.Hour+15*time.Minute))
		complete(t, inv, r)
		names = append(names, name)
	}
	return names
}

func TestExportAvailability(t *testing.T) {
	ctx := context.Background()
	inv, s := openRhythm(t)
	day := time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC)
	steps := []step{{10, true}, {10, true}, {10, true}, {2, false}, {2, false}, {2, false}}
	names := playHistory(t, inv, s, "a", day, steps, "10.0.0.8")

	h := host(t, export(t, inv, names[5]), "10.0.0.8")
	want := inventory.BuildAvailability([]inventory.HourObservation{{10, true}, {10, true}, {10, true}, {2, false}, {2, false}, {2, false}})
	av := h.Availability
	if av == nil || len(av.Hours) != 24 || av.Samples != 6 || !av.Periodic || !reflect.DeepEqual(av.UsualHours, []int{10}) {
		t.Fatalf("availability = %+v", av)
	}
	for i := range av.Hours {
		if math.Abs(av.Hours[i]-want.Hours[i]) > 1e-9 {
			t.Errorf("hour %d = %v, want %v", i, av.Hours[i], want.Hours[i])
		}
	}
	if av.Expected != "" {
		t.Errorf("expected = %q although the host was not periodic before the run", av.Expected)
	}
	if want := day.AddDate(0, 0, 5).Add(2*time.Hour + 15*time.Minute); !h.LastCovered.Equal(want) {
		t.Errorf("last covered = %v, want %v", h.LastCovered, want)
	}
	if h1 := host(t, export(t, inv, names[0]), "10.0.0.8"); h1.Availability == nil || h1.Availability.Samples != 1 ||
		h1.Availability.Hours[10] != 0.65 || h1.Availability.Periodic {
		t.Errorf("availability as of the first run = %+v", h1.Availability)
	}

	tz := runWith(t, inv, "tz", 3, inventory.RunSettings{})
	record(t, inv, tz, inventory.GroupResult{Index: 0, Hosts: []inventory.HostResult{{Address: "10.0.0.8"}}})
	if _, err := s.Pool.Exec(ctx, `UPDATE runs SET schedule = '{"timezone": "Asia/Tokyo"}' WHERE id = $1`, tz.ID); err != nil {
		t.Fatal(err)
	}
	stampGroups(t, s, tz, time.Date(2026, 3, 9, 1, 0, 0, 0, time.UTC))
	if av := host(t, export(t, inv, "tz"), "10.0.0.8").Availability; av.Samples != 7 || av.Hours[10] <= want.Hours[10] || av.Hours[1] != 0.5 {
		t.Errorf("coverage at 01:00 UTC in Asia/Tokyo should update hour 10: %+v", av)
	}

	other := runWith(t, inv, "elsewhere", 3, inventory.RunSettings{})
	record(t, inv, other, inventory.GroupResult{Index: 0, Hosts: []inventory.HostResult{{Address: "10.0.0.99"}}})
	if av := host(t, export(t, inv, "elsewhere"), "10.0.0.8").Availability; av.Samples != 7 {
		t.Errorf("run not covering the host changed its profile: %+v", av)
	}
}

func TestDownHourMissesIgnored(t *testing.T) {
	inv, s := openRhythm(t)
	day := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	steps := []step{{10, true}, {2, false}, {10, true}, {2, false}, {10, true}, {2, false}, {10, true}}
	for i := 0; i < 5; i++ {
		steps = append(steps, step{2, false})
	}
	names := playHistory(t, inv, s, "d", day, steps, "10.0.0.4")

	prev := export(t, inv, names[6])
	ref := host(t, prev, "10.0.0.4")
	if ref.Status != inventory.StatusActive || ref.Availability == nil || !ref.Availability.Periodic {
		t.Fatalf("host before the down-hour misses = %+v %+v", ref, ref.Availability)
	}
	for k := 7; k < len(names); k++ {
		cur := export(t, inv, names[k])
		h := host(t, cur, "10.0.0.4")
		if h.Status != inventory.StatusActive || h.MissedRuns != 0 || h.Stability != ref.Stability {
			t.Errorf("%s: host = %s missed %d stability %v, want as before (%s, 0, %v)", names[k], h.Status, h.MissedRuns,
				h.Stability, ref.Status, ref.Stability)
		}
		if sv := h.Services[0]; sv.Status != inventory.StatusActive || sv.MissedRuns != 0 || sv.Stability != ref.Services[0].Stability {
			t.Errorf("%s: service = %+v", names[k], sv)
		}
		if h.Availability.Samples != k+1 || h.Availability.Expected != inventory.ExpectedDown {
			t.Errorf("%s: availability = %+v, want %d samples and expected down", names[k], h.Availability, k+1)
		}
		for _, c := range diff.Compute(prev, cur, diff.Options{}).Changes {
			t.Errorf("%s: unexpected change %+v", names[k], c)
		}
		prev = cur
	}
}

func TestUpHourMissReported(t *testing.T) {
	inv, s := openRhythm(t)
	day := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	steps := []step{{10, true}, {2, false}, {10, true}, {2, false}, {10, true}, {2, false}, {10, true}, {10, false}}
	names := playHistory(t, inv, s, "u", day, steps, "10.0.0.6")
	before, after := export(t, inv, names[6]), export(t, inv, names[7])
	h := host(t, after, "10.0.0.6")
	if h.Status != inventory.StatusUnstable || h.MissedRuns != 1 || h.Availability == nil || h.Availability.Expected != inventory.ExpectedUp {
		t.Errorf("miss at a usual hour: %+v %+v", h, h.Availability)
	}
	found := false
	for _, c := range diff.Compute(before, after, diff.Options{}).Changes {
		found = found || (c.Type == diff.HostMissing && c.Address == "10.0.0.6")
	}
	if !found {
		t.Error("no host_missing for a miss at a usual hour")
	}

	plain := playHistory(t, inv, s, "n", day, []step{{10, true}, {10, false}}, "10.0.0.66")
	if h := host(t, export(t, inv, plain[1]), "10.0.0.66"); h.Availability == nil || h.Availability.Expected != "" ||
		h.Availability.Periodic || h.Status != inventory.StatusUnstable {
		t.Errorf("non-periodic host: %+v %+v", h, h.Availability)
	}
}

func TestImportAndManualRunsAreNotAvailabilitySamples(t *testing.T) {
	inv, s := openRhythm(t)
	day := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	steps := []step{{10, true}, {2, false}, {10, true}, {2, false}, {10, true}}
	names := playHistory(t, inv, s, "im", day, steps, "10.0.0.7")
	before := host(t, export(t, inv, names[len(names)-1]), "10.0.0.7").Availability
	if before == nil || before.Samples != len(steps) {
		t.Fatalf("availability after the scans = %+v", before)
	}

	for i, src := range []inventory.RunSource{inventory.SourceImport, inventory.SourceManual} {
		name := "im-" + string(src)
		r, err := inv.CreateRun(context.Background(), inventory.RunSpec{Name: name, InactiveAfter: 3, Source: src})
		if err != nil {
			t.Fatalf("CreateRun %s: %v", name, err)
		}
		record(t, inv, r, inventory.GroupResult{Index: 0, Addresses: []string{"10.0.0.7"},
			Hosts: []inventory.HostResult{{Address: "10.0.0.7", Services: tcp(80)}}})
		stampGroups(t, s, r, day.AddDate(0, 0, len(steps)+i).Add(15*time.Hour))
		complete(t, inv, r)

		av := host(t, export(t, inv, name), "10.0.0.7").Availability
		if av == nil || av.Samples != before.Samples || av.Periodic != before.Periodic || !reflect.DeepEqual(av.Hours, before.Hours) {
			t.Errorf("%s run changed the availability profile: %+v, want unchanged %+v", src, av, before)
		}
	}

	next := playHistory(t, inv, s, "im-next", day.AddDate(0, 0, len(steps)+2), []step{{2, false}}, "10.0.0.7")
	av := host(t, export(t, inv, next[0]), "10.0.0.7").Availability
	if want := len(steps) + 1; av == nil || av.Samples != want || !av.Periodic {
		t.Errorf("availability after the next scan = %+v, want %d samples (imports not counted) and periodic", av, want)
	}
}
