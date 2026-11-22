package inventory

import (
	"encoding/json"
	"math"
	"reflect"
	"testing"
)

func history(seen10, missed2 int) []HourObservation {
	var obs []HourObservation
	for i := 0; i < seen10; i++ {
		obs = append(obs, HourObservation{Hour: 10, Seen: true})
	}
	for i := 0; i < missed2; i++ {
		obs = append(obs, HourObservation{Hour: 2, Seen: false})
	}
	return obs
}

func TestBuildAvailability(t *testing.T) {
	a := BuildAvailability(history(3, 3))
	if a.Samples != 6 {
		t.Errorf("samples = %d, want 6", a.Samples)
	}
	for h, v := range a.Hours {
		want := 0.5
		switch h {
		case 10:
			want = 0.8285
		case 2:
			want = 0.1715
		}
		if math.Abs(v-want) > 0.001 {
			t.Errorf("hour %d = %.4f, want %.4f", h, v, want)
		}
	}

	empty := BuildAvailability(nil)
	if empty.Samples != 0 {
		t.Errorf("empty samples = %d", empty.Samples)
	}
	for h, v := range empty.Hours {
		if v != 0.5 {
			t.Errorf("empty hour %d = %v, want 0.5", h, v)
		}
	}
	if empty.Export() != nil {
		t.Errorf("export of a profile without samples = %+v, want nil", empty.Export())
	}

	if got := BuildAvailability([]HourObservation{{Hour: 24, Seen: true}, {Hour: -1}}); got.Samples != 0 {
		t.Errorf("out-of-range hours counted: %+v", got)
	}
}

func TestPeriodicAndUsualHours(t *testing.T) {
	cases := []struct {
		name     string
		obs      []HourObservation
		periodic bool
		usual    []int
	}{
		{"3 seen at 10, 3 missed at 2", history(3, 3), true, []int{10}},
		{"only 5 samples", history(3, 2), false, []int{}},
		{"no low bucket", history(6, 0), false, []int{}},
		{"two usual hours", append(history(3, 3), HourObservation{23, true}, HourObservation{23, true}, HourObservation{23, true}), true, []int{10, 23}},
	}
	for _, c := range cases {
		a := BuildAvailability(c.obs)
		if a.Periodic() != c.periodic {
			t.Errorf("%s: periodic = %v, want %v (%+v)", c.name, a.Periodic(), c.periodic, a)
		}
		if got := a.UsualHours(); !reflect.DeepEqual(got, c.usual) {
			t.Errorf("%s: usual hours = %v, want %v", c.name, got, c.usual)
		}
	}
}

func TestAvailabilityExpected(t *testing.T) {
	a := BuildAvailability(history(3, 3))
	if a.Expected(10) != ExpectedUp || a.Expected(2) != ExpectedDown || a.Expected(5) != "" {
		t.Errorf("expected at 10/2/5 = %q/%q/%q", a.Expected(10), a.Expected(2), a.Expected(5))
	}
	if b := BuildAvailability(history(3, 2)); b.Expected(2) != "" {
		t.Errorf("non-periodic profile expected %q at hour 2", b.Expected(2))
	}
}

func TestAvailabilityExportJSON(t *testing.T) {
	e := BuildAvailability(history(3, 3)).Export()
	e.Expected = ExpectedDown
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	requireKeys(t, "availability", doc, "hours", "samples", "periodic", "usual_hours", "expected")
	if hours := doc["hours"].([]any); len(hours) != 24 {
		t.Errorf("hours length %d", len(hours))
	}
	if doc["samples"] != 6.0 || doc["periodic"] != true || !reflect.DeepEqual(doc["usual_hours"], []any{10.0}) {
		t.Errorf("availability = %s", b)
	}
	if got := e.Profile(); got != BuildAvailability(history(3, 3)) {
		t.Errorf("profile round trip = %+v", got)
	}

	e.Expected = ""
	if b, err = json.Marshal(e); err != nil {
		t.Fatal(err)
	}
	var fresh map[string]any
	if err := json.Unmarshal(b, &fresh); err != nil {
		t.Fatal(err)
	}
	if _, ok := fresh["expected"]; ok {
		t.Errorf("expected key present when empty: %s", b)
	}
}

func cov(run int64, hour int, seen bool) coverage { return coverage{run: run, hour: hour, seen: seen} }

func TestApplyRhythmIgnoresDownHourMisses(t *testing.T) {
	var c []coverage
	run := int64(0)
	for i := 0; i < 3; i++ {
		run++
		c = append(c, cov(run, 10, true))
	}
	for i := 0; i < 3; i++ {
		run++
		c = append(c, cov(run, 2, false))
	}
	before := applyRhythm(c, run)
	if len(before.ignored) != 0 {
		t.Fatalf("misses while not yet periodic ignored: %v", before.ignored)
	}
	for i := 0; i < 5; i++ {
		run++
		c = append(c, cov(run, 2, false))
	}
	r := applyRhythm(c, run)
	if len(r.ignored) != 5 || !r.ignored[run] {
		t.Errorf("ignored = %v, want the last 5 runs", r.ignored)
	}
	if r.profile.Samples != 11 {
		t.Errorf("samples = %d, want 11 (ignored misses still update the profile)", r.profile.Samples)
	}
	if r.expected != ExpectedDown {
		t.Errorf("expected = %q, want down", r.expected)
	}
	if len(r.seen) != 6 {
		t.Errorf("seen = %v, want the 6 counted coverages", r.seen)
	}

	up := append(append([]coverage{}, c[:6]...), cov(99, 10, true), cov(100, 10, false))
	ru := applyRhythm(up, 100)
	if len(ru.ignored) != 0 || ru.expected != ExpectedUp || len(ru.seen) != 8 {
		t.Errorf("miss at usual hour: ignored %v expected %q seen %v", ru.ignored, ru.expected, ru.seen)
	}
	st, missed, _ := DeriveStatus(ru.seen, 3)
	if st != StatusUnstable || missed != 1 {
		t.Errorf("miss at usual hour: status %s missed %d", st, missed)
	}

	notAsOf := applyRhythm(up, 101)
	if notAsOf.expected != "" {
		t.Errorf("expected set although the as-of run does not cover the host: %q", notAsOf.expected)
	}
}

func TestApplyRhythmSkipsExternalRuns(t *testing.T) {
	var c []coverage
	for run := int64(1); run <= 12; run += 2 {
		c = append(c, cov(run, 10, true), cov(run+1, 2, false))
	}
	scans := applyRhythm(c, 12)
	c = append(c, coverage{run: 13, hour: 15, seen: true, external: true}, coverage{run: 14, hour: 15, seen: false, external: true})
	r := applyRhythm(c, 14)
	if r.profile != scans.profile {
		t.Errorf("profile = %+v, want unchanged %+v", r.profile, scans.profile)
	}
	if !r.profile.Periodic() || r.profile.Samples != 12 {
		t.Errorf("samples = %d periodic = %v, want 12 and periodic", r.profile.Samples, r.profile.Periodic())
	}
	if len(r.seen) != len(scans.seen)+2 {
		t.Errorf("seen = %v, want external runs still counted for status", r.seen)
	}
}

func TestRunMode(t *testing.T) {
	if (RunSettings{}).RunMode() != ModeFull || (RunSettings{Mode: "full"}).Recheck() || !(RunSettings{Mode: "recheck"}).Recheck() {
		t.Error("run mode defaults")
	}
	if ValidMode("fast") || !ValidMode("") || !ValidMode(ModeRecheck) {
		t.Error("ValidMode")
	}
}
