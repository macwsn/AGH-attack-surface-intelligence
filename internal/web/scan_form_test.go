package web

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"asi/internal/inventory"
	"asi/internal/scan"
	"asi/internal/schedule"
)

func TestPortPresets(t *testing.T) {
	cases := map[string]struct {
		custom string
		spec   string
		count  int
	}{
		"web":     {spec: "80,443,8000,8080,8443", count: 5},
		"top100":  {spec: "top100", count: 100},
		"top1000": {spec: "top1000", count: 1000},
		"all":     {spec: "all", count: 65535},
		"custom":  {custom: "22,8000-8002", spec: "22,8000,8001,8002", count: 4},
		"":        {custom: "80,443", spec: "80,443", count: 2},
	}
	for preset, c := range cases {
		got, err := portsOf(preset, c.custom)
		if err != nil {
			t.Fatalf("%q: %v", preset, err)
		}
		want, _ := scan.ParsePorts(c.spec)
		if !slices.Equal(got, want) || len(got) != c.count {
			t.Errorf("%q: got %d ports, want %d equal to ParsePorts(%q)", preset, len(got), c.count, c.spec)
		}
		again, err := scan.ParsePorts(scan.FormatPorts(got))
		if err != nil || !slices.Equal(again, got) {
			t.Errorf("%q: FormatPorts %q does not parse back: %v", preset, scan.FormatPorts(got), err)
		}
		if preset == "" || preset == presetCustom {
			continue
		}
		if p, custom := presetOf(got); p != preset || custom != "" {
			t.Errorf("presetOf(%q ports) = %q, %q", preset, p, custom)
		}
	}
	if _, err := portsOf(presetCustom, "80,9000-8000"); err == nil || !strings.Contains(err.Error(), `invalid port range "9000-8000"`) {
		t.Errorf("reversed range: %v", err)
	}
	if _, err := portsOf("bogus", ""); err == nil {
		t.Error("unknown preset accepted")
	}
	stored, _ := scan.ParsePorts("22,80,8000-8100")
	if p, custom := presetOf(stored); p != presetCustom || custom != "22,80,8000-8100" {
		t.Errorf("presetOf(custom) = %q, %q", p, custom)
	}
	var values []string
	for _, p := range portPresets {
		values = append(values, p.Value)
	}
	if !slices.Equal(values, []string{"web", "top100", "top1000", "all", "custom"}) {
		t.Errorf("preset values %v", values)
	}
}

func TestPaceChoices(t *testing.T) {
	for pace, want := range map[string]int{"careful": 20, "normal": 100, "fast": 500, "": 100} {
		got, err := rateOf(pace, "")
		if err != nil || got != want {
			t.Errorf("rateOf(%q, \"\") = %d, %v; want %d", pace, got, err, want)
		}
	}
	if got, err := rateOf(paceFast, " 37 "); err != nil || got != 37 {
		t.Errorf("exact rate does not override pace: %d, %v", got, err)
	}
	if got, err := rateOf(paceFast, "1"); err != nil || got != 1 {
		t.Errorf("rate 1 must pass through for the existing 'at least 2' check: %d, %v", got, err)
	}
	if _, err := rateOf(paceNormal, "abc"); err == nil {
		t.Error("non-number rate accepted")
	}
	for _, p := range paceChoices {
		if !strings.Contains(p.Sentence, strings.TrimSpace(digits(int64(p.Rate)))+" packets and requests per second") {
			t.Errorf("%s sentence does not state its rate: %q", p.Value, p.Sentence)
		}
		if pace, exact := paceOf(p.Rate); pace != p.Value || exact != "" {
			t.Errorf("paceOf(%d) = %q, %q", p.Rate, pace, exact)
		}
	}
	if pace, exact := paceOf(37); pace != paceNormal || exact != "37" {
		t.Errorf("paceOf(37) = %q, %q", pace, exact)
	}
}

func TestTargetLinesReportsLineNumbers(t *testing.T) {
	got, problems := targetLines("10.0.0.1\nfoo bar\n10.0.0.2\n\n300.1.1.1")
	if !slices.Equal(got, []string{"10.0.0.1", "10.0.0.2"}) {
		t.Errorf("valid targets %v", got)
	}
	if len(problems) != 2 || problems[0].Line != 2 || problems[1].Line != 5 {
		t.Fatalf("problems %+v", problems)
	}
	msg := lineProblemsText(problems)
	for _, want := range []string{`line 2: invalid target "foo bar"`, `line 5: invalid target "300.1.1.1"`} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q lacks %q", msg, want)
		}
	}
	got, problems = targetLines("# office\n10.0.0.0/24 # lan\n\ngw.example.org\n10.0.0.1-20\nbad!")
	if !slices.Equal(got, []string{"10.0.0.0/24", "gw.example.org", "10.0.0.1-20"}) || len(problems) != 1 || problems[0].Line != 6 {
		t.Errorf("comments and blanks: %v %+v", got, problems)
	}
	if lineProblemsText(nil) != "" {
		t.Error("text for no problems")
	}
	var many strings.Builder
	for range 15 {
		many.WriteString("x y\n")
	}
	_, problems = targetLines(many.String())
	if msg := lineProblemsText(problems); !strings.Contains(msg, "and 5 more invalid lines") || strings.Contains(msg, "line 11:") {
		t.Errorf("long list not cut: %q", msg)
	}
}

func TestTargetFile(t *testing.T) {
	got, problems := targetFile("t.txt", []byte("10.0.0.1\n10.0.1.0/30\n"))
	if !slices.Equal(got, []string{"10.0.0.1", "10.0.1.0/30"}) || problems != nil {
		t.Errorf("txt: %v %+v", got, problems)
	}
	got, problems = targetFile("t.csv", []byte("\ufefftarget,comment\r\n10.0.0.1,web\r\n10.0.2.0/30,lab\r\n"))
	if !slices.Equal(got, []string{"10.0.0.1", "10.0.2.0/30"}) || problems != nil {
		t.Errorf("csv: %v %+v", got, problems)
	}
	got, _ = targetFile("t.csv", []byte("Address;note\n\"10.0.0.9\";x\n"))
	if !slices.Equal(got, []string{"10.0.0.9"}) {
		t.Errorf("csv with semicolons and quotes: %v", got)
	}
	got, problems = targetFile("hosts.csv", []byte("address\n10.0.0.1\n\nnot a target!,x\n"))
	if !slices.Equal(got, []string{"10.0.0.1"}) || len(problems) != 1 || problems[0].Line != 4 {
		t.Fatalf("invalid file line: %v %+v", got, problems)
	}
	if msg := lineProblemsText(problems); !strings.Contains(msg, `file hosts.csv, line 4: invalid target "not a target!"`) {
		t.Errorf("file message %q", msg)
	}
	if got, _ = targetFile("t.txt", []byte("10.0.0.1\naddress\n")); !slices.Equal(got, []string{"10.0.0.1", "address"}) {
		t.Errorf("header word after the first row must be kept as a host name: %v", got)
	}
}

func TestScheduleWindowsAndSummary(t *testing.T) {
	ws, err := scheduleWindows([]string{"sat"}, "22:00", "06:00", "")
	if err != nil {
		t.Fatal(err)
	}
	want := []schedule.Window{{Days: []time.Weekday{time.Saturday}, Start: "22:00", End: "06:00"}}
	if !slices.EqualFunc(ws, want, func(a, b schedule.Window) bool {
		return slices.Equal(a.Days, b.Days) && a.Start == b.Start && a.End == b.End
	}) {
		t.Errorf("windows %+v", ws)
	}
	s := schedule.Schedule{Windows: ws, Frequency: schedule.Frequency{Kind: schedule.FrequencyWeekly}, RecheckEvery: "1h"}
	if got := scheduleSummary(true, s); got != "Full scan every Saturday 22:00-06:00; recheck of known services every hour" {
		t.Errorf("summary %q", got)
	}
	s.RecheckEvery = "30m"
	if got := scheduleSummary(true, s); got != "Full scan every Saturday 22:00-06:00; recheck of known services every 30 minutes" {
		t.Errorf("summary %q", got)
	}
	if got := scheduleSummary(false, s); got != "Run only when started by hand" {
		t.Errorf("manual summary %q", got)
	}

	ws, err = scheduleWindows([]string{"sat"}, "22:00", "06:00", "mon-fri 22:00-06:00\nsun 01:00-05:00")
	if err != nil || len(ws) != 2 || len(ws[0].Days) != 5 {
		t.Fatalf("windows text must win: %+v %v", ws, err)
	}
	s = schedule.Schedule{Windows: ws, Frequency: schedule.Frequency{Kind: schedule.FrequencyInterval, Every: "6h"}}
	if got := scheduleSummary(true, s); got != "Full scan every 6 hours during Monday to Friday 22:00-06:00 and Sunday 01:00-05:00" {
		t.Errorf("interval summary %q", got)
	}
	s = schedule.Schedule{Windows: ws[:1], Frequency: schedule.Frequency{Kind: schedule.FrequencyDaily}}
	if got := scheduleSummary(true, s); got != "Full scan every Monday to Friday 22:00-06:00" {
		t.Errorf("daily summary %q", got)
	}
	if got := scheduleSummary(true, schedule.Schedule{Frequency: schedule.Frequency{Kind: schedule.FrequencyDaily}}); got != "Full scan every day" {
		t.Errorf("daily without windows %q", got)
	}

	for _, c := range []struct {
		days       []string
		start, end string
		text       string
		field      string
	}{
		{nil, "22:00", "06:00", "", "days"},
		{[]string{"sat"}, "", "06:00", "", "window"},
		{[]string{"sat"}, "25:00", "06:00", "", "window"},
		{nil, "", "", "someday 1-2", "windows"},
	} {
		_, err := scheduleWindows(c.days, c.start, c.end, c.text)
		fp, ok := err.(*formProblem)
		if !ok || fp.Field != c.field {
			t.Errorf("%+v: got %v, want problem on %s", c, err, c.field)
		}
	}
	if _, err := scheduleWindows(nil, "", "", ""); !strings.Contains(err.Error(), "at least one weekday") {
		t.Errorf("no day: %v", err)
	}

	days, start, end, text := windowControls(want)
	if !slices.Equal(days, []string{"sat"}) || start != "22:00" || end != "06:00" || text != "" {
		t.Errorf("controls of one window: %v %s %s %q", days, start, end, text)
	}
	days, _, _, text = windowControls(ws)
	if days != nil || text != "mon-fri 22:00-06:00\nsun 01:00-05:00" {
		t.Errorf("controls of two windows: %v %q", days, text)
	}
}

func TestPlanSentenceAndWarnings(t *testing.T) {
	s := &scan.Scanner{}
	ports, _ := portsOf(presetCustom, "80,443")
	p, err := s.Plan(context.Background(), inventory.RunSettings{Targets: []string{"10.0.0.0/24"}, Excludes: []string{"10.0.0.0/28"},
		Ports: ports, MaxRate: paceRate(paceNormal)})
	if err != nil {
		t.Fatal(err)
	}
	want := "239 addresses after excludes, 2 ports, 4 groups, at most 47\u2009322 packets and requests, estimated about 1 min or less at this rate (at most 13 min 42 s if every address answered)"
	if got := planSentence(p); got != want {
		t.Errorf("sentence\n got %q\nwant %q", got, want)
	}
	if w := planWarnings(p, presetCustom); w != nil {
		t.Errorf("unexpected warnings %v", w)
	}

	web, _ := portsOf(presetWeb, "")
	small, err := s.Plan(context.Background(), inventory.RunSettings{Targets: []string{"10.0.0.0/28"}, Ports: web, MaxRate: 100})
	if err != nil {
		t.Fatal(err)
	}
	if w := planWarnings(small, presetWeb); w != nil {
		t.Errorf("warnings for a small web scan: %v", w)
	}
	big := small
	big.Addresses = 131072
	if w := planWarnings(big, presetWeb); len(w) != 1 || !strings.Contains(w[0], "65\u2009536 addresses") || !strings.Contains(w[0], "131\u2009072") {
		t.Errorf("bound warning %v", w)
	}
	if w := planWarnings(small, presetAll); len(w) != 1 || !strings.Contains(w[0], "All 65\u2009535 ports") {
		t.Errorf("all-ports warning %v", w)
	}
	one := scan.Plan{Addresses: 1, Ports: []int{80}, Groups: 1}
	if got := planSentence(one); !strings.HasPrefix(got, "1 address after excludes, 1 port, 1 group,") {
		t.Errorf("singular %q", got)
	}
}

func TestServerTimezone(t *testing.T) {
	tz := serverTimezone()
	if tz == "" || tz == "Local" {
		t.Errorf("server timezone %q", tz)
	}
	if _, err := time.LoadLocation(tz); err != nil {
		t.Errorf("server timezone %q does not load: %v", tz, err)
	}
	want := time.Local.String()
	if want == "Local" {
		want = "UTC"
	}
	if tz != want {
		t.Errorf("server timezone %q, want %q (time.Local name, UTC when Local)", tz, want)
	}
	opts := timezoneOptions("America/New_York")
	if !slices.Contains(opts, tz) || !slices.Contains(opts, "America/New_York") || !slices.Contains(timezoneOptions("Pacific/Fiji"), "Pacific/Fiji") {
		t.Errorf("options %v", opts)
	}
}

func TestPlanTimeBeyondDuration(t *testing.T) {
	p := scan.Plan{Packets: 1_640_000_000_000, Requests: 50_000_000, MaxRate: 100, AtMaxRate: time.Duration(1<<63 - 1)}
	if got := planTime(p); got != "9\u2009111\u2009111 h" {
		t.Errorf("planTime = %q", got)
	}
	p = scan.Plan{Packets: 3_000_000, Requests: 10, MaxRate: 100, AtMaxRate: 60000 * time.Second}
	if got := planTime(p); got != "16 h 40 min" {
		t.Errorf("planTime = %q", got)
	}
	if got := formatDuration(5000 * time.Hour); got != "5\u2009000 h 0 min" {
		t.Errorf("formatDuration = %q", got)
	}
}
