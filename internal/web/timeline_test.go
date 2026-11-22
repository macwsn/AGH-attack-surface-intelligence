package web

import (
	"context"
	"fmt"
	"io/fs"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"asi/internal/inventory"
	"asi/internal/probe"
)

func (f *fakeInventory) HostTimeline(_ context.Context, address string) (inventory.Timeline, error) {
	return inventory.Timeline{}, fmt.Errorf("timeline: %w: %s", inventory.ErrUnknownHost, address)
}

type timelineInventory struct {
	*fakeInventory
	timelines map[string]inventory.Timeline
}

func (t timelineInventory) HostTimeline(ctx context.Context, address string) (inventory.Timeline, error) {
	tl, ok := t.timelines[address]
	if !ok {
		return t.fakeInventory.HostTimeline(ctx, address)
	}
	return tl, nil
}

func stateWithTitle(addr, title string) *inventory.ExportHost {
	return &inventory.ExportHost{Address: addr, Status: inventory.StatusActive, Services: []inventory.ExportService{{
		Port: 80, Protocol: "tcp", Status: inventory.StatusActive, HTTP: &probe.HTTP{StatusCode: 200, Title: title}}}}
}

func sampleTimeline(usual bool) inventory.Timeline {
	t0 := time.Date(2026, 11, 18, 9, 5, 0, 0, time.UTC)
	entry := func(i int, covered, seen bool, state *inventory.ExportHost) inventory.TimelineEntry {
		return inventory.TimelineEntry{Run: inventory.Run{ID: int64(i + 1), Name: fmt.Sprintf("r%d", i+1)},
			At: t0.AddDate(0, 0, i), Covered: covered, Seen: seen, State: state}
	}
	host := *stateWithTitle("10.0.0.5", `<b>v2</b>`)
	host.Status = inventory.StatusUnstable
	return inventory.Timeline{
		Address: "10.0.0.5", Host: host, Score: 75,
		Reasons: []inventory.Reason{{Code: "admin-panel", Label: "Admin panel on 80/tcp", Points: 30}, {Code: "staging", Label: "Staging environment on 80/tcp", Points: 45}},
		Pattern: inventory.Pattern{Start: 8, End: 16}, Usual: usual,
		Entries: []inventory.TimelineEntry{
			entry(0, true, true, stateWithTitle("10.0.0.5", "v1")),
			entry(1, true, false, stateWithTitle("10.0.0.5", "v1")),
			entry(2, false, false, nil),
			entry(3, true, true, stateWithTitle("10.0.0.5", `<b>v2</b>`)),
		},
	}
}

func newTimelineRouter(t *testing.T, timelines map[string]inventory.Timeline) (*Router, *http.Cookie) {
	t.Helper()
	fa := newFakeAuth()
	inv := timelineInventory{fakeInventory: &fakeInventory{}, timelines: timelines}
	r, err := build(Deps{Auth: fa, Inventory: inv}, files, features)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return r, fa.session(t, "victor")
}

var stripRect = regexp.MustCompile(`<rect class="([a-z]+)" x="[0-9.]+" y="0.5" width="7" height="15"><title>([^<]*)</title></rect>`)

// REQ-WEB-013
func TestTimelinePage(t *testing.T) {
	r, viewer := newTimelineRouter(t, map[string]inventory.Timeline{"10.0.0.5": sampleTimeline(false)})
	rec := do(r, http.MethodGet, "/hosts/10.0.0.5/timeline", nil, viewer)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET timeline = %d\n%s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	var classes []string
	for _, m := range stripRect.FindAllStringSubmatch(body, -1) {
		classes = append(classes, m[1])
	}
	if strings.Join(classes, ",") != "seen,missed,uncovered,seen" || !strings.Contains(body, "<title>r3, "+zonedTime(time.Date(2026, 11, 20, 9, 5, 0, 0, time.UTC), nil)+": Not covered</title>") {
		t.Errorf("strip cells = %v:\n%s", classes, body)
	}
	for _, want := range []string{
		`<svg class="strip" role="img" aria-label="Seen in 2 of 3 covering runs" width="40" height="16" viewBox="0 0 40 16">`,
		`<span class="meter high"><progress max="100" value="75"></progress>75</span>`,
		`<tr data-reason="admin-panel"><td>Admin panel on 80/tcp</td><td class="num">30</td></tr>`,
		`<tr data-reason="staging"><td>Staging environment on 80/tcp</td><td class="num">45</td></tr>`,
		`<span class="status unstable">Unstable</span>`,
		`http.title <del>v1</del> <ins>&lt;b&gt;v2&lt;/b&gt;</ins>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %s:\n%s", want, body)
		}
	}
	if strings.Contains(body, "<b>v2</b>") || strings.Contains(body, "style=") || strings.Contains(body, "<style") ||
		strings.Contains(body, "Usually seen") || externalRef.MatchString(body) {
		t.Errorf("page is unescaped, styled inline, references external resources or shows a pattern:\n%s", body)
	}
	if i, j := strings.Index(body, `data-run="r4"`), strings.Index(body, `data-run="r1"`); i < 0 || j < 0 || i > j {
		t.Errorf("runs table is not newest first")
	}
}

// REQ-WEB-013
func TestTimelineUsualHours(t *testing.T) {
	r, viewer := newTimelineRouter(t, map[string]inventory.Timeline{"10.0.0.5": sampleTimeline(true)})
	body := do(r, http.MethodGet, "/hosts/10.0.0.5/timeline", nil, viewer).Body.String()
	if !strings.Contains(body, `<span class="muted">Usually seen 08:00-16:00</span>`) || strings.Contains(body, "Unstable") {
		t.Errorf("usual hours not shown instead of unstable:\n%s", body)
	}
}

// REQ-WEB-013
func TestTimelineBadInputs(t *testing.T) {
	r, viewer := newTimelineRouter(t, nil)
	cases := []struct {
		target string
		status int
		want   string
	}{
		{"/hosts/nope/timeline", http.StatusBadRequest, `&#34;nope&#34; is not an address.`},
		{"/hosts/10.0.0.300/timeline", http.StatusBadRequest, `&#34;10.0.0.300&#34; is not an address.`},
		{"/hosts/%3Cscript%3Ealert(1)%3C%2Fscript%3E/timeline", http.StatusBadRequest, `&#34;&lt;script&gt;alert(1)&lt;/script&gt;&#34; is not an address.`},
		{"/hosts/10.0.0.99/timeline", http.StatusNotFound, "No host with address 10.0.0.99 has been seen."},
	}
	for _, c := range cases {
		rec := do(r, http.MethodGet, c.target, nil, viewer)
		body := rec.Body.String()
		if rec.Code != c.status || !strings.Contains(body, c.want) || strings.Contains(body, "<script>alert") {
			t.Errorf("%s = %d, want %d with %q:\n%s", c.target, rec.Code, c.status, c.want, body)
		}
	}
}

// REQ-WEB-007
func TestTimelineTemplateAndStripComponent(t *testing.T) {
	tpl, err := fs.ReadFile(files, "timeline.html")
	if err != nil {
		t.Fatal(err)
	}
	if s := string(tpl); strings.Contains(s, "style=") || strings.Contains(s, "<style") || strings.Contains(s, "<script") {
		t.Error("timeline.html has inline style or script")
	}
	css, err := fs.ReadFile(files, "static/app.css")
	if err != nil {
		t.Fatal(err)
	}
	guide, err := fs.ReadFile(files, "static/styleguide.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, sel := range []string{"svg.strip rect.seen", "svg.strip rect.missed", "svg.strip rect.uncovered"} {
		if !strings.Contains(string(css), sel) {
			t.Errorf("app.css lacks %s", sel)
		}
	}
	if !strings.Contains(string(guide), `<svg class="strip"`) {
		t.Error("styleguide lacks the SVG presence strip")
	}
}

func TestTimelineIgnoresConfiguredAndRunVolatileHeaders(t *testing.T) {
	withHeaders := func(trace, node string) *inventory.ExportHost {
		h := stateWithTitle("10.0.0.6", "same")
		h.Services[0].HTTP.Headers = map[string]string{"x-trace-id": trace, "x-backend-node": node}
		return h
	}
	at := time.Date(2026, 11, 18, 9, 5, 0, 0, time.UTC)
	tl := inventory.Timeline{Address: "10.0.0.6", Host: *withHeaders("t2", "n2"), Entries: []inventory.TimelineEntry{
		{Run: inventory.Run{ID: 1, Name: "v1"}, At: at, Covered: true, Seen: true, State: withHeaders("t1", "n1")},
		{Run: inventory.Run{ID: 2, Name: "v2", Settings: inventory.RunSettings{VolatileHeaders: []string{"x-backend-node"}}},
			At: at.Add(time.Hour), Covered: true, Seen: true, State: withHeaders("t2", "n2")},
	}}
	changes := func(tl inventory.Timeline) int {
		n := 0
		for _, r := range newTimelineData(tl).Runs {
			n += len(r.Changes)
		}
		return n
	}
	if n := changes(tl); n == 0 {
		t.Fatalf("control: x-trace-id differs and is not volatile, want a change")
	}
	tl.VolatileHeaders = []string{"x-trace-id"}
	if n := changes(tl); n != 0 {
		t.Errorf("timeline shows %d changes for headers listed in configuration and run settings, want none", n)
	}
}
