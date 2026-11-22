package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"asi/internal/auth"
	"asi/internal/inventory"
)

func profileOf(obs ...inventory.HourObservation) inventory.Availability {
	return inventory.BuildAvailability(obs)
}

func repeat(n, hour int, seen bool) []inventory.HourObservation {
	out := make([]inventory.HourObservation, n)
	for i := range out {
		out[i] = inventory.HourObservation{Hour: hour, Seen: seen}
	}
	return out
}

func TestUsualHoursText(t *testing.T) {
	for _, c := range []struct {
		hours []int
		want  string
	}{
		{[]int{8, 9, 10, 11, 12, 13, 14, 15, 16, 17}, "Usually up 08:00-18:00"},
		{[]int{0, 1, 2, 3, 4, 5, 22, 23}, "Usually up 22:00-06:00"},
		{[]int{3, 10, 11, 20}, "Usually up 03:00-04:00, 10:00-12:00, 20:00-21:00"},
		{[]int{23}, "Usually up 23:00-00:00"},
		{nil, "No regular hours yet"},
	} {
		if got := usualHoursText(c.hours); got != c.want {
			t.Errorf("usualHoursText(%v) = %q, want %q", c.hours, got, c.want)
		}
	}
}

var cellRE = regexp.MustCompile(`<i( class="(seen|missed)")? title="(\d\d):00 up (\d+)%"></i>`)

func renderStrip(t *testing.T, a inventory.Availability) string {
	t.Helper()
	r, _ := newTestRouter(t)
	var b strings.Builder
	if err := r.pages["availability.html"].ExecuteTemplate(&b, "availability-strip", availabilityOf("10.0.0.5", a)); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// REQ-WEB-025
func TestAvailabilityStrip(t *testing.T) {
	var obs []inventory.HourObservation
	for h := 8; h <= 17; h++ {
		obs = append(obs, repeat(3, h, true)...)
	}
	obs = append(obs, repeat(3, 2, false)...)
	out := renderStrip(t, profileOf(obs...))
	inner := regexp.MustCompile(`<span class="presence">(.*?)</span>`).FindStringSubmatch(out)
	if inner == nil {
		t.Fatalf("no .presence strip:\n%s", out)
	}
	cells := cellRE.FindAllStringSubmatch(inner[1], -1)
	if len(cells) != 24 || strings.Count(inner[1], "<i") != 24 {
		t.Fatalf("strip has %d cells, want 24:\n%s", len(cells), out)
	}
	for h, c := range cells {
		want := ""
		switch {
		case h >= 8 && h <= 17:
			want = "seen"
		case h == 2:
			want = "missed"
		}
		if c[2] != want || c[3] != fmt.Sprintf("%02d", h) {
			t.Errorf("cell %d = %q, want hour %02d class %q", h, c[0], h, want)
		}
	}
	if !strings.Contains(out, `title="10:00 up 83%"`) || !strings.Contains(out, `title="02:00 up 17%"`) || !strings.Contains(out, `title="05:00 up 50%"`) {
		t.Errorf("cell titles:\n%s", out)
	}
	if !strings.Contains(out, "Usually up 08:00-18:00") {
		t.Errorf("usual hours missing:\n%s", out)
	}
	if regexp.MustCompile(`style\s*=`).MatchString(out) {
		t.Error("strip uses inline styles")
	}

	notPeriodic := renderStrip(t, profileOf(repeat(6, 10, true)...))
	if strings.Count(notPeriodic, "<i") != 24 || !strings.Contains(notPeriodic, "No regular hours yet") {
		t.Errorf("non-periodic host:\n%s", notPeriodic)
	}
	empty := renderStrip(t, profileOf())
	if strings.Contains(empty, "presence") || !strings.Contains(empty, "No availability data yet") {
		t.Errorf("host without samples:\n%s", empty)
	}
}

// REQ-WEB-025
func TestAvailabilityPageNeedsInventoryRead(t *testing.T) {
	r, fa := newTestRouter(t)
	fa.passwords["olga"] = "olga-password-1"
	fa.roles["olga"] = auth.Principal{Username: "olga", Role: auth.RoleOperator, Permissions: []auth.Permission{auth.PermScanRun}}
	if rec := do(r, http.MethodGet, "/hosts/10.0.0.5/availability", nil, fa.session(t, "olga")); rec.Code != http.StatusForbidden {
		t.Fatalf("user without inventory.read = %d, want 403", rec.Code)
	}
}

// REQ-WEB-025
func TestHostPageShowsAvailabilityStrip(t *testing.T) {
	var obs []inventory.HourObservation
	for h := 8; h <= 17; h++ {
		obs = append(obs, repeat(3, h, true)...)
	}
	obs = append(obs, repeat(3, 2, false)...)
	r, _ := newTestRouter(t)
	render := func(a *inventory.ExportAvailability) string {
		t.Helper()
		d := inventory.HostDetail{Run: "r1", Host: inventory.ExportHost{Address: "10.0.0.5", Availability: a}}
		rec := httptest.NewRecorder()
		r.Render(rec, httptest.NewRequest(http.MethodGet, "/hosts/10.0.0.5", nil), http.StatusOK, "host.html", View{Data: newHostView(d, time.Now())})
		if rec.Code != http.StatusOK {
			t.Fatalf("host page = %d:\n%s", rec.Code, rec.Body.String())
		}
		return rec.Body.String()
	}
	body := render(profileOf(obs...).Export())
	inner := regexp.MustCompile(`<span class="presence">(.*?)</span>`).FindStringSubmatch(body)
	if inner == nil || len(cellRE.FindAllString(inner[1], -1)) != 24 {
		t.Fatalf("host page lacks a 24-cell .presence strip:\n%s", body)
	}
	for _, want := range []string{"Usually up 08:00-18:00", `href="/hosts/10.0.0.5/availability"`} {
		if !strings.Contains(body, want) {
			t.Errorf("host page lacks %s", want)
		}
	}
	if regexp.MustCompile(`style\s*=`).MatchString(body) {
		t.Error("host page uses inline styles")
	}
	empty := render(nil)
	if strings.Contains(empty, `class="presence"`) || !strings.Contains(empty, "No availability data yet") {
		t.Errorf("host without samples:\n%s", empty)
	}
}
