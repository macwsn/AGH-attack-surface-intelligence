package web

import (
	"net/http"
	"net/url"
	"regexp"
	"testing"

	"asi/internal/schedule"
)

var (
	maxRateInput   = regexp.MustCompile(`<input type="number" name="max_rate"[^>]*>`)
	maxRateHint    = regexp.MustCompile(`(?i)name="max_rate"[^>]*><span class="hint">[^<]*(at least 2|minimum (is |of )?2|2 or more)`)
	maxRateProblem = regexp.MustCompile(`(?i)name="max_rate"[^>]*aria-invalid="true"[^>]*>.*?<span class="problem">[^<]*at least 2`)
	minTwo         = regexp.MustCompile(`\bmin="2"`)
)

func TestScanFormRejectsMaxRateBelowTwo(t *testing.T) {
	r, fa := newTestRouter(t)
	sess := fa.session(t, "alice")

	rec := do(r, http.MethodGet, "/scans/new", nil, sess)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /scans/new = %d", rec.Code)
	}
	body := rec.Body.String()
	if input := maxRateInput.FindString(body); !minTwo.MatchString(input) {
		t.Errorf("max rate input %q does not use min=\"2\"", input)
	}
	if !maxRateHint.MatchString(body) {
		t.Errorf("max rate hint does not state the minimum of 2")
	}

	form := url.Values{
		"csrf_token": {"csrf-alice"}, "name": {"max rate one"}, "targets": {"10.0.0.0/28"}, "ports": {"80,443"},
		"max_rate": {"1"}, "workers": {"not-a-number"}, "inactive_after": {"3"}, "timezone": {"Europe/Warsaw"},
		"windows": {"mon-fri 22:00-06:00"}, "frequency": {"daily"},
	}
	rec = do(r, http.MethodPost, "/scans", form, sess)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("POST /scans = %d, want 422", rec.Code)
	}
	if !maxRateProblem.MatchString(rec.Body.String()) {
		t.Errorf("form with max rate 1 shows no max rate problem asking for at least 2")
	}
}

func TestScanFormKeepsVolatileHeaders(t *testing.T) {
	req := &http.Request{PostForm: url.Values{"name": {"lan"}, "targets": {"192.0.2.0/29"}, "ports": {"80"},
		"max_rate": {"100"}, "workers": {"2"}, "inactive_after": {"3"}, "volatile_headers": {"X-Trace-Id, x-backend-node"}}}
	f, d := parseScanForm(req.PostForm, nil, schedule.Definition{})
	if got := d.Settings.VolatileHeaders; len(got) != 2 || got[0] != "x-trace-id" || got[1] != "x-backend-node" {
		t.Errorf("definition volatile headers = %q, want [x-trace-id x-backend-node]", got)
	}
	if again := scanFormOf(d); again.VolatileHeaders != "x-trace-id, x-backend-node" || f.VolatileHeaders != "X-Trace-Id, x-backend-node" {
		t.Errorf("form round trip = %q (posted %q)", again.VolatileHeaders, f.VolatileHeaders)
	}
}
