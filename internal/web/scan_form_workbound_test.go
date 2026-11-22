package web

import (
	"net/http"
	"net/url"
	"regexp"
	"testing"

	"asi/internal/schedule"
)

var workProblem = regexp.MustCompile(`(?s)name="targets"[^>]*aria-invalid="true".*?<span class="problem">[^<]*262144 addresses x 1001 ports`)

func TestScanFormRefusesAddressesTimesPortsAboveCeiling(t *testing.T) {
	fa := newFakeAuth()
	r, err := build(Deps{Auth: fa, Scans: &schedule.Scheduler{Store: &schedule.Store{}}}, files, features)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	sess := fa.session(t, "alice")
	form := url.Values{
		"csrf_token": {"csrf-alice"}, "name": {"wide"}, "targets": {"10.0.0.0/14"}, "ports": {"1-1001"},
		"max_rate": {"100"}, "workers": {"1"}, "inactive_after": {"3"}, "timezone": {"Europe/Warsaw"},
		"windows": {"mon-fri 22:00-06:00"}, "frequency": {"daily"},
	}
	rec := do(r, http.MethodPost, "/scans", form, sess)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("POST /scans of 262144 addresses x 1001 ports = %d, want 422", rec.Code)
	}
	if !workProblem.MatchString(rec.Body.String()) {
		t.Errorf("form of 262144 addresses x 1001 ports shows no targets problem naming both numbers:\n%s", rec.Body.String())
	}
}
