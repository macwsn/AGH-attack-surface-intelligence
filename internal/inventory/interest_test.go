package inventory

import (
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"asi/internal/probe"
)

var scoreAt = time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)

type svcOpt func(*ExportService)

func withFinding(kind string) svcOpt {
	return func(s *ExportService) {
		s.Findings = append(s.Findings, Finding{SignatureID: kind + "-sig", Kind: kind})
	}
}

func withTLS(selfSigned bool, notAfter time.Time) svcOpt {
	return func(s *ExportService) {
		s.HTTP = &probe.HTTP{Scheme: "https", TLS: &probe.TLS{SelfSigned: selfSigned, NotAfter: notAfter.Format(time.RFC3339)}}
	}
}

func withTech(name, version string) svcOpt {
	return func(s *ExportService) {
		s.Technologies = append(s.Technologies, Technology{Name: name, Version: version})
	}
}

func withProduct(product, version string) svcOpt {
	return func(s *ExportService) { s.Product, s.Version = product, version }
}

func inactive(s *ExportService) { s.Status = StatusInactive }

func svc(port int, opts ...svcOpt) ExportService {
	s := ExportService{Port: port, Protocol: "tcp", State: "open", Status: StatusActive}
	for _, o := range opts {
		o(&s)
	}
	return s
}

func scoredHost(firstSeen time.Time, services ...ExportService) ExportHost {
	return ExportHost{Address: "10.0.0.1", Status: StatusActive, FirstSeen: firstSeen, Services: services}
}

var oldHost = scoreAt.Add(-30 * 24 * time.Hour)

// REQ-INVENTORY-011
func TestInterestScoreDefaultWeights(t *testing.T) {
	far := scoreAt.Add(90 * 24 * time.Hour)
	cases := []struct {
		name    string
		host    ExportHost
		score   int
		reasons []Reason
	}{
		{"nothing notable", scoredHost(oldHost, svc(22), svc(443, withTLS(false, far))), 0, []Reason{}},
		{"no services", scoredHost(oldHost), 0, []Reason{}},
		{"admin panel", scoredHost(oldHost, svc(443, withFinding("admin-panel"))), 30,
			[]Reason{{ReasonAdminPanel, "Admin panel on 443/tcp", 30}}},
		{"staging", scoredHost(oldHost, svc(8000, withFinding("staging"))), 20,
			[]Reason{{ReasonStaging, "Staging environment on 8000/tcp", 20}}},
		{"iot", scoredHost(oldHost, svc(80, withFinding("iot"))), 25,
			[]Reason{{ReasonIoT, "IoT device on 80/tcp", 25}}},
		{"interesting header", scoredHost(oldHost, svc(80, withFinding("interesting-header"))), 10,
			[]Reason{{ReasonInterestingHeader, "Notable header on 80/tcp", 10}}},
		{"interesting cookie", scoredHost(oldHost, svc(80, withFinding("interesting-cookie"))), 10,
			[]Reason{{ReasonInterestingCookie, "Notable cookie on 80/tcp", 10}}},
		{"technology and custom findings score nothing", scoredHost(oldHost, svc(80, withFinding("technology"), withFinding("custom"))), 0, []Reason{}},
		{"same kind on two ports counts once", scoredHost(oldHost, svc(80, withFinding("admin-panel"), withFinding("admin-panel")), svc(443, withFinding("admin-panel"))), 30,
			[]Reason{{ReasonAdminPanel, "Admin panel on 80/tcp, 443/tcp", 30}}},
		{"first seen in this run", scoredHost(scoreAt), 20, []Reason{{ReasonNew, "First seen in this run", 20}}},
		{"first seen after run start", scoredHost(scoreAt.Add(time.Minute)), 20, []Reason{{ReasonNew, "First seen in this run", 20}}},
		{"first seen recently", scoredHost(scoreAt.Add(-48 * time.Hour)), 10, []Reason{{ReasonRecent, "First seen in the last 7 days", 10}}},
		{"first seen 8 days ago", scoredHost(scoreAt.Add(-8 * 24 * time.Hour)), 0, []Reason{}},
		{"self-signed", scoredHost(oldHost, svc(443, withTLS(true, far))), 10,
			[]Reason{{ReasonSelfSigned, "Self-signed certificate on 443/tcp", 10}}},
		{"expiring certificate", scoredHost(oldHost, svc(443, withTLS(false, scoreAt.Add(10*24*time.Hour)))), 10,
			[]Reason{{ReasonExpiringCert, "Certificate expires within 30 days or has expired on 443/tcp", 10}}},
		{"expired certificate", scoredHost(oldHost, svc(443, withTLS(false, scoreAt.Add(-time.Hour)))), 10,
			[]Reason{{ReasonExpiringCert, "Certificate expires within 30 days or has expired on 443/tcp", 10}}},
		{"outdated technology", scoredHost(oldHost, svc(80, withTech("PHP", "7.4.3"))), 15,
			[]Reason{{ReasonOutdated, "Outdated version on 80/tcp", 15}}},
		{"outdated product", scoredHost(oldHost, svc(80, withProduct("nginx", "1.18.0"))), 15,
			[]Reason{{ReasonOutdated, "Outdated version on 80/tcp", 15}}},
		{"current versions", scoredHost(oldHost, svc(80, withProduct("nginx", "1.27.5"), withTech("PHP", "8.3.1"), withTech("WordPress", ""))), 0, []Reason{}},
		{"inactive service is ignored", scoredHost(oldHost, svc(443, inactive, withFinding("admin-panel"), withTLS(true, far))), 0, []Reason{}},
		{"combination", scoredHost(scoreAt, svc(443, withFinding("admin-panel"), withTLS(true, far)), svc(8000, withFinding("staging"))), 80,
			[]Reason{
				{ReasonAdminPanel, "Admin panel on 443/tcp", 30},
				{ReasonStaging, "Staging environment on 8000/tcp", 20},
				{ReasonNew, "First seen in this run", 20},
				{ReasonSelfSigned, "Self-signed certificate on 443/tcp", 10},
			}},
		{"clamped at 100", scoredHost(scoreAt,
			svc(443, withFinding("admin-panel"), withFinding("interesting-cookie"), withTLS(true, scoreAt.Add(24*time.Hour)), withTech("PHP", "5.6")),
			svc(8000, withFinding("staging"), withFinding("interesting-header")),
			svc(80, withFinding("iot"))), 100,
			[]Reason{
				{ReasonAdminPanel, "Admin panel on 443/tcp", 30},
				{ReasonStaging, "Staging environment on 8000/tcp", 20},
				{ReasonIoT, "IoT device on 80/tcp", 25},
				{ReasonInterestingHeader, "Notable header on 8000/tcp", 10},
				{ReasonInterestingCookie, "Notable cookie on 443/tcp", 10},
				{ReasonNew, "First seen in this run", 20},
				{ReasonSelfSigned, "Self-signed certificate on 443/tcp", 10},
				{ReasonExpiringCert, "Certificate expires within 30 days or has expired on 443/tcp", 10},
				{ReasonOutdated, "Outdated version on 443/tcp", 15},
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			score, reasons := Score(tc.host, scoreAt, nil)
			if score != tc.score || !reflect.DeepEqual(reasons, tc.reasons) {
				t.Errorf("Score = %d %+v\nwant %d %+v", score, reasons, tc.score, tc.reasons)
			}
			if s2, r2 := Score(tc.host, scoreAt, DefaultInterestWeights); s2 != score || !reflect.DeepEqual(r2, reasons) {
				t.Errorf("nil weights and DefaultInterestWeights differ: %d %+v", s2, r2)
			}
		})
	}
}

// REQ-INVENTORY-011
func TestInterestScoreCustomWeights(t *testing.T) {
	host := scoredHost(scoreAt, svc(443, withFinding("admin-panel"), withTLS(true, scoreAt.Add(90*24*time.Hour))), svc(8000, withFinding("staging")))
	cases := []struct {
		spec    string
		score   int
		reasons []string
	}{
		{"", 80, []string{"admin-panel=30", "staging=20", "new=20", "self-signed=10"}},
		{"admin-panel=50", 100, []string{"admin-panel=50", "staging=20", "new=20", "self-signed=10"}},
		{"admin-panel=5,staging=5,new=0,self-signed=1", 11, []string{"admin-panel=5", "staging=5", "self-signed=1"}},
		{"admin-panel=0, staging=0, new=0, self-signed=0", 0, nil},
		{"iot=100", 80, []string{"admin-panel=30", "staging=20", "new=20", "self-signed=10"}},
	}
	for _, tc := range cases {
		w, err := ParseInterestWeights(tc.spec)
		if err != nil {
			t.Fatalf("ParseInterestWeights(%q): %v", tc.spec, err)
		}
		score, reasons := Score(host, scoreAt, w)
		var got []string
		for _, r := range reasons {
			got = append(got, r.Code+"="+strconv.Itoa(r.Points))
		}
		if score != tc.score || strings.Join(got, ",") != strings.Join(tc.reasons, ",") {
			t.Errorf("weights %q: score %d reasons %v, want %d %v", tc.spec, score, got, tc.score, tc.reasons)
		}
	}
}

// REQ-INVENTORY-011
func TestParseInterestWeights(t *testing.T) {
	w, err := ParseInterestWeights("")
	if err != nil || !reflect.DeepEqual(w, DefaultInterestWeights) {
		t.Fatalf("empty spec = %v, %v; want defaults", w, err)
	}
	w, err = ParseInterestWeights(" admin-panel = 40 ,outdated=0")
	if err != nil || w[ReasonAdminPanel] != 40 || w[ReasonOutdated] != 0 || w[ReasonStaging] != DefaultInterestWeights[ReasonStaging] {
		t.Fatalf("partial spec = %v, %v", w, err)
	}
	if DefaultInterestWeights[ReasonAdminPanel] != 30 {
		t.Fatal("ParseInterestWeights changed the defaults")
	}
	for spec, want := range map[string]string{
		"bogus=1":         `unknown key "bogus"`,
		"admin-panel=x":   `admin-panel: "x" is not a number`,
		"admin-panel=101": `admin-panel: "101" is not a number from 0 to 100`,
		"admin-panel=-1":  `admin-panel: "-1" is not a number`,
		"admin-panel":     `"admin-panel" is not key=points`,
		"=3":              `"=3" is not key=points`,
		"staging=1,,":     `"" is not key=points`,
	} {
		if _, err := ParseInterestWeights(spec); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("ParseInterestWeights(%q) error = %v, want %q", spec, err, want)
		}
	}
}
