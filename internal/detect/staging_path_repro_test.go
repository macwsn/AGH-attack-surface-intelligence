package detect

import (
	"errors"
	"fmt"
	"testing"

	"asi/internal/probe"
)

// AC2: the built-in pack itself detects staging and test environments, without the lab's signature file.
func TestPackDetectsStagingEnvironments(t *testing.T) {
	set := packSet(t)
	cases := []struct {
		name    string
		url     string
		title   string
		headers map[string]string
		want    bool
	}{
		{"x-environment header", "http://www.example.org/", "Home", map[string]string{"x-environment": "staging"}, true},
		{"x-env header", "http://www.example.org/", "Home", map[string]string{"x-env": "test"}, true},
		{"x-stage header", "http://www.example.org/", "Home", map[string]string{"x-stage": "uat"}, true},
		{"staging hostname", "http://staging.example.org/", "Home", nil, true},
		{"dev hostname", "http://dev.example.org/", "Home", nil, true},
		{"preprod hostname", "https://shop-preprod.example.org/", "Home", nil, true},
		{"sandbox hostname", "http://sandbox.example.org/", "Home", nil, true},
		{"bracketed title", "http://www.example.org/", "[STAGING] Shop", nil, true},
		{"test word title", "http://www.example.org/", "Shop - test environment", nil, true},
		{"uat title", "http://www.example.org/", "Portal (UAT)", nil, true},
		{"stage hostname", "http://stage.example.org/", "Home", nil, true},
		{"latest in title", "http://www.example.org/", "Latest news", nil, false},
		{"contest hostname", "http://contest.example.org/", "Contest", nil, false},
		{"device title", "http://www.example.org/", "Device manager", nil, false},
		{"developer hostname", "http://developer.example.org/", "Developers", nil, false},
		{"testimonials title", "http://www.example.org/", "Testimonials", nil, false},
		{"backstage title", "http://www.example.org/", "Backstage pass", nil, false},
		{"production header", "http://www.example.org/", "Home", map[string]string{"x-environment": "production"}, false},
		{"plain site", "http://www.example.org/", "Welcome", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := &probe.HTTP{Scheme: "http", URL: c.url, StatusCode: 200, Title: c.title, Headers: c.headers}
			res := set.DetectRecorded(h)
			var got []Finding
			for _, f := range res.Findings {
				if f.Kind == "staging" {
					got = append(got, f)
				}
			}
			if c.want && len(got) == 0 {
				t.Fatalf("no staging finding from the built-in pack for url %q title %q headers %v; findings %+v", c.url, c.title, c.headers, res.Findings)
			}
			if !c.want && len(got) > 0 {
				t.Fatalf("false staging finding for url %q title %q headers %v: %+v", c.url, c.title, c.headers, got)
			}
			for _, f := range got {
				if f.Confidence < 60 || f.Confidence > 75 {
					t.Errorf("staging finding %s confidence %d, want 60-75", f.SignatureID, f.Confidence)
				}
			}
		})
	}
}

// AC3: a signature request path with traversal, encoded traversal, backslashes, a scheme or host, a query or a
// fragment is rejected under the path rule.
func TestSignaturePathRejectsTraversal(t *testing.T) {
	cases := []struct {
		path string
		ok   bool
	}{
		{"/robots.txt", true},
		{"/admin/login", true},
		{"/../../etc/passwd", false},
		{"/static/../../etc/passwd", false},
		{"/..", false},
		{"/%2e%2e/etc/passwd", false},
		{"/%2E%2E/%2e%2e/etc/passwd", false},
		{"/a/%2e%2e/b", false},
		{"/a\\..\\b", false},
		{"/a\\b", false},
		{"//evil.example/x", false},
		{"http://evil.example/x", false},
		{"/x?a=1", false},
		{"/x#frag", false},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			src := fmt.Sprintf("- id: path-test\n  name: Path test\n  kind: custom\n  confidence: 50\n  request: { path: %q }\n  match:\n    all:\n      - { type: status, value: \"200\" }\n", c.path)
			_, err := Parse([]byte(src))
			if c.ok {
				if err != nil {
					t.Fatalf("path %q rejected: %v", c.path, err)
				}
				return
			}
			var re *RuleError
			if !errors.As(err, &re) || re.Rule != RulePath {
				t.Fatalf("path %q accepted or rejected under the wrong rule: err = %v", c.path, err)
			}
		})
	}
}
