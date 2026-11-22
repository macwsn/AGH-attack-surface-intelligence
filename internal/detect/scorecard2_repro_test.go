package detect

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"asi/internal/probe"
)

func detectLabServiceWithLabSignatures(t *testing.T, name string) Result {
	t.Helper()
	lab, err := LoadDir("../../lab/signatures")
	if err != nil {
		t.Fatal(err)
	}
	set, err := Combine(lab, mustPack(t))
	if err != nil {
		t.Fatal(err)
	}
	s := parseLabService(t, filepath.Join(labServicesDir, name))
	f := &fixtureFetcher{responses: map[string]*probe.Response{"/": s.response(t, "/")}}
	for _, sig := range set.Signatures {
		if _, ok := f.responses[sig.Path]; !ok {
			r, _ := s.raw(t, sig.Path)
			parsed, err := parseRawResponses(packFixtureBase, sig.Path, []byte(r))
			if err != nil {
				t.Fatal(err)
			}
			f.responses[sig.Path] = parsed
		}
	}
	root := f.responses["/"]
	h := &probe.HTTP{Scheme: "http", URL: "http://192.0.2.7/", StatusCode: root.StatusCode, Title: root.Title,
		Headers: root.Headers, Cookies: root.Cookies, RedirectChain: root.RedirectChain}
	return set.withNotable(set.detect(context.Background(), f, h), h, root.Body)
}

// AC1: the same kind+name found by several signatures on one service is one finding with the highest confidence
// and the contributing signature ids in its evidence.
func TestReproFindingsAreUniquePerServiceByKindAndName(t *testing.T) {
	cases := []struct {
		service, kind, name string
		confidence          int
		ids                 []string
	}{
		{"staging", KindStaging, "Staging or test environment", 75, []string{"staging-environment", "builtin-staging-header", "builtin-staging-title"}},
		{"wp", "technology", "WordPress", 95, []string{"wordpress-generator", "builtin-wordpress"}},
		{"drupal", "technology", "Drupal", 90, []string{"drupal-x-generator", "builtin-drupal"}},
	}
	for _, c := range cases {
		t.Run(c.service, func(t *testing.T) {
			res := detectLabServiceWithLabSignatures(t, c.service)
			var got []Finding
			seen := map[string]int{}
			for _, f := range res.Findings {
				seen[f.Kind+"\x00"+f.Name]++
				if f.Kind == c.kind && f.Name == c.name {
					got = append(got, f)
				}
			}
			for k, n := range seen {
				if n > 1 {
					t.Errorf("finding %q stored %d times on one service, want once", strings.ReplaceAll(k, "\x00", " "), n)
				}
			}
			if len(got) != 1 {
				t.Fatalf("%s %q findings = %d, want exactly one (%+v)", c.kind, c.name, len(got), res.Findings)
			}
			if got[0].Confidence != c.confidence {
				t.Errorf("merged confidence = %d, want the highest %d", got[0].Confidence, c.confidence)
			}
			for _, id := range c.ids {
				if !strings.Contains(got[0].Evidence, id) && got[0].SignatureID != id {
					t.Errorf("merged finding %+v does not list contributing signature %s", got[0], id)
				}
			}
		})
	}
}

// AC1: a plain Server: nginx header without a version is not a notable-header finding.
func TestReproPlainServerNginxIsNotANotableHeader(t *testing.T) {
	for _, v := range []string{"nginx", "nginx (Ubuntu)"} {
		h := &probe.HTTP{Scheme: "http", URL: "http://192.0.2.1/", StatusCode: 200, Title: "Welcome to nginx!", Headers: map[string]string{"server": v}}
		for _, f := range packSet(t).DetectRecorded(h).Findings {
			if f.Kind == KindInterestingHeader {
				t.Errorf("Server: %s produced notable-header finding %+v", v, f)
			}
		}
	}
}
