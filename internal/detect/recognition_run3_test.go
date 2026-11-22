package detect

import (
	"context"
	"fmt"
	"net/http"
	"testing"
)

func TestRun3ServiceVersionBoundGivesNoTechnologyVersion(t *testing.T) {
	cases := []struct{ service, product, version string }{
		{"postgresql", "PostgreSQL DB", "9.6.0 or later"},
		{"ftp", "vsftpd", "2.0.8 or later"},
		{"ssh", "OpenSSH", "7.x"},
		{"mysql", "MySQL", "5.x"},
	}
	for _, c := range cases {
		got := ServiceTechnologies(c.service, c.product, c.version)
		if len(got) != 1 || got[0].Version != "" || got[0].Confidence >= serviceConfidence {
			t.Errorf("ServiceTechnologies(%q, %q, %q) = %+v, want one technology with an empty version and confidence below %d", c.service, c.product, c.version, got, serviceConfidence)
		}
		if f := Outdated(got); len(f) != 0 {
			t.Errorf("bound %q flagged outdated: %+v", c.version, f)
		}
	}
}

func TestRun3CustomSignatureNamedLikeBuiltinKeepsItsTechnologiesEntry(t *testing.T) {
	pack, err := Pack()
	if err != nil {
		t.Fatal(err)
	}
	custom := mustParse(t, `
- id: eval-gitea
  name: Gitea
  kind: technology
  category: code-hosting
  confidence: 90
  match:
    any:
      - { type: title_regex, value: 'Gitea' }
`)
	set, err := Combine(&Set{Signatures: custom}, pack)
	if err != nil {
		t.Fatal(err)
	}
	sess, _ := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "i_like_gitea", Value: "x"})
		fmt.Fprint(w, `<html><head><title>Gitea: Git with a cup of tea</title><meta name="author" content="Gitea - Git with a cup of tea"></head><body><a href="https://about.gitea.com">Powered by Gitea</a> Version: 1.21.4</body></html>`)
	})
	res := set.Detect(context.Background(), sess)
	finding := false
	for _, f := range res.Findings {
		if f.SignatureID == "eval-gitea" {
			finding = true
		}
	}
	if !finding {
		t.Fatalf("eval-gitea finding missing: %+v", res.Findings)
	}
	sources := map[string]bool{}
	for _, tech := range res.Technologies {
		if tech.Name == "Gitea" {
			sources[tech.Source] = true
		}
	}
	if !sources["signature:eval-gitea"] || len(sources) != 2 {
		t.Errorf("Gitea technologies sources = %v (all: %+v), want both the built-in entry and signature:eval-gitea", sources, res.Technologies)
	}
}
