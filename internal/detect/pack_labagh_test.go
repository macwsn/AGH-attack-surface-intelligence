package detect

import (
	"slices"
	"strings"
	"testing"
)

func TestPackLabAGHProducts(t *testing.T) {
	cases := []struct {
		dir, name, category, version string
		versionPrefix                bool
		kinds                        []string
	}{
		{dir: "wordpress", name: "WordPress", category: "cms", version: "7.1.5", kinds: []string{"technology"}},
		{dir: "wordpress-4.7", name: "WordPress", category: "cms", version: "4.7", versionPrefix: true, kinds: []string{"technology"}},
		{dir: "phpmyadmin", name: "phpMyAdmin", category: "database-admin", version: "5.2.3", kinds: []string{"admin-panel", "technology"}},
		{dir: "adminer", name: "Adminer", category: "database-admin", version: "6.3.0", kinds: []string{"admin-panel", "technology"}},
		{dir: "dvwa", name: "DVWA", category: "web-application", version: "1.10", kinds: []string{"technology"}},
		{dir: "gitea", name: "Gitea", category: "code-hosting", version: "28.4.0", kinds: []string{"technology"}},
		{dir: "rabbitmq", name: "RabbitMQ", category: "message-broker", kinds: []string{"admin-panel", "technology"}},
		{dir: "traefik", name: "Traefik", category: "reverse-proxy", version: "3.1.7", kinds: []string{"admin-panel", "technology"}},
		{dir: "nginx-proxy-manager", name: "Nginx Proxy Manager", category: "reverse-proxy", kinds: []string{"admin-panel", "technology"}},
		{dir: "httpbin", name: "httpbin", category: "development-tool", version: "0.9.2", kinds: []string{"technology"}},
		{dir: "toxiproxy", name: "Toxiproxy", category: "development-tool", version: "2.12.0", kinds: []string{"technology"}},
	}
	for _, c := range cases {
		t.Run(c.dir, func(t *testing.T) {
			res := runPackFixture(t, c.dir)
			i := slices.IndexFunc(res.Technologies, func(tc Technology) bool { return tc.Name == c.name })
			if i < 0 {
				t.Fatalf("no technology %q in %+v", c.name, res.Technologies)
			}
			tech := res.Technologies[i]
			if tech.Category != c.category {
				t.Errorf("%s category = %q, want %q", c.name, tech.Category, c.category)
			}
			if c.versionPrefix && !strings.HasPrefix(tech.Version, c.version) || !c.versionPrefix && tech.Version != c.version {
				t.Errorf("%s version = %q, want %q (prefix %v)", c.name, tech.Version, c.version, c.versionPrefix)
			}
			if !strings.HasPrefix(tech.Source, signatureSource+PackIDPrefix) {
				t.Errorf("%s source = %q, want a built-in pack signature", c.name, tech.Source)
			}
			var kinds []string
			for _, f := range res.Findings {
				if !slices.Contains(kinds, f.Kind) {
					kinds = append(kinds, f.Kind)
				}
			}
			slices.Sort(kinds)
			if !slices.Equal(kinds, c.kinds) {
				t.Errorf("finding kinds = %v, want %v (findings %+v)", kinds, c.kinds, res.Findings)
			}
		})
	}
}
