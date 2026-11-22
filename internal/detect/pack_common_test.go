package detect

import (
	"slices"
	"sort"
	"strings"
	"testing"
)

func TestPackDocumentedProducts(t *testing.T) {
	cases := []struct {
		dir, name, category, version string
		kinds                        []string
	}{
		{"grafana", "Grafana", "monitoring", "10.4.2", []string{"technology"}},
		{"jenkins", "Jenkins", "ci-cd", "2.440.3", []string{"admin-panel", "technology"}},
		{"gitlab", "GitLab", "code-hosting", "", []string{"technology"}},
		{"tomcat", "Apache Tomcat", "application-server", "9.0.85", []string{"technology"}},
		{"kibana", "Kibana", "monitoring", "8.13.0", []string{"technology"}},
		{"portainer", "Portainer", "container-management", "", []string{"admin-panel", "technology"}},
		{"minio", "MinIO", "object-storage", "", []string{"technology"}},
		{"prometheus", "Prometheus", "monitoring", "", []string{"technology"}},
		{"keycloak", "Keycloak", "identity", "", []string{"technology"}},
		{"joomla", "Joomla", "cms", "", []string{"technology"}},
		{"drupal", "Drupal", "cms", "10", []string{"technology"}},
		{"roundcube", "Roundcube", "webmail", "", []string{"technology"}},
		{"zabbix", "Zabbix", "monitoring", "", []string{"technology"}},
		{"proxmox", "Proxmox VE", "virtualization", "8.1.4", []string{"admin-panel", "technology"}},
		{"pfsense", "pfSense", "firewall", "", []string{"admin-panel", "technology"}},
		{"synology", "Synology DSM", "nas", "", []string{"admin-panel", "technology"}},
		{"mikrotik", "MikroTik RouterOS", "network-device", "6.49.10", []string{"admin-panel", "technology"}},
		{"hikvision", "Hikvision", "camera", "", []string{"iot", "technology"}},
		{"dahua", "Dahua", "camera", "", []string{"iot", "technology"}},
		{"hp-printer", "HP Printer", "printer", "", []string{"iot", "technology"}},
		{"brother-printer", "Brother Printer", "printer", "", []string{"iot", "technology"}},
		{"admin-login", "", "", "", []string{"admin-panel"}},
	}
	for _, c := range cases {
		t.Run(c.dir, func(t *testing.T) {
			res := runPackFixture(t, c.dir)
			if c.name != "" {
				i := slices.IndexFunc(res.Technologies, func(tc Technology) bool { return tc.Name == c.name })
				if i < 0 {
					t.Fatalf("technologies = %+v, want %q", res.Technologies, c.name)
				}
				tc := res.Technologies[i]
				if tc.Category != c.category || tc.Version != c.version {
					t.Errorf("%s = category %q version %q, want %q %q", c.name, tc.Category, tc.Version, c.category, c.version)
				}
				if c.name == "Joomla" || c.name == "Drupal" {
					if n := countName(res.Technologies, c.name); n != 1 {
						t.Errorf("%d technologies named %s, want one merged entry", n, c.name)
					}
				}
			}
			kinds := map[string]bool{}
			for _, f := range res.Findings {
				if !strings.HasPrefix(f.SignatureID, PackIDPrefix) {
					continue
				}
				if c.name != "" && f.Name != c.name {
					t.Errorf("finding %s names %q, want %q", f.SignatureID, f.Name, c.name)
				}
				kinds[f.Kind] = true
			}
			got := make([]string, 0, len(kinds))
			for k := range kinds {
				got = append(got, k)
			}
			sort.Strings(got)
			if !slices.Equal(got, c.kinds) {
				t.Errorf("finding kinds = %v, want %v (findings %+v)", got, c.kinds, res.Findings)
			}
		})
	}
}

func countName(techs []Technology, name string) int {
	n := 0
	for _, tc := range techs {
		if tc.Name == name {
			n++
		}
	}
	return n
}
