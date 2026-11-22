package detect

import (
	"slices"
	"strings"
	"testing"

	"asi/internal/probe"
)

func TestPackVulhubProducts(t *testing.T) {
	cases := []struct {
		dir, name, version string
		admin              bool
		outdated           []string
	}{
		{"grafana-8.2", "Grafana", "8.2.6", true, []string{"outdated-grafana"}},
		{"phpmyadmin", "phpMyAdmin", "5.2.3", true, nil},
		{"phpmyadmin-4.8", "phpMyAdmin", "4.8.1", true, []string{"outdated-apache", "outdated-php", "outdated-phpmyadmin"}},
		{"activemq", "ActiveMQ", "", true, nil},
		{"activemq-console", "ActiveMQ", "", true, nil},
		{"jenkins", "Jenkins", "2.440.3", true, []string{"outdated-jenkins"}},
		{"jenkins-2.441", "Jenkins", "2.441", true, []string{"outdated-jenkins"}},
		{"tomcat", "Apache Tomcat", "9.0.85", false, nil},
		{"tomcat-8.0", "Apache Tomcat", "8.0.43", false, []string{"outdated-apache-tomcat"}},
		{"httpd-2.4.49", "Apache", "2.4.49", false, []string{"outdated-apache"}},
		{"elasticsearch-1.4", "Elasticsearch", "1.4.2", false, []string{"outdated-elasticsearch"}},
		{"drupal", "Drupal", "10", false, nil},
		{"drupal-8", "Drupal", "8.5.0", false, []string{"outdated-apache", "outdated-drupal", "outdated-php"}},
		{"joomla", "Joomla", "", false, nil},
		{"gitea", "Gitea", "28.4.0", false, nil},
	}
	for _, c := range cases {
		t.Run(c.dir, func(t *testing.T) {
			res := runPackFixture(t, c.dir)
			i := slices.IndexFunc(res.Technologies, func(tc Technology) bool { return tc.Name == c.name })
			if i < 0 {
				t.Fatalf("technologies = %+v, want %s", res.Technologies, c.name)
			}
			if got := res.Technologies[i].Version; got != c.version {
				t.Errorf("%s version = %q, want %q", c.name, got, c.version)
			}
			if got := findingKinds(res)["admin-panel"]; got != c.admin {
				t.Errorf("admin-panel finding = %v, want %v (findings %+v)", got, c.admin, res.Findings)
			}
			var ids []string
			for _, f := range Outdated(res.Technologies) {
				ids = append(ids, f.SignatureID)
			}
			slices.Sort(ids)
			if !slices.Equal(ids, c.outdated) {
				t.Errorf("outdated findings = %v, want %v", ids, c.outdated)
			}
		})
	}
}

func TestPackTomcatVersionIgnoresCoyote(t *testing.T) {
	res := runPackFixture(t, "tomcat-8.0")
	for _, tc := range res.Technologies {
		if tc.Version == "1.1" || tc.Name == "Apache" {
			t.Errorf("technology %+v comes from the Apache-Coyote/1.1 connector string", tc)
		}
	}
}

func TestDrupalVersionSpecificity(t *testing.T) {
	cases := []struct {
		name, header, body, want string
	}{
		{"major only", "Drupal 10 (https://www.drupal.org)", `<script type="application/json" data-drupal-selector="drupal-settings-json">{}</script>`, "10"},
		{"core asset version", "Drupal 8 (https://www.drupal.org)", `<script src="/core/misc/drupal.js?v=8.5.0"></script>`, "8.5.0"},
		{"vendor asset version is not Drupal", "Drupal 8 (https://www.drupal.org)", `<script src="/core/assets/vendor/jquery/jquery.min.js?v=3.2.1"></script>`, "8"},
		{"conflicting major keeps the header", "Drupal 9 (https://www.drupal.org)", `<script src="/core/misc/drupal.js?v=8.5.0"></script>`, "9"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			techs := Builtin(&probe.Response{StatusCode: 200, Headers: map[string]string{"x-generator": c.header}, Body: []byte(c.body)})
			i := slices.IndexFunc(techs, func(tc Technology) bool { return tc.Name == "Drupal" })
			if i < 0 {
				t.Fatalf("technologies = %+v, want Drupal", techs)
			}
			if techs[i].Version != c.want {
				t.Errorf("Drupal version = %q, want %q", techs[i].Version, c.want)
			}
		})
	}
}

func TestOutdatedVulhubVersions(t *testing.T) {
	cases := []struct {
		name, version string
		outdated      bool
	}{
		{"Apache Tomcat", "8.0.43", true},
		{"Apache Tomcat", "9.0.112", false},
		{"Apache Tomcat", "11.0.14", false},
		{"Jenkins", "2.441", true},
		{"Jenkins", "2.580.2", false},
		{"Jenkins", "2.590", false},
		{"Grafana", "8.2.6", true},
		{"Grafana", "12.3.0", false},
		{"Apache", "2.4.49", true},
		{"Apache", "2.4.71", false},
		{"Elasticsearch", "1.4.2", true},
		{"Elasticsearch", "9.4.3", false},
		{"Redis", "4.0.14", true},
		{"Redis", "8.2.1", false},
		{"ActiveMQ", "5.17.3", true},
		{"ActiveMQ", "5.19.1", false},
		{"ActiveMQ", "6.1.7", false},
		{"Joomla", "3.9.28", true},
		{"Joomla", "5.4.1", false},
		{"Drupal", "8.5.0", true},
		{"Drupal", "8", true},
		{"Drupal", "10", false},
		{"Drupal", "11.2.5", false},
		{"Gitea", "1.4.0", true},
		{"Gitea", "28.4.0", false},
	}
	for _, c := range cases {
		t.Run(c.name+" "+c.version, func(t *testing.T) {
			got := Outdated([]Technology{{Name: c.name, Version: c.version, Confidence: 90}})
			if (len(got) == 1) != c.outdated || len(got) > 1 {
				t.Errorf("Outdated = %+v, want outdated %v", got, c.outdated)
			}
		})
	}
}

func TestOutdatedTableCoversVulhubProducts(t *testing.T) {
	table, err := outdatedTable()
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]OutdatedEntry{}
	for _, e := range table {
		have[strings.ToLower(e.Name)] = e
	}
	for _, want := range []string{"Apache Tomcat", "Jenkins", "Grafana", "Apache", "Elasticsearch", "Redis", "ActiveMQ", "Joomla", "Drupal", "Gitea"} {
		if _, ok := have[strings.ToLower(want)]; !ok {
			t.Errorf("table lacks %s", want)
		}
	}
	for _, e := range table {
		if e.Minimum == "" || e.Checked == "" {
			t.Errorf("%s: minimum %q checked %q, want both", e.Name, e.Minimum, e.Checked)
		}
	}
	if _, err := ParseOutdated([]byte("- {name: X, minimum: '1.0', latest: '1.0'}")); err == nil {
		t.Error("entry without checked date accepted")
	}
	if _, err := ParseOutdated([]byte("- {name: X, minimum: '1.0', latest: '1.0', checked: soon}")); err == nil {
		t.Error("entry with a non-date checked accepted")
	}
}

func TestOutdatedNonHTTPServices(t *testing.T) {
	cases := []struct {
		service, product, version, wantName, wantID string
	}{
		{"redis", "Redis key-value store", "4.0.14", "Redis", "outdated-redis"},
		{"apachemq", "ActiveMQ OpenWire transport", "5.17.3", "ActiveMQ", "outdated-activemq"},
		{"apachemq", "ActiveMQ OpenWire transport", "6.1.7", "ActiveMQ", ""},
	}
	for _, c := range cases {
		techs := ServiceTechnologies(c.service, c.product, c.version)
		if len(techs) != 1 || techs[0].Name != c.wantName || techs[0].Version != c.version || techs[0].Category == "" {
			t.Fatalf("%s %s: technologies = %+v, want %s %s", c.service, c.product, techs, c.wantName, c.version)
		}
		var ids []string
		for _, f := range Outdated(techs) {
			ids = append(ids, f.SignatureID)
		}
		if want := []string{c.wantID}; c.wantID == "" && len(ids) != 0 || c.wantID != "" && !slices.Equal(ids, want) {
			t.Errorf("%s %s: outdated = %v, want %q", c.service, c.version, ids, c.wantID)
		}
	}
}
