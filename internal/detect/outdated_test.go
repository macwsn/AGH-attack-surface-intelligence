package detect

import (
	"os"
	"strings"
	"testing"
)

func TestOutdated(t *testing.T) {
	cases := []struct {
		name, version, wantID string
	}{
		{"WordPress", "4.7", "outdated-wordpress"},
		{"PHP", "5.6.40", "outdated-php"},
		{"PHP", "5.4.45", "outdated-php"},
		{"PHP", "7.4.3", "outdated-php"},
		{"nginx", "1.10.3", "outdated-nginx"},
		{"Apache", "2.2.34", "outdated-apache"},
		{"OpenSSH", "7.4", "outdated-openssh"},
		{"OpenSSH", "7.4p1", "outdated-openssh"},
		{"openssh", "7.4", "outdated-openssh"},
		{"vsftpd", "2.3.4", "outdated-vsftpd"},
		{"vsftpd", "3.0.2", "outdated-vsftpd"},
		{"vsftpd", "3.0.3", ""},
		{"ProFTPD", "1.3.5e", "outdated-proftpd"},
		{"ProFTPD", "1.3.8b", ""},
		{"Pure-FTPd", "1.0.47", "outdated-pure-ftpd"},
		{"MySQL", "5.5.62", "outdated-mysql"},
		{"MySQL", "5.7.44", "outdated-mysql"},
		{"phpMyAdmin", "4.9.11", "outdated-phpmyadmin"},
		{"WordPress", "", ""},
		{"WordPress", "latest", ""},
		{"PHP", "x7.4", ""},
		{"Gitea", "1.22.0", ""},
	}
	for _, c := range cases {
		t.Run(c.name+" "+c.version, func(t *testing.T) {
			got := Outdated([]Technology{{Name: c.name, Category: "x", Version: c.version, Confidence: 77, Source: SourceBuiltin}})
			if c.wantID == "" {
				if len(got) != 0 {
					t.Fatalf("Outdated = %+v, want nothing", got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("Outdated = %+v, want one finding", got)
			}
			f := got[0]
			if f.SignatureID != c.wantID || f.Kind != KindOutdated || f.Version != c.version || f.Confidence != 77 {
				t.Fatalf("finding = %+v, want id %s kind outdated version %s confidence 77", f, c.wantID, c.version)
			}
			if !strings.Contains(strings.ToLower(f.Name), strings.ToLower(c.name)) {
				t.Errorf("name %q does not name %s", f.Name, c.name)
			}
			if !strings.Contains(f.Evidence, c.version) {
				t.Errorf("evidence %q lacks detected version %s", f.Evidence, c.version)
			}
		})
	}
}

// REQ-SCAN-032
func TestOutdatedFTPServers(t *testing.T) {
	cases := []struct{ product, version, wantID string }{
		{"vsftpd", "3.0.2", "outdated-vsftpd"},
		{"vsftpd", "3.0.5", ""},
		{"ProFTPD", "1.3.6", "outdated-proftpd"},
		{"ProFTPD", "1.3.7c", ""},
		{"Pure-FTPd", "1.0.49", "outdated-pure-ftpd"},
	}
	for _, c := range cases {
		got := Outdated(ServiceTechnologies("ftp", c.product, c.version))
		if c.wantID == "" && len(got) != 0 || c.wantID != "" && (len(got) != 1 || got[0].SignatureID != c.wantID) {
			t.Errorf("%s %s: Outdated = %+v, want %q", c.product, c.version, got, c.wantID)
		}
	}
}

func TestOutdatedTableBoundaries(t *testing.T) {
	table, err := outdatedTable()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range table {
		for _, v := range []string{e.Latest, e.Minimum, e.Minimum + ".0"} {
			if got := Outdated([]Technology{{Name: e.Name, Version: v, Confidence: 90}}); len(got) != 0 {
				t.Errorf("%s %s flagged: %+v", e.Name, v, got)
			}
		}
		got := Outdated([]Technology{{Name: e.Name, Version: "0.1", Confidence: 90}})
		if len(got) != 1 || !strings.Contains(got[0].Evidence, e.Minimum) {
			t.Errorf("%s 0.1 = %+v, want one finding whose evidence has the minimum %s", e.Name, got, e.Minimum)
		}
	}
}

func TestOutdatedTableFile(t *testing.T) {
	data, err := os.ReadFile("outdated.yaml")
	if err != nil {
		t.Fatal(err)
	}
	table, err := ParseOutdated(data)
	if err != nil {
		t.Fatalf("ParseOutdated: %v", err)
	}
	have := map[string]bool{}
	for _, e := range table {
		have[strings.ToLower(e.Name)] = true
	}
	for _, want := range []string{"wordpress", "php", "nginx", "apache", "openssh", "vsftpd", "mysql", "phpmyadmin"} {
		if !have[want] {
			t.Errorf("table lacks %s", want)
		}
	}
	for _, bad := range []string{
		"- {name: X, minimum: '2.0', latest: '1.0'}",
		"- {name: X, minimum: abc, latest: '1.0'}",
		"- {name: X, minimum: '1.0', latest: '1.0'}\n- {name: x, minimum: '1.0', latest: '1.0'}",
		"- {name: '', minimum: '1.0', latest: '1.0'}",
	} {
		if _, err := ParseOutdated([]byte(bad)); err == nil {
			t.Errorf("ParseOutdated(%q) = nil error", bad)
		}
	}
}
