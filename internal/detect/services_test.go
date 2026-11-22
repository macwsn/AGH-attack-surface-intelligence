package detect

import (
	"reflect"
	"testing"
)

func TestServiceTechnologies(t *testing.T) {
	tech := func(name, category, version string) []Technology {
		return []Technology{{Name: name, Category: category, Version: version, Confidence: serviceConfidence, Source: SourceBuiltin}}
	}
	bound := func(name, category string) []Technology {
		return []Technology{{Name: name, Category: category, Confidence: boundConfidence, Source: SourceBuiltin}}
	}
	cases := []struct {
		service, product, version string
		want                      []Technology
	}{
		{"ftp", "vsftpd", "2.3.4", tech("vsftpd", "ftp-server", "2.3.4")},
		{"ftp", "vsftpd", "", tech("vsftpd", "ftp-server", "")},
		{"ftp", "ProFTPD", "1.3.5e", tech("ProFTPD", "ftp-server", "1.3.5e")},
		{"ftp", "Pure-FTPd", "", tech("Pure-FTPd", "ftp-server", "")},
		{"ssh", "OpenSSH", "8.9p1 Ubuntu 3ubuntu0.10", tech("OpenSSH", "ssh-server", "8.9p1")},
		{"redis", "Redis key-value store", "7.2.4", tech("Redis", "database", "7.2.4")},
		{"redis", "", "", tech("Redis", "database", "")},
		{"postgresql", "PostgreSQL DB", "16.4", tech("PostgreSQL", "database", "16.4")},
		{"postgresql", "", "", tech("PostgreSQL", "database", "")},
		{"mysql", "MySQL", "5.7.44", tech("MySQL", "database", "5.7.44")},
		{"mysql", "MariaDB", "10.11.6", tech("MariaDB", "database", "10.11.6")},
		{"mysql", "MySQL", "5.5.5-10.11.6-MariaDB-0+deb12u1", tech("MariaDB", "database", "10.11.6")},
		{"mysql", "MariaDB", "", tech("MariaDB", "database", "")},
		{"amqp", "RabbitMQ", "3.13.7", tech("RabbitMQ", "message-broker", "3.13.7")},
		{"telnet", "", "", nil},
		{"ssh", "", "", nil},
		{"ssh", "Dropbear sshd", "2022.83", nil},
		{"mysql", "", "", nil},
		{"http", "nginx", "1.24.0", nil},
		{"postgresql", "PostgreSQL DB", "9.6.0 - 9.6.24", tech("PostgreSQL", "database", "")},
		{"mysql", "MySQL", "unauthorized", tech("MySQL", "database", "")},
		{"postgresql", "PostgreSQL DB", "9.6.0 or later", bound("PostgreSQL", "database")},
		{"ftp", "vsftpd", "2.0.8 or later", bound("vsftpd", "ftp-server")},
		{"ssh", "OpenSSH", "8.x", bound("OpenSSH", "ssh-server")},
		{"ssh", "OpenSSH", "2.4.x - 2.4.y", bound("OpenSSH", "ssh-server")},
		{"mysql", "MariaDB", "10.x", bound("MariaDB", "database")},
	}
	for _, c := range cases {
		got := ServiceTechnologies(c.service, c.product, c.version)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("ServiceTechnologies(%q, %q, %q) = %+v, want %+v", c.service, c.product, c.version, got, c.want)
		}
	}
}

func TestDetectServiceWebServerProducts(t *testing.T) {
	cases := []struct {
		product, version string
		techs, findings  []string
	}{
		{"nginx", "1.14.0", []string{"nginx 1.14.0"}, []string{"outdated-nginx"}},
		{"Apache httpd", "2.2.15", []string{"Apache 2.2.15"}, []string{"outdated-apache"}},
		{"Apache Tomcat/Coyote JSP engine", "1.1", []string{"Apache Tomcat "}, nil},
		{"nginx", "1.27.5", []string{"nginx 1.27.5"}, nil},
		{"lighttpd", "1.4.0", nil, nil},
	}
	for _, c := range cases {
		res := (&Set{}).DetectService(Service{Service: "http", Product: c.product, Version: c.version})
		var techs, findings []string
		for _, tc := range res.Technologies {
			techs = append(techs, tc.Name+" "+tc.Version)
		}
		for _, f := range res.Findings {
			findings = append(findings, f.SignatureID)
		}
		if !reflect.DeepEqual(techs, c.techs) || !reflect.DeepEqual(findings, c.findings) {
			t.Errorf("DetectService(http %q %q) = technologies %q findings %q, want %q %q", c.product, c.version, techs, findings, c.techs, c.findings)
		}
	}
}
