package scan_test

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"asi/internal/inventory"
	"asi/internal/scan"
	"asi/internal/scan/nmap"
	"asi/internal/scan/nmap/nmaptest"
	"asi/internal/scan/scantest"
)

func scanRecordedXML(t *testing.T, file string) map[string]map[int]inventory.ServiceResult {
	t.Helper()
	f, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	recorded, err := nmap.Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	var addrs []string
	seen := map[int]bool{}
	var ports []int
	for _, h := range recorded {
		addrs = append(addrs, h.Address)
		for _, p := range h.Ports {
			if !seen[p.Number] {
				seen[p.Number] = true
				ports = append(ports, p.Number)
			}
		}
	}
	r := &nmaptest.Runner{DiscoverFunc: allUp, ServicesFunc: func(_ context.Context, in []string, _ []int, _ nmap.Options) ([]nmap.Host, error) {
		var out []nmap.Host
		for _, a := range in {
			for _, h := range recorded {
				if h.Address == a {
					out = append(out, h)
				}
			}
		}
		return out, nil
	}}
	tr := &scantest.Transport{Handler: http.NotFoundHandler()}
	st := &scantest.Store{}
	settings := inventory.RunSettings{Targets: addrs, Ports: ports, MaxRate: 1000, Workers: 1}
	sc := &scan.Scanner{Store: st, Runner: r, Transport: tr.For, Clock: scantest.NewClock(time.Unix(0, 0))}
	if err := sc.Run(context.Background(), testRun(settings)); err != nil {
		t.Fatal(err)
	}
	out := map[string]map[int]inventory.ServiceResult{}
	for _, h := range st.Hosts() {
		by := map[int]inventory.ServiceResult{}
		for _, s := range h.Services {
			by[s.Port] = s
		}
		out[h.Address] = by
	}
	return out
}

func TestRun3BannersFromNmapGiveProductAndVersion(t *testing.T) {
	svcs := scanRecordedXML(t, "testdata/run3/banners.xml")["192.0.2.30"]
	cases := []struct {
		port           int
		product        string
		versionPrefix  string
		technology     string
		technologyVers string
	}{
		{21, "vsftpd", "3.0.2", "vsftpd", "3.0.2"},
		{22, "openssh", "9.6p1", "OpenSSH", "9.6p1"},
		{25, "postfix", "", "", ""},
		{110, "dovecot", "", "", ""},
		{143, "dovecot", "", "", ""},
		{2121, "proftpd", "1.3.8", "", ""},
		{2122, "pure-ftpd", "", "", ""},
		{2525, "exim", "4.96", "", ""},
	}
	for _, c := range cases {
		s := svcs[c.port]
		if !strings.Contains(strings.ToLower(s.Product), c.product) || !strings.HasPrefix(s.Version, c.versionPrefix) {
			t.Errorf("port %d (%s) = product %q version %q, want product %s version %s from the banner", c.port, s.Service, s.Product, s.Version, c.product, c.versionPrefix)
		}
		if c.technology == "" {
			continue
		}
		found := false
		for _, tech := range s.Technologies {
			if tech.Name == c.technology && tech.Version == c.technologyVers {
				found = true
			}
		}
		if !found {
			t.Errorf("port %d technologies = %+v, want %s %s", c.port, s.Technologies, c.technology, c.technologyVers)
		}
	}
}

func TestRun3RabbitMQOnAMQPPort(t *testing.T) {
	hosts := scanRecordedXML(t, "testdata/run3/rabbitmq.xml")
	rabbit := hosts["192.0.2.40"][5672]
	found := false
	for _, tech := range rabbit.Technologies {
		if tech.Name == "RabbitMQ" && tech.Version == "3.13.7" {
			found = true
		}
	}
	if !found {
		t.Errorf("rabbitmq:3-management on 5672 = product %q technologies %+v, want technology RabbitMQ 3.13.7", rabbit.Product, rabbit.Technologies)
	}
	generic := hosts["192.0.2.41"][5672]
	if generic.Service != "amqp" || generic.Product != "" || len(generic.Technologies) != 0 {
		t.Errorf("unidentified AMQP = service %q product %q technologies %+v, want amqp without a product", generic.Service, generic.Product, generic.Technologies)
	}
}

func TestRun3VersionBoundIsNotATechnologyVersion(t *testing.T) {
	svcs := scanRecordedXML(t, "testdata/run3/bounds.xml")["192.0.2.50"]
	for _, c := range []struct {
		port       int
		technology string
		bound      string
	}{
		{5432, "PostgreSQL", "9.6.0 or later"},
		{21, "vsftpd", "2.0.8 or later"},
	} {
		s := svcs[c.port]
		if s.Version != c.bound {
			t.Errorf("port %d version = %q, want %q as nmap gave it", c.port, s.Version, c.bound)
		}
		var techs []inventory.Technology
		for _, tech := range s.Technologies {
			if tech.Name == c.technology {
				techs = append(techs, tech)
			}
		}
		if len(techs) != 1 || techs[0].Version != "" || techs[0].Confidence >= 80 {
			t.Errorf("port %d technologies = %+v, want one %s with an empty version and confidence below 80 (bound %q is not a version)", c.port, s.Technologies, c.technology, c.bound)
		}
		for _, f := range s.Findings {
			if f.Kind == "outdated" {
				t.Errorf("port %d flagged outdated from the bound %q: %+v", c.port, c.bound, f)
			}
		}
	}
}
