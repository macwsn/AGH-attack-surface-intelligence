package scan_test

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"asi/internal/detect"
	"asi/internal/inventory"
	"asi/internal/scan"
	"asi/internal/scan/nmap"
	"asi/internal/scan/nmap/nmaptest"
	"asi/internal/scan/scantest"
)

func runRecordedNonHTTP(t *testing.T) (map[int]inventory.ServiceResult, *scantest.Transport) {
	t.Helper()
	f, err := os.Open(filepath.Join("nmap", "testdata", "nonhttp.xml"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	recorded, err := nmap.Parse(f)
	if err != nil {
		t.Fatalf("parse recorded nmap output: %v", err)
	}
	tr := &scantest.Transport{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "nginx/1.24.0")
		w.Header().Set("X-Powered-By", "PHP/5.6.40")
		fmt.Fprint(w, "<title>ok</title>")
	})}
	r := &nmaptest.Runner{DiscoverFunc: allUp, ServicesFunc: func(context.Context, []string, []int, nmap.Options) ([]nmap.Host, error) {
		return recorded, nil
	}}
	settings := inventory.RunSettings{Targets: []string{"192.0.2.20"}, Ports: []int{21, 22, 80, 3306, 5432, 5672, 6379}, MaxRate: 100, Workers: 1}
	st := &scantest.Store{}
	if err := (&scan.Scanner{Store: st, Runner: r, Transport: tr.For}).Run(context.Background(), testRun(settings)); err != nil {
		t.Fatalf("Run: %v", err)
	}
	hosts := st.Hosts()
	if len(hosts) != 1 {
		t.Fatalf("hosts = %+v, want one", hosts)
	}
	byPort := map[int]inventory.ServiceResult{}
	for _, s := range hosts[0].Services {
		byPort[s.Port] = s
	}
	return byPort, tr
}

// REQ-SCAN-013
func TestRunNonHTTPServiceTechnologies(t *testing.T) {
	byPort, tr := runRecordedNonHTTP(t)
	want := map[int]inventory.Technology{
		21:   {Name: "vsftpd", Category: "ftp-server", Version: "2.3.4"},
		22:   {Name: "OpenSSH", Category: "ssh-server", Version: "7.4"},
		3306: {Name: "MySQL", Category: "database", Version: "5.7.44"},
		5432: {Name: "PostgreSQL", Category: "database"},
		5672: {Name: "RabbitMQ", Category: "message-broker", Version: "3.13.7"},
		6379: {Name: "Redis", Category: "database"},
	}
	for port, w := range want {
		s := byPort[port]
		if s.HTTP != nil {
			t.Errorf("port %d: probed over HTTP", port)
		}
		if len(s.Technologies) != 1 {
			t.Errorf("port %d: technologies = %+v, want only %s", port, s.Technologies, w.Name)
			continue
		}
		got := s.Technologies[0]
		if got.Name != w.Name || got.Category != w.Category || got.Version != w.Version || got.Source != detect.SourceBuiltin || got.Confidence == 0 {
			t.Errorf("port %d: technology = %+v, want %+v with source builtin", port, got, w)
		}
	}

	web := byPort[80]
	if web.HTTP == nil {
		t.Fatal("port 80: no HTTP detection")
	}
	var names []string
	for _, tc := range web.Technologies {
		names = append(names, tc.Name)
		if tc.Source != detect.SourceBuiltin {
			t.Errorf("port 80: technology %+v, want HTTP built-in detection", tc)
		}
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"PHP", "nginx"}) {
		t.Errorf("port 80: technologies = %v, want nginx and PHP once each", names)
	}
	for _, req := range tr.Requests() {
		if req.Target != "192.0.2.20:80" {
			t.Errorf("HTTP request to non-HTTP service %s", req.Target)
		}
	}
}

// REQ-SCAN-014
func TestRunOutdatedFindings(t *testing.T) {
	byPort, _ := runRecordedNonHTTP(t)
	want := map[int][]string{
		21:   {"outdated-vsftpd"},
		22:   {"outdated-openssh"},
		80:   {"outdated-php"},
		3306: {"outdated-mysql"},
		5432: nil,
		5672: nil,
		6379: nil,
	}
	for port, ids := range want {
		var got []string
		for _, f := range byPort[port].Findings {
			if f.Kind != detect.KindOutdated {
				continue
			}
			got = append(got, f.SignatureID)
			if f.Version == "" || f.Evidence == "" || f.Confidence == 0 {
				t.Errorf("port %d: finding %+v lacks version, evidence or confidence", port, f)
			}
		}
		if !reflect.DeepEqual(got, ids) {
			t.Errorf("port %d: outdated findings = %v, want %v", port, got, ids)
		}
	}
}

// AC1 of T-803xbjbxg8: a scanned service whose nmap product is nginx 1.14.0 or Apache httpd 2.2.15 gets the same
// technologies and findings as the same service entered by form or imported (exchange detection parity test).
func TestRunWebServerProductParity(t *testing.T) {
	tr := &scantest.Transport{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "<title>ok</title>")
	})}
	r := &nmaptest.Runner{DiscoverFunc: allUp, ServicesFunc: func(_ context.Context, addrs []string, _ []int, _ nmap.Options) ([]nmap.Host, error) {
		return []nmap.Host{{Address: addrs[0], Ports: []nmap.Port{
			{Number: 80, Protocol: "tcp", State: "open", Service: "http", Product: "nginx", Version: "1.14.0"},
			{Number: 8080, Protocol: "tcp", State: "open", Service: "http", Product: "Apache httpd", Version: "2.2.15"},
		}}}, nil
	}}
	settings := inventory.RunSettings{Targets: []string{"192.0.2.21"}, Ports: []int{80, 8080}, MaxRate: 100, Workers: 1}
	st := &scantest.Store{}
	if err := (&scan.Scanner{Store: st, Runner: r, Transport: tr.For}).Run(context.Background(), testRun(settings)); err != nil {
		t.Fatalf("Run: %v", err)
	}
	hosts := st.Hosts()
	if len(hosts) != 1 {
		t.Fatalf("hosts = %+v, want one", hosts)
	}
	want := map[int][2][]string{
		80:   {{"nginx 1.14.0"}, {"outdated-nginx"}},
		8080: {{"Apache 2.2.15"}, {"outdated-apache"}},
	}
	for _, s := range hosts[0].Services {
		var techs, findings []string
		for _, tc := range s.Technologies {
			techs = append(techs, tc.Name+" "+tc.Version)
		}
		for _, f := range s.Findings {
			findings = append(findings, f.SignatureID)
		}
		slices.Sort(techs)
		slices.Sort(findings)
		if w := want[s.Port]; !reflect.DeepEqual(techs, w[0]) || !reflect.DeepEqual(findings, w[1]) {
			t.Errorf("%d/tcp: technologies %q findings %q, want technologies %q findings %q", s.Port, techs, findings, w[0], w[1])
		}
	}
}
