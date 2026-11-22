package scan_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asi/internal/inventory"
	"asi/internal/probe"
	"asi/internal/scan"
	"asi/internal/scan/nmap"
	"asi/internal/scan/nmap/nmaptest"
	"asi/internal/scan/scantest"
)

func TestNeverProbePortsFromLabAGH(t *testing.T) {
	ports := []int{515, 789, 1911, 1962, 2222, 4911, 5007, 9101, 9102, 9103, 9600, 18245, 18246, 20547, 34962, 34963, 34964}
	var open []nmap.Port
	for _, p := range ports {
		open = append(open, nmap.Port{Number: p, Protocol: "tcp", State: "open", Service: "unknown"})
	}
	r := &nmaptest.Runner{DiscoverFunc: allUp, ServicesFunc: func(_ context.Context, addrs []string, _ []int, _ nmap.Options) ([]nmap.Host, error) {
		return []nmap.Host{{Address: addrs[0], Up: true, Ports: open}}, nil
	}}
	tr := &scantest.Transport{}
	st := &scantest.Store{}
	settings := inventory.RunSettings{Targets: []string{"10.8.0.1"}, Ports: ports, MaxRate: 1000, Workers: 1}
	sc := &scan.Scanner{Store: st, Runner: r, Transport: tr.For, Clock: scantest.NewClock(time.Unix(0, 0))}
	if err := sc.Run(context.Background(), testRun(settings)); err != nil {
		t.Fatal(err)
	}
	probed := map[int]bool{}
	for _, q := range tr.Requests() {
		_, p, _ := net.SplitHostPort(q.Target)
		n, _ := strconv.Atoi(p)
		probed[n] = true
	}
	for _, p := range ports {
		if probed[p] {
			t.Errorf("never-probe port %d was probed over HTTP", p)
		}
	}
	for i, c := range r.Calls() {
		if c.Method == "Services" && i > 1 {
			t.Errorf("never-probe ports got a second service detection: %+v", c.Ports)
		}
	}
}

func TestSecondServicePassForUnidentifiedPorts(t *testing.T) {
	light := []nmap.Port{
		{Number: 21, Protocol: "tcp", State: "open", Service: "ftp"},
		{Number: 22, Protocol: "tcp", State: "open", Service: "ssh", Product: "OpenSSH", Version: "9.6"},
		{Number: 502, Protocol: "tcp", State: "open", Service: ""},
		{Number: 1883, Protocol: "tcp", State: "open", Service: "mqtt", Guessed: true},
		{Number: 3306, Protocol: "tcp", State: "open", Service: "mysql", Guessed: true},
		{Number: 5000, Protocol: "tcp", State: "open", Service: "tcpwrapped"},
		{Number: 6000, Protocol: "tcp", State: "open", Service: "unknown"},
		{Number: 15432, Protocol: "tcp", State: "open", Service: ""},
	}
	standard := map[int]nmap.Port{
		21:    {Number: 21, Protocol: "tcp", State: "open", Service: "ftp", Product: "vsftpd", Version: "2.3.4"},
		3306:  {Number: 3306, Protocol: "tcp", State: "open", Service: "mysql", Product: "MySQL", Version: "8.0.36"},
		5000:  {Number: 5000, Protocol: "tcp", State: "open", Service: "tcpwrapped"},
		6000:  {Number: 6000, Protocol: "tcp", State: "open", Service: "unknown"},
		15432: {Number: 15432, Protocol: "tcp", State: "open", Service: "postgresql", Product: "PostgreSQL DB", Version: "16.2"},
	}
	var calls atomic.Int32
	r := &nmaptest.Runner{DiscoverFunc: allUp, ServicesFunc: func(_ context.Context, addrs []string, ports []int, _ nmap.Options) ([]nmap.Host, error) {
		if calls.Add(1) == 1 {
			return []nmap.Host{{Address: addrs[0], Up: true, Ports: light}}, nil
		}
		var out []nmap.Port
		for _, p := range ports {
			if sp, ok := standard[p]; ok {
				out = append(out, sp)
			}
		}
		return []nmap.Host{{Address: addrs[0], Up: true, Ports: out}}, nil
	}}
	var ports []int
	for _, p := range light {
		ports = append(ports, p.Number)
	}
	tr := &scantest.Transport{Handler: http.NotFoundHandler()}
	st := &scantest.Store{}
	settings := inventory.RunSettings{Targets: []string{"10.8.0.1"}, Ports: ports, MaxRate: 1000, Workers: 1}
	sc := &scan.Scanner{Store: st, Runner: r, Transport: tr.For, Clock: scantest.NewClock(time.Unix(0, 0))}
	if err := sc.Run(context.Background(), testRun(settings)); err != nil {
		t.Fatal(err)
	}
	var services []nmaptest.Call
	for _, c := range r.Calls() {
		if c.Method == "Services" {
			services = append(services, c)
		}
	}
	if len(services) != 2 {
		t.Fatalf("service detections = %d (%+v), want the light pass and one second pass", len(services), services)
	}
	second := slices.Clone(services[1].Ports)
	slices.Sort(second)
	if want := []int{21, 3306, 5000, 6000, 15432}; !slices.Equal(second, want) {
		t.Errorf("second pass ports = %v, want %v", second, want)
	}
	hosts := st.Hosts()
	if len(hosts) != 1 {
		t.Fatalf("hosts = %+v", hosts)
	}
	by := map[int]inventory.ServiceResult{}
	for _, s := range hosts[0].Services {
		by[s.Port] = s
	}
	if pg := by[15432]; pg.Service != "postgresql" || pg.Version != "16.2" {
		t.Errorf("15432 = service %q version %q, want postgresql 16.2 from the second pass", pg.Service, pg.Version)
	}
	if my := by[3306]; my.Service != "mysql" || my.Product != "MySQL" {
		t.Errorf("3306 = service %q product %q, want mysql MySQL from the second pass", my.Service, my.Product)
	}
}

func tlsConfig(t *testing.T) *tls.Config {
	t.Helper()
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	cfg := srv.TLS.Clone()
	srv.Close()
	return cfg
}

func serveHTTP(c net.Conn, title string) {
	if _, err := http.ReadRequest(bufio.NewReader(c)); err != nil {
		return
	}
	body := "<title>" + title + "</title>"
	fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
}

func scanOne(t *testing.T, ports []nmap.Port) map[int]inventory.ServiceResult {
	t.Helper()
	r := &nmaptest.Runner{DiscoverFunc: allUp, ServicesFunc: func(_ context.Context, addrs []string, want []int, _ nmap.Options) ([]nmap.Host, error) {
		var out []nmap.Port
		for _, p := range ports {
			if slices.Contains(want, p.Number) {
				out = append(out, p)
			}
		}
		return []nmap.Host{{Address: addrs[0], Up: true, Ports: out}}, nil
	}}
	var numbers []int
	for _, p := range ports {
		numbers = append(numbers, p.Number)
	}
	st := &scantest.Store{}
	settings := inventory.RunSettings{Targets: []string{"127.0.0.1"}, Ports: numbers, MaxRate: 1000, Workers: 1}
	sc := &scan.Scanner{
		Store: st, Runner: r, Clock: scantest.NewClock(time.Unix(0, 0)),
		Transport: func(target string) http.RoundTripper { return probe.NewTransport(target, 5*time.Second) },
	}
	if err := sc.Run(context.Background(), testRun(settings)); err != nil {
		t.Fatal(err)
	}
	hosts := st.Hosts()
	if len(hosts) != 1 {
		t.Fatalf("hosts = %+v", hosts)
	}
	by := map[int]inventory.ServiceResult{}
	for _, s := range hosts[0].Services {
		by[s.Port] = s
	}
	return by
}

func TestHTTPNamedPortPrefersPlainHTTPAndFallsBackToTLS(t *testing.T) {
	cfg := tlsConfig(t)
	bothPort, _ := listenRaw(t, func(c net.Conn) {
		br := bufio.NewReader(c)
		first, err := br.Peek(1)
		if err != nil {
			return
		}
		if first[0] == 0x16 {
			serveHTTP(tls.Server(peekConn{c, br}, cfg), "default certificate")
			return
		}
		serveHTTP(peekConn{c, br}, "plain answer")
	})
	tlsOnlyPort, _ := listenRaw(t, func(c net.Conn) {
		serveHTTP(tls.Server(c, cfg), "tls only")
	})
	for run := 1; run <= 2; run++ {
		by := scanOne(t, []nmap.Port{
			{Number: bothPort, Protocol: "tcp", State: "open", Service: "http"},
			{Number: tlsOnlyPort, Protocol: "tcp", State: "open", Service: "http"},
		})
		if b := by[bothPort]; b.Service != "http" || b.HTTP == nil || b.HTTP.Scheme != "http" || b.HTTP.Title != "plain answer" {
			t.Errorf("run %d: port speaking both = service %q http %+v, want the plain-HTTP answer", run, b.Service, b.HTTP)
		}
		s := by[tlsOnlyPort]
		if s.HTTP == nil || s.HTTP.Scheme != "https" || s.HTTP.Title != "tls only" {
			t.Errorf("run %d: http-named TLS-only port = service %q http %+v, want an HTTPS fallback after plain HTTP fails", run, s.Service, s.HTTP)
		}
	}
}

func TestFailedTLSHandshakeExportedAsHTTPWithError(t *testing.T) {
	alertPort, _ := listenRaw(t, func(c net.Conn) {
		b := make([]byte, 512)
		c.Read(b)
		c.Write([]byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28})
	})
	closePort, _ := listenRaw(t, func(c net.Conn) {
		b := make([]byte, 512)
		c.Read(b)
	})
	by := scanOne(t, []nmap.Port{
		{Number: alertPort, Protocol: "tcp", State: "open", Service: "https"},
		{Number: closePort, Protocol: "tcp", State: "open", Service: "http", Tunnel: "ssl"},
	})
	for _, p := range []int{alertPort, closePort} {
		s := by[p]
		if s.Service != "http" || s.HTTP == nil || s.HTTP.Scheme != "https" || s.HTTP.Error == "" {
			t.Errorf("port %d with a failed TLS handshake = service %q http %+v, want service http, http.scheme https and http.error", p, s.Service, s.HTTP)
		}
	}
}

// REQ-SCAN-033
func TestNeverProbePortsExcludedFromServiceDetection(t *testing.T) {
	policy := []int{502, 1883, 8883, 9100}
	r := &nmaptest.Runner{DiscoverFunc: allUp, ServicesFunc: func(_ context.Context, addrs []string, ports []int, opts nmap.Options) ([]nmap.Host, error) {
		table := map[int]string{502: "mbap", 1883: "mqtt", 8883: "secure-mqtt", 9100: "jetdirect"}
		var out []nmap.Port
		for _, p := range ports {
			if slices.Contains(opts.NoVersion, p) {
				out = append(out, nmap.Port{Number: p, Protocol: "tcp", State: "open", Service: table[p], Guessed: true})
				continue
			}
			out = append(out, nmap.Port{Number: p, Protocol: "tcp", State: "open", Service: "http"})
		}
		return []nmap.Host{{Address: addrs[0], Up: true, Ports: out}}, nil
	}}
	tr := &scantest.Transport{Handler: http.NotFoundHandler()}
	st := &scantest.Store{}
	for _, mode := range []string{scan.ServiceDetectionLight, scan.ServiceDetectionStandard} {
		settings := inventory.RunSettings{Targets: []string{"10.8.0.1"}, Ports: append([]int{80}, policy...), MaxRate: 1000, Workers: 1, ServiceDetection: mode}
		sc := &scan.Scanner{Store: st, Runner: r, Transport: tr.For, Clock: scantest.NewClock(time.Unix(0, 0))}
		if err := sc.Run(context.Background(), testRun(settings)); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range r.Calls() {
		if c.Method != "Services" {
			continue
		}
		for _, p := range c.Ports {
			if slices.Contains(policy, p) && !slices.Contains(c.Opts.NoVersion, p) {
				t.Errorf("never-probe port %d in a -sV call: %+v", p, c)
			}
		}
	}
	for _, q := range tr.Requests() {
		if _, p, _ := net.SplitHostPort(q.Target); p != "80" {
			t.Errorf("HTTP request to %s", q.Target)
		}
	}
	for _, h := range st.Hosts() {
		for _, s := range h.Services {
			flagged := slices.ContainsFunc(s.Findings, func(f inventory.Finding) bool { return f.SignatureID == scan.NotProbedID })
			if want := slices.Contains(policy, s.Port); flagged != want {
				t.Errorf("port %d: not-probed-by-policy finding = %v, want %v (%+v)", s.Port, flagged, want, s.Findings)
			}
			if s.Port == 1883 && (s.State != "open" || s.Service != "mqtt") {
				t.Errorf("1883 = %+v, want open mqtt from the port table", s)
			}
		}
	}
}

func TestServiceProductFromBannerExtraInfoAndScripts(t *testing.T) {
	ports := []nmap.Port{
		{Number: 21, Protocol: "tcp", State: "open", Service: "ftp", Banner: "220 (vsFTPd 3.0.2)\r\n"},
		{Number: 22, Protocol: "tcp", State: "open", Service: "ssh", Product: "Dropbear sshd", Version: "2022.83", Banner: "SSH-2.0-OpenSSH_9.6p1"},
		{Number: 25, Protocol: "tcp", State: "open", Service: "smtp", Banner: "220 mail.example.org ESMTP ready\r\n"},
		{Number: 5671, Protocol: "tcp", State: "open", Service: "amqp", Product: "Advanced Message Queue Protocol", ExtraInfo: "RabbitMQ 3.12.1"},
		{Number: 5672, Protocol: "tcp", State: "open", Service: "amqp", Product: "Advanced Message Queue Protocol", ScriptProduct: "RabbitMQ", ScriptVersion: "3.13.7"},
		{Number: 5673, Protocol: "tcp", State: "open", Service: "amqp", Product: "Advanced Message Queue Protocol"},
	}
	r := &nmaptest.Runner{DiscoverFunc: allUp, ServicesFunc: func(_ context.Context, addrs []string, _ []int, _ nmap.Options) ([]nmap.Host, error) {
		return []nmap.Host{{Address: addrs[0], Up: true, Ports: ports}}, nil
	}}
	var list []int
	for _, p := range ports {
		list = append(list, p.Number)
	}
	st := &scantest.Store{}
	settings := inventory.RunSettings{Targets: []string{"10.8.0.1"}, Ports: list, MaxRate: 1000, Workers: 1, ServiceDetection: "light"}
	sc := &scan.Scanner{Store: st, Runner: r, Transport: (&scantest.Transport{}).For, Clock: scantest.NewClock(time.Unix(0, 0))}
	if err := sc.Run(context.Background(), testRun(settings)); err != nil {
		t.Fatal(err)
	}
	type got struct {
		product, version string
		techs            []inventory.Technology
	}
	want := map[int]got{
		21:   {"vsftpd", "3.0.2", []inventory.Technology{{Name: "vsftpd", Category: "ftp-server", Version: "3.0.2", Confidence: 80, Source: "builtin"}}},
		22:   {"Dropbear sshd", "2022.83", nil},
		25:   {"", "", nil},
		5671: {"RabbitMQ", "3.12.1", []inventory.Technology{{Name: "RabbitMQ", Category: "message-broker", Version: "3.12.1", Confidence: 80, Source: "builtin"}}},
		5672: {"RabbitMQ", "3.13.7", []inventory.Technology{{Name: "RabbitMQ", Category: "message-broker", Version: "3.13.7", Confidence: 80, Source: "builtin"}}},
		5673: {"", "", nil},
	}
	for _, s := range st.Hosts()[0].Services {
		w := want[s.Port]
		if s.Product != w.product || s.Version != w.version || len(s.Technologies) != len(w.techs) || len(w.techs) > 0 && !slices.Equal(s.Technologies, w.techs) {
			t.Errorf("port %d = product %q version %q technologies %+v, want %q %q %+v", s.Port, s.Product, s.Version, s.Technologies, w.product, w.version, w.techs)
		}
	}
}

// REQ-SCAN-022
func TestSoftMatchGetsStockLightPass(t *testing.T) {
	for _, mode := range []string{scan.ServiceDetectionLight, scan.ServiceDetectionStandard} {
		t.Run(mode, func(t *testing.T) {
			r := &nmaptest.Runner{DiscoverFunc: allUp, ServicesFunc: func(_ context.Context, addrs []string, ports []int, opts nmap.Options) ([]nmap.Host, error) {
				var out []nmap.Port
				for _, p := range ports {
					switch {
					case p == 22:
						out = append(out, nmap.Port{Number: 22, Protocol: "tcp", State: "open", Service: "ssh", Product: "OpenSSH", Version: "9.6"})
					case p == 8086 && (opts.StockProbes || opts.Standard):
						out = append(out, nmap.Port{Number: 8086, Protocol: "tcp", State: "open", Service: "http", Product: "InfluxDB http admin", Version: "1.6.6"})
					case p == 8086:
						out = append(out, nmap.Port{Number: 8086, Protocol: "tcp", State: "open", Service: "http", Product: "Golang net/http server", Soft: true})
					}
				}
				return []nmap.Host{{Address: addrs[0], Up: true, Ports: out}}, nil
			}}
			st := &scantest.Store{}
			tr := &scantest.Transport{Handler: http.NotFoundHandler()}
			settings := inventory.RunSettings{Targets: []string{"10.8.0.1"}, Ports: []int{22, 8086}, MaxRate: 1000, Workers: 1, ServiceDetection: mode}
			sc := &scan.Scanner{Store: st, Runner: r, Transport: tr.For, Clock: scantest.NewClock(time.Unix(0, 0))}
			if err := sc.Run(context.Background(), testRun(settings)); err != nil {
				t.Fatal(err)
			}
			var second []nmaptest.Call
			for _, c := range r.Calls() {
				if c.Method == "Services" && (c.Opts.StockProbes || c.Opts.Standard) {
					second = append(second, c)
				}
			}
			stock := mode == scan.ServiceDetectionLight
			if len(second) != 1 || !slices.Equal(second[0].Ports, []int{8086}) || second[0].Opts.StockProbes != stock || second[0].Opts.Standard == stock || second[0].Opts.VersionDB != "" {
				t.Fatalf("second passes = %+v, want one on 8086 with nmap's own probes (stock light in light mode, default intensity in standard mode)", second)
			}
			for _, s := range st.Hosts()[0].Services {
				if s.Port == 8086 && (s.Product != "InfluxDB http admin" || s.Version != "1.6.6") {
					t.Errorf("8086 = %q %q, want InfluxDB http admin 1.6.6", s.Product, s.Version)
				}
			}
		})
	}
}

// REQ-SCAN-022: the recorded light-pass XML soft-matches Golang net/http server, stock nmap light names InfluxDB 1.6.6.
func TestInfluxDBFromRecordedNmapXML(t *testing.T) {
	asi, err := filepath.Abs("nmap/testdata/influxdb-light-asi.xml")
	if err != nil {
		t.Fatal(err)
	}
	stock, err := filepath.Abs("nmap/testdata/influxdb-light-stock.xml")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	share := filepath.Join(root, "share")
	if err := os.MkdirAll(share, 0o755); err != nil {
		t.Fatal(err)
	}
	probes := "Probe TCP NULL q||\nsoftmatch http m|^HTTP/1\\.1 400 Bad Request\\r\\n| p|Golang net/http server| cpe:/a:golang:go/\n"
	if err := os.WriteFile(filepath.Join(share, "nmap-service-probes"), []byte(probes), 0o644); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\ncase \" $* \" in\n*' -sn '*) cat <<EOF\n<?xml version=\"1.0\"?><nmaprun><host><status state=\"up\"/><address addr=\"192.0.2.30\" addrtype=\"ipv4\"/></host><runstats><hosts up=\"1\" down=\"0\" total=\"1\"/></runstats></nmaprun>\nEOF\n;;\n" +
		"*' --versiondb '*) cat '" + asi + "' ;;\n*) cat '" + stock + "' ;;\nesac\n"
	bin := filepath.Join(root, "nmap")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NMAPDIR", share)
	for _, mode := range []string{scan.ServiceDetectionLight, scan.ServiceDetectionStandard} {
		st := &scantest.Store{}
		tr := &scantest.Transport{Handler: http.NotFoundHandler()}
		settings := inventory.RunSettings{Targets: []string{"192.0.2.30"}, Ports: []int{8086}, MaxRate: 1000, Workers: 1, ServiceDetection: mode}
		sc := &scan.Scanner{Store: st, Runner: nmap.ExecRunner{Path: bin}, Transport: tr.For, Clock: scantest.NewClock(time.Unix(0, 0))}
		if err := sc.Run(context.Background(), testRun(settings)); err != nil {
			t.Fatal(err)
		}
		hosts := st.Hosts()
		if len(hosts) != 1 || len(hosts[0].Services) != 1 {
			t.Fatalf("%s: hosts = %+v", mode, hosts)
		}
		if s := hosts[0].Services[0]; s.Product != "InfluxDB http admin" || s.Version != "1.6.6" {
			t.Errorf("%s: 8086 = %q %q, want InfluxDB http admin 1.6.6 as stock nmap -sV --version-light reports", mode, s.Product, s.Version)
		}
	}
}

func TestRecordedLightPassEscalatesBannerServicesAndGenericAMQP(t *testing.T) {
	parse := func(files ...string) map[string]nmap.Host {
		out := map[string]nmap.Host{}
		for _, file := range files {
			f, err := os.Open(file)
			if err != nil {
				t.Fatal(err)
			}
			hosts, err := nmap.Parse(f)
			f.Close()
			if err != nil {
				t.Fatal(err)
			}
			for _, h := range hosts {
				out[h.Address] = h
			}
		}
		return out
	}
	light := parse("testdata/run3/real/banners-light.xml", "testdata/run3/real/light.xml")
	standard := parse("testdata/run3/real/banners-standard.xml", "testdata/run3/real/standard.xml")
	second := map[string][]int{}
	var mu sync.Mutex
	r := &nmaptest.Runner{DiscoverFunc: allUp, ServicesFunc: func(_ context.Context, addrs []string, ports []int, opts nmap.Options) ([]nmap.Host, error) {
		src := light
		if opts.Standard {
			src = standard
		}
		var out []nmap.Host
		for _, a := range addrs {
			h := nmap.Host{Address: a, Up: true}
			for _, p := range src[a].Ports {
				if slices.Contains(ports, p.Number) {
					h.Ports = append(h.Ports, p)
				}
			}
			if opts.Standard {
				mu.Lock()
				second[a] = slices.Sorted(slices.Values(ports))
				mu.Unlock()
			}
			out = append(out, h)
		}
		return out, nil
	}}
	var addrs []string
	for a := range light {
		addrs = append(addrs, a)
	}
	slices.Sort(addrs)
	settings := inventory.RunSettings{Targets: addrs, Ports: []int{21, 22, 25, 110, 143, 5432, 5672}, MaxRate: 1000, Workers: 1}
	st := &scantest.Store{}
	sc := &scan.Scanner{Store: st, Runner: r, Transport: (&scantest.Transport{Handler: http.NotFoundHandler()}).For, Clock: scantest.NewClock(time.Unix(0, 0))}
	if err := sc.Run(context.Background(), testRun(settings)); err != nil {
		t.Fatal(err)
	}
	got := map[string]inventory.ServiceResult{}
	for _, h := range st.Hosts() {
		for _, s := range h.Services {
			got[net.JoinHostPort(h.Address, strconv.Itoa(s.Port))] = s
		}
	}
	for _, c := range []struct{ addr, product, version, tech string }{
		{"172.23.0.11:110", "Dovecot pop3d", "", ""},
		{"172.23.0.12:143", "Dovecot imapd", "", ""},
		{"172.23.0.3:5672", "RabbitMQ", "3.13.7", "RabbitMQ"},
		{"172.23.0.5:21", "vsftpd", "3.0.2", "vsftpd"},
		{"172.23.0.6:21", "vsftpd", "3.0.5", "vsftpd"},
		{"172.23.0.7:21", "ProFTPD", "1.3.8", ""},
		{"172.23.0.8:21", "Pure-FTPd", "", ""},
		{"172.23.0.9:25", "Postfix smtpd", "", ""},
		{"172.23.0.10:25", "Exim smtpd", "4.96", ""},
		{"172.23.0.13:22", "OpenSSH", "9.6p1 Ubuntu 3ubuntu13.5", "OpenSSH"},
	} {
		s := got[c.addr]
		if s.Product != c.product || s.Version != c.version {
			t.Errorf("%s = product %q version %q, want %q %q", c.addr, s.Product, s.Version, c.product, c.version)
		}
		if c.tech != "" && !slices.ContainsFunc(s.Technologies, func(t inventory.Technology) bool { return t.Name == c.tech }) {
			t.Errorf("%s technologies = %+v, want %s", c.addr, s.Technologies, c.tech)
		}
	}
	for _, a := range []string{"172.23.0.11", "172.23.0.12", "172.23.0.3", "172.23.0.6"} {
		if len(second[a]) == 0 {
			t.Errorf("%s got no second pass, want the light pass's soft or generic result escalated", a)
		}
	}
	for _, a := range []string{"172.23.0.5", "172.23.0.7", "172.23.0.9", "172.23.0.13"} {
		if len(second[a]) != 0 {
			t.Errorf("%s second pass ports = %v, want none for a product nmap named", a, second[a])
		}
	}
}
