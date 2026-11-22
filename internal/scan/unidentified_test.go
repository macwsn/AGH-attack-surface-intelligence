package scan_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"asi/internal/inventory"
	"asi/internal/probe"
	"asi/internal/scan"
	"asi/internal/scan/nmap"
	"asi/internal/scan/nmap/nmaptest"
	"asi/internal/scan/scantest"
)

func TestHTTPProbeDecisionByNmapService(t *testing.T) {
	cases := []struct {
		service, tunnel string
		guessed         bool
		port            int
		want            string
	}{
		{"http", "", false, 0, "http"},
		{"http-proxy", "", false, 0, "http"},
		{"https", "", false, 0, "https"},
		{"ssl", "", false, 0, "https"},
		{"http", "ssl", false, 0, "https"},
		{"", "", false, 0, "http"},
		{"unknown", "", false, 0, "http"},
		{"tcpwrapped", "", false, 0, "http"},
		{"tcpwrapped", "", false, 8888, "http"},
		{"unknown", "ssl", false, 0, "https"},
		{"sun-answerbook", "", true, 0, "http"},
		{"rtsp", "", false, 0, ""},
		{"rtsp", "", true, 0, "http"},
		{"ssh", "", false, 0, ""},
		{"ssh", "", true, 0, "http"},
		{"ftp", "", false, 0, ""},
		{"smtp", "", false, 0, ""},
		{"redis", "", false, 0, ""},
		{"postgresql", "", false, 0, ""},
		{"postgresql", "", true, 0, "http"},
		{"mysql", "", false, 0, ""},
		{"amqp", "", false, 0, ""},
		{"imap", "ssl", false, 0, ""},
		{"imap", "ssl", true, 0, "https"},
		{"modbus", "", true, 0, ""},
		{"s7comm", "", true, 0, ""},
		{"iso-tsap", "", true, 0, ""},
		{"bacnet", "", true, 0, ""},
		{"dnp3", "", true, 0, ""},
		{"iec-104", "", true, 0, ""},
		{"enip", "", true, 0, ""},
		{"EtherNetIP-2", "", true, 0, ""},
		{"opc-ua", "", true, 0, ""},
		{"opcua-tcp", "", true, 0, ""},
		{"fins", "", true, 0, ""},
		{"mqtt", "", true, 0, ""},
		{"mqtt", "", false, 0, ""},
		{"jetdirect", "", true, 0, ""},
		{"jetdirect", "", false, 0, ""},
		{"pdl-datastream", "", true, 0, ""},
		{"printer", "", true, 0, ""},
		{"iso-tsap", "", true, 102, ""},
		{"", "", false, 502, ""},
		{"unknown", "", false, 2404, ""},
		{"tcpwrapped", "", false, 4840, ""},
		{"tcpwrapped", "", false, 9100, ""},
		{"unknown", "ssl", false, 20000, ""},
		{"http", "", true, 44818, ""},
		{"", "", false, 47808, ""},
		{"printer", "", false, 515, ""},
		{"unknown", "", false, 789, ""},
		{"", "", false, 1911, ""},
		{"tcpwrapped", "", false, 1962, ""},
		{"unknown", "", false, 2222, ""},
		{"", "", false, 4911, ""},
		{"unknown", "", false, 5007, ""},
		{"unknown", "", false, 9101, ""},
		{"", "", false, 9102, ""},
		{"tcpwrapped", "", false, 9103, ""},
		{"unknown", "", false, 9600, ""},
		{"", "", false, 18245, ""},
		{"unknown", "", false, 18246, ""},
		{"", "", false, 20547, ""},
		{"unknown", "", false, 34962, ""},
		{"", "", false, 34963, ""},
		{"tcpwrapped", "", false, 34964, ""},
		{"http", "", true, 2222, ""},
	}
	var ports []nmap.Port
	var numbers []int
	for i := range cases {
		if cases[i].port == 0 {
			cases[i].port = 30000 + i
		}
		c := cases[i]
		ports = append(ports, nmap.Port{Number: c.port, Protocol: "tcp", State: "open", Service: c.service, Tunnel: c.tunnel, Guessed: c.guessed})
		numbers = append(numbers, c.port)
	}
	r := &nmaptest.Runner{DiscoverFunc: allUp, ServicesFunc: func(_ context.Context, addrs []string, _ []int, _ nmap.Options) ([]nmap.Host, error) {
		return []nmap.Host{{Address: addrs[0], Up: true, Ports: ports}}, nil
	}}
	tr := &scantest.Transport{}
	st := &scantest.Store{}
	settings := inventory.RunSettings{Targets: []string{"10.8.0.1"}, Ports: numbers, MaxRate: 1000, Workers: 1}
	sc := &scan.Scanner{Store: st, Runner: r, Transport: tr.For, Clock: scantest.NewClock(time.Unix(0, 0))}
	if err := sc.Run(context.Background(), testRun(settings)); err != nil {
		t.Fatal(err)
	}
	first := map[int]string{}
	for _, q := range tr.Requests() {
		_, p, _ := net.SplitHostPort(q.Target)
		n, _ := strconv.Atoi(p)
		u, err := url.Parse(q.URL)
		if err != nil {
			t.Fatal(err)
		}
		if first[n] == "" {
			first[n] = u.Scheme
		}
	}
	for _, c := range cases {
		if first[c.port] != c.want {
			t.Errorf("service %q tunnel %q guessed %v port %d: first probe %q, want %q", c.service, c.tunnel, c.guessed, c.port, first[c.port], c.want)
		}
	}
}

func listenRaw(t *testing.T, serve func(net.Conn)) (int, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var conns atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns.Add(1)
			go func() {
				defer c.Close()
				serve(c)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, &conns
}

type peekConn struct {
	net.Conn
	r *bufio.Reader
}

func (c peekConn) Read(b []byte) (int, error) { return c.r.Read(b) }

func TestUnidentifiedPortsGetHTTPThenTLS(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "nginx/1.27.5")
		fmt.Fprint(w, "<title>httpbin.org</title>")
	}))
	defer plain.Close()
	u, _ := url.Parse(plain.URL)
	plainPort, _ := strconv.Atoi(u.Port())

	cert := httptest.NewTLSServer(http.NotFoundHandler())
	tlsCfg := cert.TLS.Clone()
	cert.Close()
	var plainAttempts atomic.Int32
	tlsPort, tlsConns := listenRaw(t, func(c net.Conn) {
		br := bufio.NewReader(c)
		first, err := br.Peek(1)
		if err != nil {
			return
		}
		if first[0] != 0x16 {
			plainAttempts.Add(1)
			c.Write([]byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28})
			return
		}
		tc := tls.Server(peekConn{c, br}, tlsCfg)
		if _, err := http.ReadRequest(bufio.NewReader(tc)); err != nil {
			return
		}
		body := "<title>secure</title>"
		fmt.Fprintf(tc, "HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
	})
	pgPort, pgConns := listenRaw(t, func(c net.Conn) {
		b := make([]byte, 512)
		c.Read(b)
		c.Write([]byte("E\x00\x00\x00\x08invalid"))
	})
	closePort, closeConns := listenRaw(t, func(c net.Conn) {})

	r := &nmaptest.Runner{DiscoverFunc: allUp, ServicesFunc: func(_ context.Context, addrs []string, _ []int, _ nmap.Options) ([]nmap.Host, error) {
		return []nmap.Host{{Address: addrs[0], Up: true, Ports: []nmap.Port{
			{Number: plainPort, Protocol: "tcp", State: "open", Service: "tcpwrapped"},
			{Number: tlsPort, Protocol: "tcp", State: "open", Service: "unknown"},
			{Number: pgPort, Protocol: "tcp", State: "open", Service: ""},
			{Number: closePort, Protocol: "tcp", State: "open", Service: "tcpwrapped", Product: "x"},
		}}}, nil
	}}
	st := &scantest.Store{}
	settings := inventory.RunSettings{Targets: []string{"127.0.0.1"}, Ports: []int{plainPort, tlsPort, pgPort, closePort}, MaxRate: 1000, Workers: 1}
	sc := &scan.Scanner{
		Store: st, Runner: r, Clock: scantest.NewClock(time.Unix(0, 0)),
		Transport: func(target string) http.RoundTripper { return probe.NewTransport(target, 5*time.Second) },
	}
	if err := sc.Run(context.Background(), testRun(settings)); err != nil {
		t.Fatal(err)
	}
	hosts := st.Hosts()
	if len(hosts) != 1 || len(hosts[0].Services) != 4 {
		t.Fatalf("hosts = %+v", hosts)
	}
	by := map[int]inventory.ServiceResult{}
	for _, s := range hosts[0].Services {
		by[s.Port] = s
	}

	p := by[plainPort]
	if p.Service != "http" || p.HTTP == nil || p.HTTP.StatusCode != 200 || p.HTTP.Title != "httpbin.org" || p.HTTP.Headers["server"] != "nginx/1.27.5" {
		t.Errorf("plain service = %+v http %+v", p, p.HTTP)
	}
	if len(p.Technologies) == 0 || p.Technologies[0].Name != "nginx" {
		t.Errorf("plain technologies = %+v, want nginx", p.Technologies)
	}

	s := by[tlsPort]
	if s.Service != "https" || s.HTTP == nil || s.HTTP.Scheme != "https" || s.HTTP.StatusCode != 200 || s.HTTP.Title != "secure" || s.HTTP.TLS == nil {
		t.Errorf("tls service = %+v http %+v", s, s.HTTP)
	}
	if n := plainAttempts.Load(); n != 1 {
		t.Errorf("plain attempts on the TLS port = %d, want 1", n)
	}
	if tlsConns.Load() < 2 {
		t.Errorf("TLS port connections = %d, want a plain and an HTTPS probe", tlsConns.Load())
	}

	for _, c := range []struct {
		port    int
		conns   *atomic.Int32
		service string
	}{{pgPort, pgConns, ""}, {closePort, closeConns, "tcpwrapped"}} {
		got := by[c.port]
		if got.Service != c.service || got.HTTP != nil || len(got.Technologies) != 0 {
			t.Errorf("port %d = %+v http %+v, want nmap's %q and no http", c.port, got, got.HTTP, c.service)
		}
		if n := c.conns.Load(); n != 1 {
			t.Errorf("port %d connections = %d, want one plain probe and no TLS probe", c.port, n)
		}
	}
	if by[closePort].Product != "x" {
		t.Errorf("product lost: %+v", by[closePort])
	}
}

func servicesCalls(r *nmaptest.Runner) []nmaptest.Call {
	var out []nmaptest.Call
	for _, c := range r.Calls() {
		if c.Method == "Services" {
			out = append(out, c)
		}
	}
	return out
}

// REQ-SCAN-022
func TestSecondServicePassOptions(t *testing.T) {
	r := &nmaptest.Runner{DiscoverFunc: allUp, ServicesFunc: func(_ context.Context, addrs []string, ports []int, _ nmap.Options) ([]nmap.Host, error) {
		return []nmap.Host{{Address: addrs[0], Up: true, Ports: []nmap.Port{{Number: 6000, Protocol: "tcp", State: "open"}}}}, nil
	}}
	for _, tc := range []struct {
		setting string
		calls   int
	}{{"", 2}, {scan.ServiceDetectionStandard, 2}, {scan.ServiceDetectionLight, 1}} {
		r := &nmaptest.Runner{DiscoverFunc: allUp, ServicesFunc: r.ServicesFunc}
		settings := inventory.RunSettings{Targets: []string{"10.8.0.1"}, Ports: []int{22, 6000}, MaxRate: 1000, Workers: 1, ServiceDetection: tc.setting}
		sc := &scan.Scanner{Store: &scantest.Store{}, Runner: r, Transport: (&scantest.Transport{}).For, Clock: scantest.NewClock(time.Unix(0, 0))}
		if err := sc.Run(context.Background(), testRun(settings)); err != nil {
			t.Fatal(err)
		}
		calls := servicesCalls(r)
		if len(calls) != tc.calls {
			t.Fatalf("service_detection %q: %d service detections %+v, want %d", tc.setting, len(calls), calls, tc.calls)
		}
		if calls[0].Opts.Standard || !slices.Equal(calls[0].Ports, []int{22, 6000}) {
			t.Errorf("service_detection %q: light pass = %+v", tc.setting, calls[0])
		}
		if tc.calls == 2 {
			second := calls[1]
			if !second.Opts.Standard || !slices.Equal(second.Ports, []int{6000}) || second.Opts.MaxRate != calls[0].Opts.MaxRate {
				t.Errorf("service_detection %q: second pass = %+v, want standard intensity on port 6000 at the light pass rate %d", tc.setting, second, calls[0].Opts.MaxRate)
			}
		}
	}
}

// REQ-SCAN-022
func TestServiceDetectionSettingRejected(t *testing.T) {
	r := &nmaptest.Runner{DiscoverFunc: allUp, ServicesFunc: openPorts(80)}
	settings := inventory.RunSettings{Targets: []string{"10.8.0.1"}, Ports: []int{80}, MaxRate: 100, Workers: 1, ServiceDetection: "full"}
	sc := &scan.Scanner{Store: &scantest.Store{}, Runner: r, Transport: (&scantest.Transport{}).For, Clock: scantest.NewClock(time.Unix(0, 0))}
	if err := sc.Run(context.Background(), testRun(settings)); err == nil || !strings.Contains(err.Error(), "service detection") {
		t.Fatalf("Run = %v, want a service detection error", err)
	}
	if c := r.Calls(); len(c) != 0 {
		t.Fatalf("nmap calls = %+v, want none", c)
	}
}

// REQ-SCAN-022
func TestSecondServicePassOnlyFlaggedPortsPerHost(t *testing.T) {
	light := map[string][]nmap.Port{
		"10.8.0.1": {{Number: 6000, Protocol: "tcp", State: "open", Service: "unknown"}, {Number: 7000, Protocol: "tcp", State: "open", Service: "ssh"}},
		"10.8.0.2": {{Number: 6000, Protocol: "tcp", State: "open", Service: "modbus", Guessed: true}, {Number: 7000, Protocol: "tcp", State: "open", Service: ""}},
		"10.8.0.3": {{Number: 6000, Protocol: "tcp", State: "open", Service: "tcpwrapped"}},
	}
	var calls atomic.Int32
	r := &nmaptest.Runner{DiscoverFunc: allUp, ServicesFunc: func(_ context.Context, addrs []string, ports []int, _ nmap.Options) ([]nmap.Host, error) {
		var out []nmap.Host
		for _, a := range addrs {
			h := nmap.Host{Address: a, Up: true}
			for _, p := range light[a] {
				if !slices.Contains(ports, p.Number) {
					continue
				}
				if calls.Load() >= 1 {
					p.Service, p.Guessed = "second", false
				}
				h.Ports = append(h.Ports, p)
			}
			out = append(out, h)
		}
		calls.Add(1)
		return out, nil
	}}
	st := &scantest.Store{}
	settings := inventory.RunSettings{Targets: []string{"10.8.0.1", "10.8.0.2", "10.8.0.3", "10.8.0.4"}, Ports: []int{6000, 7000}, MaxRate: 1000, Workers: 1}
	sc := &scan.Scanner{Store: st, Runner: r, Transport: (&scantest.Transport{}).For, Clock: scantest.NewClock(time.Unix(0, 0))}
	if err := sc.Run(context.Background(), testRun(settings)); err != nil {
		t.Fatal(err)
	}
	got := map[string][]int{}
	for _, c := range servicesCalls(r)[1:] {
		got[strings.Join(c.Addrs, " ")] = c.Ports
	}
	want := map[string][]int{"10.8.0.1": {6000, 7000}, "10.8.0.2": {7000}, "10.8.0.3": {6000}}
	if len(got) != len(want) || !slices.Equal(got["10.8.0.1"], want["10.8.0.1"]) || !slices.Equal(got["10.8.0.2"], want["10.8.0.2"]) || !slices.Equal(got["10.8.0.3"], want["10.8.0.3"]) {
		t.Fatalf("second pass calls = %v, want %v", got, want)
	}
	for _, h := range st.Hosts() {
		for _, s := range h.Services {
			flagged := (h.Address != "10.8.0.2" && s.Port == 6000) || s.Port == 7000
			if (s.Service == "second") != flagged {
				t.Errorf("%s:%d = %q, second pass result applied %v, want %v", h.Address, s.Port, s.Service, s.Service == "second", flagged)
			}
		}
	}
}

// REQ-SCAN-015
func TestHTTPNamedPortTimeoutSkipsTLSFallback(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tr := &scantest.Transport{Hold: make(chan struct{})}
		r := &nmaptest.Runner{DiscoverFunc: allUp, ServicesFunc: openPorts(8080)}
		st := &scantest.Store{}
		settings := inventory.RunSettings{Targets: []string{"10.8.0.1"}, Ports: []int{8080}, MaxRate: 1000, Workers: 1, HTTPTimeoutMS: 300}
		sc := &scan.Scanner{Store: st, Runner: r, Transport: tr.For, Clock: scantest.NewClock(time.Unix(0, 0))}
		if err := sc.Run(context.Background(), testRun(settings)); err != nil {
			t.Fatal(err)
		}
		if q := tr.Requests(); len(q) != 1 || !strings.HasPrefix(q[0].URL, "http://") {
			t.Fatalf("requests = %+v, want one plain request", q)
		}
		s := st.Hosts()[0].Services[0]
		if s.Service != "http" || s.HTTP == nil || s.HTTP.Scheme != "http" || s.HTTP.Error != probe.ErrorTimeout {
			t.Fatalf("service = %q http %+v, want the plain timeout", s.Service, s.HTTP)
		}
	})
}

// REQ-SCAN-022
func TestSecondServicePassTimedOutHostKeepsLightResults(t *testing.T) {
	r := &nmaptest.Runner{DiscoverFunc: allUp, ServicesFunc: func(_ context.Context, addrs []string, ports []int, opts nmap.Options) ([]nmap.Host, error) {
		var out []nmap.Host
		for _, a := range addrs {
			h := nmap.Host{Address: a, Up: true}
			switch {
			case !opts.Standard:
				h.Ports = []nmap.Port{{Number: 22, Protocol: "tcp", State: "open", Service: "ssh", Product: "OpenSSH"}, {Number: 6000, Protocol: "tcp", State: "open", Service: "unknown"}}
			case a == "10.8.0.2":
				h.TimedOut = true
			default:
				h.Ports = []nmap.Port{{Number: 6000, Protocol: "tcp", State: "open", Service: "postgresql", Version: "16.2"}}
			}
			out = append(out, h)
		}
		return out, nil
	}}
	st := &scantest.Store{}
	settings := inventory.RunSettings{Targets: []string{"10.8.0.1", "10.8.0.2", "10.8.0.3"}, Ports: []int{22, 6000}, MaxRate: 1000, Workers: 1}
	sc := &scan.Scanner{Store: st, Runner: r, Transport: (&scantest.Transport{}).For, Clock: scantest.NewClock(time.Unix(0, 0))}
	if err := sc.Run(context.Background(), testRun(settings)); err != nil {
		t.Fatal(err)
	}
	calls := servicesCalls(r)
	if len(calls) != 2 {
		t.Fatalf("service detections = %+v, want the light pass and one second pass over all flagged hosts", calls)
	}
	second := calls[1]
	if !slices.Equal(second.Addrs, []string{"10.8.0.1", "10.8.0.2", "10.8.0.3"}) || !slices.Equal(second.Ports, []int{6000}) {
		t.Errorf("second pass = %v on %v, want all three hosts in one call on 6000", second.Addrs, second.Ports)
	}
	if second.Opts.MaxRate != calls[0].Opts.MaxRate || second.Opts.HostTimeout != scan.SecondPassPerPort || second.Opts.MaxRetries != scan.SecondPassRetries {
		t.Errorf("second pass opts = %+v, want the light pass rate %d, host timeout %s and %d retry", second.Opts, calls[0].Opts.MaxRate, scan.SecondPassPerPort, scan.SecondPassRetries)
	}
	if f, _ := st.FailedGroups(context.Background(), 1); len(f) != 0 {
		t.Fatalf("failed groups = %+v, want none", f)
	}
	if g := st.Groups(); len(g) != 1 || len(g[0].Hosts) != 3 {
		t.Fatalf("groups = %+v, want one group with three hosts", g)
	}
	for _, h := range st.Hosts() {
		svc := map[int]inventory.ServiceResult{}
		for _, s := range h.Services {
			svc[s.Port] = s
		}
		second, notes := true, 0
		if h.Address == "10.8.0.2" {
			second, notes = false, 1
		}
		if (svc[6000].Service == "postgresql") != second || svc[22].Product != "OpenSSH" {
			t.Errorf("%s services = %+v, want the second pass result on 6000 %v and the light ssh result", h.Address, h.Services, second)
		}
		if len(h.Notes) != notes || (notes == 1 && !strings.Contains(h.Notes[0], "timed out")) {
			t.Errorf("%s notes = %q, want %d timeout note", h.Address, h.Notes, notes)
		}
	}
}

// REQ-SCAN-022
func TestSecondServicePassHostTimeout(t *testing.T) {
	for _, tc := range []struct {
		ports   int
		scanner time.Duration
		want    time.Duration
	}{{1, 0, 20 * time.Second}, {3, 0, 60 * time.Second}, {6, 0, 90 * time.Second}, {6, 30 * time.Second, 30 * time.Second}} {
		var ports []int
		for i := range tc.ports {
			ports = append(ports, 6000+i)
		}
		r := &nmaptest.Runner{DiscoverFunc: allUp, ServicesFunc: func(_ context.Context, addrs []string, ps []int, _ nmap.Options) ([]nmap.Host, error) {
			h := nmap.Host{Address: addrs[0], Up: true}
			for _, p := range ps {
				h.Ports = append(h.Ports, nmap.Port{Number: p, Protocol: "tcp", State: "open", Service: "unknown"})
			}
			return []nmap.Host{h}, nil
		}}
		settings := inventory.RunSettings{Targets: []string{"10.8.0.1"}, Ports: ports, MaxRate: 1000, Workers: 1}
		sc := &scan.Scanner{Store: &scantest.Store{}, Runner: r, Transport: (&scantest.Transport{}).For, Clock: scantest.NewClock(time.Unix(0, 0)), HostTimeout: tc.scanner}
		if err := sc.Run(context.Background(), testRun(settings)); err != nil {
			t.Fatal(err)
		}
		calls := servicesCalls(r)
		if len(calls) != 2 || calls[1].Opts.HostTimeout != tc.want {
			t.Errorf("%d ports, scanner host timeout %s: service detections %+v, want a second pass bounded at %s", tc.ports, tc.scanner, calls, tc.want)
		}
	}
}

// REQ-SCAN-022
func TestSecondServicePassWaitsForSilentHostsInParallel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var inflight, peak atomic.Int32
		all := make(chan struct{})
		r := &nmaptest.Runner{DiscoverFunc: allUp, ServicesFunc: func(_ context.Context, addrs []string, ports []int, opts nmap.Options) ([]nmap.Host, error) {
			if !opts.Standard {
				var out []nmap.Host
				for i, a := range addrs {
					out = append(out, nmap.Host{Address: a, Up: true, Ports: []nmap.Port{{Number: 6000 + i, Protocol: "tcp", State: "open", Service: "unknown"}}})
				}
				return out, nil
			}
			n := inflight.Add(1)
			peak.Store(max(peak.Load(), n))
			if n == 3 {
				close(all)
			}
			select {
			case <-all:
			case <-time.After(opts.HostTimeout):
			}
			inflight.Add(-1)
			return []nmap.Host{{Address: addrs[0], Up: true, TimedOut: true}}, nil
		}}
		st := &scantest.Store{}
		settings := inventory.RunSettings{Targets: []string{"10.8.0.1", "10.8.0.2", "10.8.0.3"}, Ports: []int{6000, 6001, 6002}, MaxRate: 1000, Workers: 1}
		sc := &scan.Scanner{Store: st, Runner: r, Transport: (&scantest.Transport{}).For, Clock: scantest.NewClock(time.Unix(0, 0))}
		if err := sc.Run(context.Background(), testRun(settings)); err != nil {
			t.Fatal(err)
		}
		calls := servicesCalls(r)
		if len(calls) != 4 {
			t.Fatalf("service detections = %+v, want the light pass and one second pass per flagged port set", calls)
		}
		if p := peak.Load(); p != 3 {
			t.Errorf("second pass calls in flight at once = %d, want all 3 silent hosts waited for in parallel", p)
		}
		rate := 0
		flagged := map[string]int{"10.8.0.1": 6000, "10.8.0.2": 6001, "10.8.0.3": 6002}
		for _, c := range calls[1:] {
			if len(c.Addrs) != 1 || !slices.Equal(c.Ports, []int{flagged[c.Addrs[0]]}) {
				t.Errorf("second pass call %+v probes ports the host did not flag", c)
			}
			rate += c.Opts.MaxRate
		}
		if rate > calls[0].Opts.MaxRate {
			t.Errorf("second pass calls together run at %d/s, want at most the light pass share %d/s", rate, calls[0].Opts.MaxRate)
		}
		if f, _ := st.FailedGroups(context.Background(), 1); len(f) != 0 {
			t.Fatalf("failed groups = %+v, want none", f)
		}
		for _, h := range st.Hosts() {
			if len(h.Services) != 1 || len(h.Notes) != 1 {
				t.Errorf("%s services %+v notes %q, want the light result and one timeout note", h.Address, h.Services, h.Notes)
			}
		}
	})
}
