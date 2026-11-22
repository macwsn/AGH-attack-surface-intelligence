package scan_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
	"unicode/utf8"

	"asi/internal/diff"
	"asi/internal/inventory"
	"asi/internal/scan"
	"asi/internal/scan/nmap"
	"asi/internal/scan/nmap/nmaptest"
	"asi/internal/scan/scantest"
)

type failingTransport struct{ err error }

func (f failingTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, f.err }

func scanOnce(t *testing.T, transport func(string) http.RoundTripper) inventory.HostResult {
	t.Helper()
	r := &nmaptest.Runner{DiscoverFunc: allUp, ServicesFunc: openPorts(80)}
	st := &scantest.Store{}
	settings := inventory.RunSettings{Targets: []string{"10.20.0.1"}, Ports: []int{80}, MaxRate: 100, Workers: 1}
	s := &scan.Scanner{Store: st, Runner: r, Transport: transport, Clock: scantest.NewClock(time.Unix(0, 0))}
	if err := s.Run(context.Background(), testRun(settings)); err != nil {
		t.Fatalf("Run: %v", err)
	}
	hosts := st.Hosts()
	if len(hosts) != 1 || len(hosts[0].Services) != 1 {
		t.Fatalf("hosts = %+v", hosts)
	}
	return hosts[0]
}

func exportOf(run string, h inventory.HostResult) inventory.Export {
	var svcs []inventory.ExportService
	for _, s := range h.Services {
		svcs = append(svcs, inventory.ExportService{
			Port: s.Port, Protocol: s.Protocol, State: s.State, Status: inventory.StatusActive,
			Service: s.Service, Product: s.Product, Version: s.Version, HTTP: s.HTTP,
		})
	}
	return inventory.Export{Run: run, Hosts: []inventory.ExportHost{{Address: h.Address, Status: inventory.StatusActive, Services: svcs}}}
}

func TestVanishedHostProbeFailureCarriesHTTPErrorAndNoServiceChanged(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		up := (&scantest.Transport{}).For
		gone := func(string) http.RoundTripper {
			return failingTransport{err: errors.New("read tcp 10.20.0.1:80: connection reset by peer")}
		}
		runs := []inventory.HostResult{scanOnce(t, up), scanOnce(t, gone), scanOnce(t, up)}

		h := runs[1].Services[0].HTTP
		if h == nil || h.Error == "" {
			t.Errorf("vanished host: http = %+v, want http.error set", h)
		} else if h.StatusCode != 0 || h.Title != "" || len(h.Headers) != 0 || len(h.Cookies) != 0 || len(h.RedirectChain) != 0 ||
			h.TLS != nil || h.FaviconSHA256 != "" {
			t.Errorf("vanished host: http = %+v, want only http.error", h)
		}

		for i := 1; i < len(runs); i++ {
			from := exportOf(fmt.Sprintf("r%d", i), runs[i-1])
			to := exportOf(fmt.Sprintf("r%d", i+1), runs[i])
			for _, c := range diff.Compute(from, to, diff.Options{}).Changes {
				if c.Type == diff.ServiceChanged {
					t.Errorf("open-then-gone run %d->%d: got service_changed %+v", i, i+1, c.Fields)
				}
			}
		}
	})
}

func TestRecordGroupRetriedUntilStoreRecovers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		st := &scantest.Store{OnRecordGroup: func(inventory.GroupResult) error {
			if calls.Add(1) <= 3 {
				return errors.New("dial tcp 127.0.0.1:5432: connection refused")
			}
			return nil
		}}
		r := &nmaptest.Runner{DiscoverFunc: allUp, ServicesFunc: openPorts(80)}
		settings := inventory.RunSettings{Targets: []string{"10.21.0.1-4"}, Ports: []int{80}, MaxRate: 100, Workers: 1}
		s := &scan.Scanner{Store: st, Runner: r, Transport: (&scantest.Transport{}).For, Clock: scantest.NewClock(time.Unix(0, 0))}
		if err := s.Run(context.Background(), testRun(settings)); err != nil {
			t.Fatalf("store fails 3 times then recovers: Run = %v, want the write retried and the run completed", err)
		}
		if got := st.Statuses(); len(got) == 0 || got[len(got)-1] != inventory.RunCompleted {
			t.Fatalf("statuses = %v, want completed", got)
		}
		if n := len(st.Hosts()); n != 4 {
			t.Fatalf("hosts recorded = %d, want 4", n)
		}
	})
}

func TestStoreOutageLeavesRunPausedAfterRetries(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		st := &scantest.Store{OnRecordGroup: func(inventory.GroupResult) error {
			calls.Add(1)
			return errors.New("dial tcp 127.0.0.1:5432: connection refused")
		}}
		r := &nmaptest.Runner{DiscoverFunc: allUp, ServicesFunc: openPorts(80)}
		settings := inventory.RunSettings{Targets: []string{"10.22.0.1"}, Ports: []int{80}, MaxRate: 100, Workers: 1}
		s := &scan.Scanner{Store: st, Runner: r, Transport: (&scantest.Transport{}).For, Clock: scantest.NewClock(time.Unix(0, 0))}
		err := s.Run(context.Background(), testRun(settings))
		if err == nil || strings.Contains(err.Error(), "\n") {
			t.Fatalf("Run = %v, want a one-line error", err)
		}
		if n := calls.Load(); n < 2 {
			t.Errorf("RecordGroup attempts = %d, want retries with backoff", n)
		}
		if got := st.Statuses(); len(got) == 0 || got[len(got)-1] != inventory.RunPaused {
			t.Fatalf("database outage: statuses = %v, want the run left paused (resumable)", got)
		}
	})
}

type rawServer struct {
	response string
	after    string
	done     chan struct{}
}

func (rs rawServer) transport(string) http.RoundTripper {
	return &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			client, server := net.Pipe()
			go rs.serve(server)
			return client, nil
		},
	}
}

func (rs rawServer) serve(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		if line == "\r\n" {
			break
		}
	}
	if _, err := io.WriteString(c, rs.response); err != nil {
		return
	}
	switch rs.after {
	case "stall":
		_, _ = io.Copy(io.Discard, br)
	case "drip":
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-tick.C:
			case <-rs.done:
				return
			}
			if _, err := io.WriteString(c, "1\r\na\r\n"); err != nil {
				return
			}
		}
	}
}

func TestPartialHTTPResponseKeepsStatusHeadersAndTitle(t *testing.T) {
	for _, tc := range []struct {
		name        string
		srv         rawServer
		title       string
		wantHeaders bool
	}{
		{
			name:        "slow body",
			srv:         rawServer{response: "HTTP/1.1 200 OK\r\nX-App: demo\r\nContent-Length: 100000\r\n\r\n<html><title>slow page</title><body>", after: "stall"},
			title:       "slow page",
			wantHeaders: true,
		},
		{
			name:        "endless chunked",
			srv:         rawServer{response: "HTTP/1.1 200 OK\r\nX-App: demo\r\nTransfer-Encoding: chunked\r\n\r\n17\r\n<title>chunky</title>\r\n\r\n", after: "drip"},
			title:       "chunky",
			wantHeaders: true,
		},
		{
			name:        "connection cut mid body",
			srv:         rawServer{response: "HTTP/1.1 200 OK\r\nX-App: demo\r\nContent-Length: 100000\r\n\r\n<html><title>cut off</title><body>", after: "close"},
			title:       "cut off",
			wantHeaders: true,
		},
		{
			name: "invalid header bytes",
			srv:  rawServer{response: "HTTP/1.1 200 OK\r\nX-App: demo\r\nX-Bad: a\x01b\r\nContent-Length: 25\r\n\r\n<title>bad header</title>", after: "close"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				srv := tc.srv
				srv.done = make(chan struct{})
				defer close(srv.done)
				r := &nmaptest.Runner{DiscoverFunc: allUp, ServicesFunc: openPorts(80)}
				st := &scantest.Store{}
				settings := inventory.RunSettings{Targets: []string{"10.23.0.1"}, Ports: []int{80}, MaxRate: 100, Workers: 1, HTTPTimeoutMS: 1000}
				s := &scan.Scanner{Store: st, Runner: r, Transport: srv.transport, Clock: scantest.NewClock(time.Unix(0, 0))}
				if err := s.Run(context.Background(), testRun(settings)); err != nil {
					t.Fatalf("Run: %v", err)
				}
				hosts := st.Hosts()
				if len(hosts) != 1 || len(hosts[0].Services) != 1 {
					t.Fatalf("hosts = %+v", hosts)
				}
				h := hosts[0].Services[0].HTTP
				if h == nil {
					t.Fatal("partial response: http = nil, want status code and http.error")
				}
				if h.StatusCode != 200 || h.Error == "" {
					t.Errorf("partial response: status_code %d error %q, want 200 and an http.error saying what failed", h.StatusCode, h.Error)
				}
				if tc.wantHeaders && h.Headers["x-app"] != "demo" {
					t.Errorf("partial response: headers %v, want x-app kept", h.Headers)
				}
				if h.Title != tc.title {
					t.Errorf("partial response: title %q, want %q", h.Title, tc.title)
				}
			})
		})
	}
}

func TestTitleAndCookieNamesCapped(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		longTitle := strings.Repeat("t", 5000)
		longCookie := strings.Repeat("c", 1000)
		tr := &scantest.Transport{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Add("Set-Cookie", longCookie+"=v")
			fmt.Fprintf(w, "<title>%s</title>", longTitle)
		})}
		r := &nmaptest.Runner{DiscoverFunc: allUp, ServicesFunc: openPorts(80)}
		st := &scantest.Store{}
		settings := inventory.RunSettings{Targets: []string{"10.24.0.1"}, Ports: []int{80}, MaxRate: 100, Workers: 1}
		s := &scan.Scanner{Store: st, Runner: r, Transport: tr.For, Clock: scantest.NewClock(time.Unix(0, 0))}
		if err := s.Run(context.Background(), testRun(settings)); err != nil {
			t.Fatalf("Run: %v", err)
		}
		hosts := st.Hosts()
		if len(hosts) != 1 || len(hosts[0].Services) != 1 || hosts[0].Services[0].HTTP == nil {
			t.Fatalf("hosts = %+v", hosts)
		}
		h := hosts[0].Services[0].HTTP
		if n := utf8.RuneCountInString(h.Title); n > 512+32 || !strings.HasPrefix(h.Title, strings.Repeat("t", 400)) || h.Title == longTitle {
			t.Errorf("title of 5000 characters stored with %d characters, want capped at 512 with a marker", n)
		}
		if len(h.Cookies) != 1 {
			t.Fatalf("cookies = %+v", h.Cookies)
		}
		if name := h.Cookies[0].Name; utf8.RuneCountInString(name) > 256+32 || !strings.HasPrefix(name, strings.Repeat("c", 200)) || name == longCookie {
			t.Errorf("cookie name of 1000 characters stored with %d characters, want capped at 256 with a marker", utf8.RuneCountInString(name))
		}
	})
}

func TestGroupWhereNmapSkippedEveryTargetRecordedFailed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nmap")
	script := "#!/bin/sh\n" +
		"for a in \"$@\"; do case \"$a\" in 192.*) echo \"Failed to determine route to $a\" >&2 ;; esac; done\n" +
		"echo 'WARNING: No targets were specified, so 0 hosts scanned.' >&2\n" +
		"cat <<'XML'\n" +
		`<?xml version="1.0"?><nmaprun scanner="nmap"><runstats><finished time="1" elapsed="0.01" exit="success"/><hosts up="0" down="0" total="0"/></runstats></nmaprun>` + "\n" +
		"XML\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	st := &scantest.Store{}
	settings := inventory.RunSettings{Targets: []string{"192.0.2.10-11"}, Ports: []int{80}, MaxRate: 100, Workers: 1}
	s := &scan.Scanner{Store: st, Runner: nmap.ExecRunner{Path: path}, Transport: (&scantest.Transport{}).For, Clock: scantest.NewClock(time.Unix(0, 0))}
	_ = s.Run(context.Background(), testRun(settings))
	failed, err := st.FailedGroups(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(failed) != 1 || !strings.Contains(strings.ToLower(failed[0].Reason), "failed to determine route") {
		t.Errorf("nmap skipped every target: failed groups = %+v, want one failed group with the reason", failed)
	}
	if g := st.Groups(); len(g) != 0 {
		t.Errorf("nmap skipped every target: recorded as finished group %+v with 0 hosts, want failed", g)
	}
}
