//go:build integration

package scan_test

import (
	"context"
	"net"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"asi/internal/inventory"
	"asi/internal/scan"
	"asi/internal/scan/nmap"
	"asi/internal/scan/nmap/nmaptest"
	"asi/internal/scan/scantest"
)

func tarpit(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var held []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range held {
			c.Close()
		}
	})
	return ln.Addr().(*net.TCPAddr).Port
}

// REQ-SCAN-022
func TestSilentListenersDoNotStallStandardDetection(t *testing.T) {
	if _, err := exec.LookPath("nmap"); err != nil {
		t.Skip("nmap not installed")
	}
	ports := []int{tarpit(t), tarpit(t), tarpit(t)}
	inv := openInventory(t)
	settings := inventory.RunSettings{Targets: []string{"127.0.0.1"}, Ports: ports, MaxRate: scan.DefaultMaxRate, Workers: 1}
	run, err := inv.CreateRun(context.Background(), inventory.RunSpec{Name: "tarpit", InactiveAfter: 3, Settings: settings})
	if err != nil {
		t.Fatal(err)
	}
	sc := &scan.Scanner{Store: inv, Runner: nmap.ExecRunner{}, Transport: (&scantest.Transport{}).For, Clock: scantest.NewClock(time.Unix(0, 0))}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	start := time.Now()
	if err := sc.Run(ctx, run); err != nil {
		t.Fatal(err)
	}
	took := time.Since(start)
	t.Logf("scan of three silent listeners took %s", took)
	if took >= 120*time.Second {
		t.Errorf("scan took %s, want under 120s", took)
	}
	if f, _ := inv.FailedGroups(context.Background(), run.ID); len(f) != 0 {
		t.Fatalf("failed groups = %+v, want none", f)
	}
	d, err := inv.HostDetail(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range ports {
		if !slices.ContainsFunc(d.Host.Services, func(s inventory.ExportService) bool { return s.Port == p }) {
			t.Errorf("stored services = %+v, want port %d kept from the light pass", d.Host.Services, p)
		}
	}
	if len(d.History) == 0 || !slices.ContainsFunc(d.History[0].Notes, func(n string) bool { return strings.Contains(n, "timed out") }) {
		t.Errorf("stored history = %+v, want the second pass timeout note on run tarpit", d.History)
	}
}

// REQ-SCAN-022
func TestSecondPassTimeoutNoteIsStored(t *testing.T) {
	inv := openInventory(t)
	r := &nmaptest.Runner{DiscoverFunc: allUp, ServicesFunc: func(_ context.Context, addrs []string, _ []int, opts nmap.Options) ([]nmap.Host, error) {
		var out []nmap.Host
		for _, a := range addrs {
			h := nmap.Host{Address: a, Up: true, TimedOut: opts.Standard && a == "10.9.0.2"}
			if !opts.Standard || a != "10.9.0.2" {
				h.Ports = []nmap.Port{{Number: 6000, Protocol: "tcp", State: "open", Service: "unknown"}}
			}
			out = append(out, h)
		}
		return out, nil
	}}
	settings := inventory.RunSettings{Targets: []string{"10.9.0.1", "10.9.0.2"}, Ports: []int{6000}, MaxRate: 1000, Workers: 1}
	run, err := inv.CreateRun(context.Background(), inventory.RunSpec{Name: "notes", InactiveAfter: 3, Settings: settings})
	if err != nil {
		t.Fatal(err)
	}
	sc := &scan.Scanner{Store: inv, Runner: r, Transport: (&scantest.Transport{}).For, Clock: scantest.NewClock(time.Unix(0, 0))}
	if err := sc.Run(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	for addr, want := range map[string]int{"10.9.0.1": 0, "10.9.0.2": 1} {
		d, err := inv.HostDetail(context.Background(), addr)
		if err != nil {
			t.Fatal(err)
		}
		if len(d.History) != 1 || len(d.History[0].Notes) != want || (want == 1 && !strings.Contains(d.History[0].Notes[0], "timed out")) {
			t.Errorf("%s stored history = %+v, want %d second pass timeout note", addr, d.History, want)
		}
		if len(d.Host.Services) != 1 || d.Host.Services[0].Port != 6000 {
			t.Errorf("%s stored services = %+v, want 6000 kept", addr, d.Host.Services)
		}
	}
}
