package nmap

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestDiscoverArgs(t *testing.T) {
	got, err := DiscoverArgs([]string{"192.0.2.10", "192.0.2.11"}, Options{ProbePorts: []int{22, 80, 443}})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"-sn", "-PE", "-PS22,80,443", "-n", "-oX", "-", "192.0.2.10", "192.0.2.11"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args = %q, want %q", got, want)
	}
}

func TestServicesArgs(t *testing.T) {
	got, err := ServicesArgs([]string{"192.0.2.10"}, []int{80, 443}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"-Pn", "-sT", "-sV", "--version-light", "-p", "80,443", "-n", "-oX", "-", "192.0.2.10"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args = %q, want %q", got, want)
	}
}

func TestArgsIPv6(t *testing.T) {
	got, err := ServicesArgs([]string{"2001:DB8::1", "2001:db8::2"}, []int{443}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"-Pn", "-sT", "-sV", "--version-light", "-p", "443", "-n", "-oX", "-", "-6", "2001:db8::1", "2001:db8::2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args = %q, want %q", got, want)
	}
	got, err = DiscoverArgs([]string{"::ffff:192.0.2.1"}, Options{ProbePorts: []int{80}})
	if err != nil {
		t.Fatal(err)
	}
	want = []string{"-sn", "-PE", "-PS80", "-n", "-oX", "-", "192.0.2.1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mapped args = %q, want %q", got, want)
	}
	for _, addrs := range [][]string{{"192.0.2.1", "2001:db8::1"}, {"2001:db8::1", "192.0.2.1"}} {
		if args, err := ServicesArgs(addrs, []int{80}, Options{}); err == nil {
			t.Errorf("mixed families %q accepted: %q", addrs, args)
		}
	}
}

func TestArgsOptions(t *testing.T) {
	opts := Options{ProbePorts: []int{443}, MaxRate: 100, HostTimeout: 90 * time.Second, ResolveDNS: true}
	got, err := ServicesArgs([]string{"192.0.2.10"}, []int{443}, opts)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"-Pn", "-sT", "-sV", "--version-light", "-p", "443", "--max-rate", "100", "--host-timeout", "90000ms", "-oX", "-", "192.0.2.10"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("services args = %q, want %q", got, want)
	}
	got, err = DiscoverArgs([]string{"192.0.2.10"}, opts)
	if err != nil {
		t.Fatal(err)
	}
	want = []string{"-sn", "-PE", "-PS443", "--max-rate", "100", "--host-timeout", "90000ms", "-oX", "-", "192.0.2.10"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("discover args = %q, want %q", got, want)
	}
}

func TestArgsOnlyAllowedFlags(t *testing.T) {
	opts := Options{ProbePorts: []int{80}, MaxRate: 10, HostTimeout: time.Minute}
	d, _ := DiscoverArgs([]string{"192.0.2.1"}, opts)
	s, _ := ServicesArgs([]string{"192.0.2.1"}, []int{80}, opts)
	allowed := map[string]bool{"-sn": true, "-PE": true, "-Pn": true, "-PS80": true, "-sT": true, "-sV": true, "--version-light": true,
		"-p": true, "--max-rate": true, "--host-timeout": true, "-n": true, "-oX": true, "-": true}
	for _, a := range append(d, s...) {
		if strings.HasPrefix(a, "-") && !allowed[a] {
			t.Errorf("unexpected flag %q", a)
		}
		if strings.Contains(a, "script") {
			t.Errorf("script argument %q", a)
		}
	}
}

func TestArgsRejectHostileInput(t *testing.T) {
	addrs := []string{
		"-iL /etc/passwd", "--script=http-brute", "-sU", "192.0.2.1 -sU", "192.0.2.1;id", "$(id)",
		"192.0.2.0/24", "example.org", "", "fe80::1%eth0", "192.0.2.1\n-oN", "--",
	}
	for _, a := range addrs {
		if args, err := DiscoverArgs([]string{"192.0.2.1", a}, Options{ProbePorts: []int{80}}); err == nil {
			t.Errorf("DiscoverArgs accepted address %q: %q", a, args)
		}
		if args, err := ServicesArgs([]string{a}, []int{80}, Options{}); err == nil {
			t.Errorf("ServicesArgs accepted address %q: %q", a, args)
		}
	}
	for _, p := range []int{0, -1, -80, 65536, 1 << 20} {
		if args, err := ServicesArgs([]string{"192.0.2.1"}, []int{80, p}, Options{}); err == nil {
			t.Errorf("ServicesArgs accepted port %d: %q", p, args)
		}
		if args, err := DiscoverArgs([]string{"192.0.2.1"}, Options{ProbePorts: []int{p}}); err == nil {
			t.Errorf("DiscoverArgs accepted probe port %d: %q", p, args)
		}
	}
	bad := []struct {
		name string
		fn   func() ([]string, error)
	}{
		{"no addresses", func() ([]string, error) { return ServicesArgs(nil, []int{80}, Options{}) }},
		{"no ports", func() ([]string, error) { return ServicesArgs([]string{"192.0.2.1"}, nil, Options{}) }},
		{"no probe ports", func() ([]string, error) { return DiscoverArgs([]string{"192.0.2.1"}, Options{}) }},
		{"negative rate", func() ([]string, error) {
			return ServicesArgs([]string{"192.0.2.1"}, []int{80}, Options{MaxRate: -1})
		}},
		{"negative timeout", func() ([]string, error) {
			return ServicesArgs([]string{"192.0.2.1"}, []int{80}, Options{HostTimeout: -time.Second})
		}},
	}
	for _, b := range bad {
		if args, err := b.fn(); err == nil {
			t.Errorf("%s: accepted: %q", b.name, args)
		}
	}
}

func TestParseServices(t *testing.T) {
	f, err := os.Open("testdata/services.xml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	hosts, err := Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	want := []Host{{
		Address:   "192.0.2.10",
		Hostnames: []string{"www.example.org", "example.org"},
		Up:        true,
		Ports: []Port{
			{Number: 22, Protocol: "tcp", State: "open", Service: "ssh", Product: "OpenSSH", Version: "9.6p1 Ubuntu 3ubuntu13.5", ExtraInfo: "Ubuntu Linux; protocol 2.0"},
			{Number: 81, Protocol: "tcp", State: "closed", Service: "hosts2-ns"},
			{Number: 443, Protocol: "tcp", State: "open", Service: "http", Product: "nginx", Version: "1.24.0", ExtraInfo: "Ubuntu", Tunnel: "ssl"},
		},
	}}
	if !reflect.DeepEqual(hosts, want) {
		t.Fatalf("hosts = %+v\nwant  %+v", hosts, want)
	}
}

func TestParseDiscover(t *testing.T) {
	f, err := os.Open("testdata/discover.xml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	hosts, err := Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	want := []Host{{Address: "192.0.2.10", Up: true}, {Address: "192.0.2.11", Up: false}}
	if !reflect.DeepEqual(hosts, want) {
		t.Fatalf("hosts = %+v, want %+v", hosts, want)
	}
}

func TestParseInvalid(t *testing.T) {
	for _, in := range []string{"", "<nmaprun><host>", `<nmaprun><host><status state="up"/></host></nmaprun>`} {
		if _, err := Parse(strings.NewReader(in)); err == nil {
			t.Errorf("Parse(%q) succeeded", in)
		}
	}
}

func fakeNmap(t *testing.T, body string) (ExecRunner, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "nmap")
	script := "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done > \"" + dir + "/args\"\n" + body + "\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return ExecRunner{Path: path}, dir
}

func TestExecServices(t *testing.T) {
	fixture, err := filepath.Abs("testdata/services.xml")
	if err != nil {
		t.Fatal(err)
	}
	r, dir := fakeNmap(t, "cat '"+fixture+"'")
	hosts, err := r.Services(context.Background(), []string{"192.0.2.10"}, []int{22, 81, 443}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 || len(hosts[0].Ports) != 3 || hosts[0].Ports[2].Tunnel != "ssl" {
		t.Fatalf("hosts = %+v", hosts)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "args"))
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	want := []string{"-Pn", "-sT", "-sV", "--version-light", "-p", "22,81,443", "-n", "-oX", "-", "192.0.2.10"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("nmap argv = %q, want %q", got, want)
	}
}

func TestExecDiscover(t *testing.T) {
	fixture, err := filepath.Abs("testdata/discover.xml")
	if err != nil {
		t.Fatal(err)
	}
	r, dir := fakeNmap(t, "cat '"+fixture+"'")
	hosts, err := r.Discover(context.Background(), []string{"192.0.2.10", "192.0.2.11"}, Options{ProbePorts: []int{22, 80, 443}})
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 2 || !hosts[0].Up || hosts[1].Up {
		t.Fatalf("hosts = %+v", hosts)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "args"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(raw), "-sn\n-PE\n-PS22,80,443\n") {
		t.Fatalf("nmap argv = %q", raw)
	}
}

func TestExecHostileInputNeverRuns(t *testing.T) {
	r, dir := fakeNmap(t, "exit 0")
	if _, err := r.Services(context.Background(), []string{"--script=vuln"}, []int{80}, Options{}); err == nil {
		t.Fatal("hostile address accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "args")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("nmap was started: %v", err)
	}
}

func TestExecNonZeroExit(t *testing.T) {
	r, _ := fakeNmap(t, "echo 'Starting Nmap' >&2\necho 'Failed to resolve something.' >&2\necho >&2\nexit 1")
	_, err := r.Services(context.Background(), []string{"192.0.2.10"}, []int{80}, Options{})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "Failed to resolve something.") || strings.Contains(err.Error(), "Starting Nmap") {
		t.Fatalf("error = %v", err)
	}
}

func TestExecBadXML(t *testing.T) {
	r, _ := fakeNmap(t, "echo '<nmaprun><host>'")
	if _, err := r.Services(context.Background(), []string{"192.0.2.10"}, []int{80}, Options{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestExecContextCancelKillsProcess(t *testing.T) {
	r, dir := fakeNmap(t, "echo $$ > \""+"$(dirname \"$0\")"+"/pid\"\nexec sleep 30")
	ctx, cancel := context.WithCancel(context.Background())
	pidFile := filepath.Join(dir, "pid")
	go func() {
		for i := 0; i < 500; i++ {
			if b, err := os.ReadFile(pidFile); err == nil && len(b) > 0 {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		cancel()
	}()
	start := time.Now()
	_, err := r.Discover(ctx, []string{"192.0.2.10"}, Options{ProbePorts: []int{80}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("Discover returned after %s", d)
	}
	b, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("nmap process %d still exists: %v", pid, err)
	}
}
