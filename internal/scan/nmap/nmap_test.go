package nmap

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
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

// REQ-SCAN-011
func TestArgsCompressPortRanges(t *testing.T) {
	ports := []int{21, 80}
	for p := 8000; p <= 8100; p++ {
		ports = append(ports, p)
	}
	got, err := ServicesArgs([]string{"127.0.0.1"}, ports, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got[5] != "21,80,8000-8100" {
		t.Fatalf("-p %q, want 21,80,8000-8100", got[5])
	}
	all := make([]int, 65535)
	for i := range all {
		all[i] = i + 1
	}
	got, err = DiscoverArgs([]string{"127.0.0.1"}, Options{ProbePorts: all})
	if err != nil || got[2] != "-PS1-65535" {
		t.Fatalf("discover args = %q, %v", got[:3], err)
	}
}

func TestParseGuessedService(t *testing.T) {
	xml := `<nmaprun><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="8888"><state state="open"/><service name="sun-answerbook" method="table" conf="3"/></port>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" method="probed" conf="10"/></port>
<port protocol="tcp" portid="81"><state state="closed"/><service name="hosts2-ns" method="table" conf="3"/></port>
<port protocol="tcp" portid="15432"><state state="open"/></port>
</ports></host></nmaprun>`
	hosts, err := Parse(strings.NewReader(xml))
	if err != nil {
		t.Fatal(err)
	}
	got := map[int]bool{}
	for _, p := range hosts[0].Ports {
		got[p.Number] = p.Guessed
	}
	want := map[int]bool{8888: true, 22: false, 81: false, 15432: false}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("guessed = %v, want %v", got, want)
	}
}

// REQ-SCAN-022
func TestServicesArgsStandardAndVersionDB(t *testing.T) {
	got, err := ServicesArgs([]string{"192.0.2.10"}, []int{5432}, Options{Standard: true})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"-Pn", "-sT", "-sV", "-p", "5432", "-n", "-oX", "-", "192.0.2.10"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("standard args = %q, want %q", got, want)
	}
	got, err = ServicesArgs([]string{"192.0.2.10"}, []int{80}, Options{VersionDB: "/tmp/probes"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"-Pn", "-sT", "-sV", "--version-light", "--versiondb", "/tmp/probes", "-p", "80", "-n", "-oX", "-", "192.0.2.10"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("version db args = %q, want %q", got, want)
	}
	for _, db := range []string{"probes", "-iL", "--script=x"} {
		if args, err := ServicesArgs([]string{"192.0.2.10"}, []int{80}, Options{VersionDB: db}); err == nil {
			t.Errorf("ServicesArgs accepted version db %q: %q", db, args)
		}
	}
}

const sampleProbes = `# header
Probe TCP NULL q||
totalwaitms 6000
softmatch ftp m|^220 .*ftp|i
match ftp m|^220 vsFTPd| p/vsftpd/
softmatch ssl m|^\x16\x03|
match ssh m|^SSH-|
Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
rarity 1
softmatch http m|^HTTP/1\.1 400 Bad Request\r\n| p|Golang net/http server|
match http m|^HTTP/1\.[01] \d\d\d .*Server: nginx| p/nginx/
`

const lightSampleProbes = `# header
Probe TCP NULL q||
totalwaitms 6000
match ftp m|^220 vsFTPd| p/vsftpd/
softmatch ssl m|^\x16\x03|
match ssh m|^SSH-|
match ftp m|^220 .*ftp|i
Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
rarity 1
match http m|^HTTP/1\.[01] \d\d\d .*Server: nginx| p/nginx/
match http m|^HTTP/1\.1 400 Bad Request\r\n| p|Golang net/http server|
`

// REQ-SCAN-022
func TestWriteLightProbes(t *testing.T) {
	var out strings.Builder
	if err := WriteLightProbes(&out, strings.NewReader(sampleProbes)); err != nil {
		t.Fatal(err)
	}
	if out.String() != lightSampleProbes {
		t.Fatalf("light probes =\n%s\nwant\n%s", out.String(), lightSampleProbes)
	}
}

// REQ-SCAN-022
func TestExecServicesUsesLightProbes(t *testing.T) {
	fixture, err := filepath.Abs("testdata/services.xml")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	share := filepath.Join(root, "share", "nmap")
	for _, d := range []string{bin, share} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(share, "nmap-service-probes"), []byte(sampleProbes), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NMAPDIR", "")
	path := filepath.Join(bin, "nmap")
	script := "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done > \"" + root + "/args\"\n" +
		"prev=\nfor a in \"$@\"; do [ \"$prev\" = --versiondb ] && cp \"$a\" \"" + root + "/db\"; prev=$a; done\ncat '" + fixture + "'\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	r := ExecRunner{Path: path}
	args := func() []string {
		raw, err := os.ReadFile(filepath.Join(root, "args"))
		if err != nil {
			t.Fatal(err)
		}
		return strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	}
	if _, err := r.Services(context.Background(), []string{"192.0.2.10"}, []int{22}, Options{}); err != nil {
		t.Fatal(err)
	}
	got := args()
	if len(got) < 6 || got[3] != "--version-light" || got[4] != "--versiondb" {
		t.Fatalf("light argv = %q, want --version-light --versiondb <file>", got)
	}
	db, err := os.ReadFile(filepath.Join(root, "db"))
	if err != nil || string(db) != lightSampleProbes {
		t.Fatalf("version db passed to nmap = %q (%v), want the light probes", db, err)
	}
	if _, err := os.Stat(got[5]); !os.IsNotExist(err) {
		t.Errorf("light probes file %s left behind: %v", got[5], err)
	}
	if _, err := r.Services(context.Background(), []string{"192.0.2.10"}, []int{22}, Options{Standard: true}); err != nil {
		t.Fatal(err)
	}
	if got, want := args(), []string{"-Pn", "-sT", "-sV", "-p", "22", "-n", "-oX", "-", "192.0.2.10"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("standard argv = %q, want %q (stock probes)", got, want)
	}
}

const influxProbes = `Probe TCP NULL q||
softmatch http m|^HTTP/1\.1 400 Bad Request\r\nContent-Type: text/plain(?:; charset=utf-8)?\r\nConnection: close\r\n\r\n400 Bad Request| p|Golang net/http server| cpe:/a:golang:go/
Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
match http m|^HTTP/1\.0 404 Not Found\r\nContent-Type: text/plain; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\nDate: .*\r\nContent-Length: 19\r\n\r\n404 page not found\n| p|Golang net/http server| i/Go-IPFS json-rpc or InfluxDB API/ cpe:/a:golang:go/
match http m|^HTTP/1\.0 \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?X-Influxdb-Version: v?([\d.]+)\r\n|s p/InfluxDB http admin/ v/$1/ cpe:/a:influxdata:influxdb:$1/
softmatch http m|^HTTP/1\.[01] \d\d\d| p/$1 httpd/
`

func fakeNmapWithProbes(t *testing.T, probes, script string) (ExecRunner, string) {
	t.Helper()
	root := t.TempDir()
	share := filepath.Join(root, "share")
	if err := os.MkdirAll(share, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(share, "nmap-service-probes"), []byte(probes), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NMAPDIR", share)
	path := filepath.Join(root, "nmap")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nprintf '%s ' \"$@\" >> \""+root+"/argv\"\necho >> \""+root+"/argv\"\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
	return ExecRunner{Path: path}, filepath.Join(root, "argv")
}

func argvLines(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
}

// REQ-SCAN-022: recorded nmap 7.99 output for InfluxDB 1.6.6 on 8086.
func TestExecLightPassMarksSoftMatchInfluxDB(t *testing.T) {
	asi, err := filepath.Abs("testdata/influxdb-light-asi.xml")
	if err != nil {
		t.Fatal(err)
	}
	stock, err := filepath.Abs("testdata/influxdb-light-stock.xml")
	if err != nil {
		t.Fatal(err)
	}
	r, argv := fakeNmapWithProbes(t, influxProbes, "case \" $* \" in *' --versiondb '*) cat '"+asi+"' ;; *) cat '"+stock+"' ;; esac\n")
	hosts, err := r.Services(context.Background(), []string{"192.0.2.30"}, []int{8086}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if p := hosts[0].Ports[0]; p.Product != "Golang net/http server" || !p.Soft {
		t.Fatalf("light pass = %+v, want the soft match Golang net/http server marked Soft", p)
	}
	hosts, err = r.Services(context.Background(), []string{"192.0.2.30"}, []int{8086}, Options{StockProbes: true})
	if err != nil {
		t.Fatal(err)
	}
	if p := hosts[0].Ports[0]; p.Product != "InfluxDB http admin" || p.Version != "1.6.6" || p.Soft {
		t.Fatalf("stock light pass = %+v, want InfluxDB http admin 1.6.6, not soft", p)
	}
	lines := argvLines(t, argv)
	if len(lines) != 2 || !strings.Contains(lines[1], "-sV --version-light -p 8086") || strings.Contains(lines[1], "--versiondb") {
		t.Fatalf("argv = %q, want the second call to be stock nmap -sV --version-light", lines)
	}
}

func TestMarkSoft(t *testing.T) {
	hosts := []Host{{Ports: []Port{
		{Number: 1, State: "open", Service: "http", Product: "Golang net/http server"},
		{Number: 2, State: "open", Service: "http", Product: "Golang net/http server", ExtraInfo: "Go-IPFS json-rpc or InfluxDB API"},
		{Number: 3, State: "open", Service: "http", Product: "InfluxDB http admin", Version: "1.6.6"},
		{Number: 4, State: "open", Service: "http", Product: "Foo httpd"},
		{Number: 5, State: "open", Service: "ssl", Product: "Golang net/http server"},
		{Number: 6, State: "open", Service: "http", Product: "Golang net/http server", Guessed: true},
		{Number: 7, State: "closed", Service: "http", Product: "Golang net/http server"},
	}}}
	if err := MarkSoft(hosts, strings.NewReader(influxProbes)); err != nil {
		t.Fatal(err)
	}
	want := map[int]bool{1: true, 4: true}
	for _, p := range hosts[0].Ports {
		if p.Soft != want[p.Number] {
			t.Errorf("port %d %q %q: soft = %v, want %v", p.Number, p.Product, p.ExtraInfo, p.Soft, want[p.Number])
		}
	}
}

// REQ-SCAN-033: never-probe ports get a connect scan, never a version scan.
func TestExecNoVersionPortsGetNoVersionDetection(t *testing.T) {
	fixture, err := filepath.Abs("testdata/services.xml")
	if err != nil {
		t.Fatal(err)
	}
	r, argv := fakeNmapWithProbes(t, sampleProbes, "cat '"+fixture+"'\n")
	if _, err := r.Services(context.Background(), []string{"192.0.2.10"}, []int{22, 502, 1883}, Options{NoVersion: []int{502, 1883}}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Services(context.Background(), []string{"192.0.2.10"}, []int{1883}, Options{NoVersion: []int{1883}}); err != nil {
		t.Fatal(err)
	}
	lines := argvLines(t, argv)
	if len(lines) != 3 {
		t.Fatalf("nmap calls = %q, want 3", lines)
	}
	for _, l := range lines {
		_, list, _ := strings.Cut(l, " -p ")
		list, _, _ = strings.Cut(list, " ")
		if strings.Contains(l, "-sV") && (strings.Contains(list, "502") || strings.Contains(list, "1883")) {
			t.Errorf("never-probe port in a version scan: %s", l)
		}
	}
	if !strings.Contains(lines[0], "-sV") || !strings.Contains(lines[0], "-p 22 ") {
		t.Errorf("first call = %s, want -sV on 22 only", lines[0])
	}
	for _, l := range lines[1:] {
		if !strings.HasPrefix(l, "-Pn -sT -p ") || strings.Contains(l, "-sV") {
			t.Errorf("never-probe call = %s, want a connect scan without -sV", l)
		}
	}
}

func TestParseBannerAndScriptProperties(t *testing.T) {
	xml := `<nmaprun><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="21"><state state="open"/><service name="ftp" method="probed" conf="10" servicefp="SF-Port21-TCP:V=7.95%I=7%D=11/21%Time=692053EA%P=x86_64-pc-linux-gnu%r(NULL,33,&quot;220\x20ftp\.example\.org\x20FTP\x20server\x20\(vsFTPd\x203\.0\.5\)&#xa;SF:\x20ready\r\n&quot;)%r(GenericLines,4,&quot;500\x20&quot;);"/></port>
<port protocol="tcp" portid="25"><state state="open"/><service name="smtp" method="probed" conf="10"/><script id="banner" output="220 mx.example.org ESMTP Exim 4.96"/></port>
<port protocol="tcp" portid="5672"><state state="open"/><service name="amqp" product="Advanced Message Queue Protocol" method="probed" conf="10"/><script id="amqp-info" output="..."><table key="capabilities"><elem key="version">nested</elem></table><elem key="product">RabbitMQ</elem><elem key="version">3.13.7</elem></script></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" method="probed" conf="10"/></port>
</ports></host></nmaprun>`
	hosts, err := Parse(strings.NewReader(xml))
	if err != nil {
		t.Fatal(err)
	}
	type info struct{ banner, product, version string }
	got := map[int]info{}
	for _, p := range hosts[0].Ports {
		got[p.Number] = info{p.Banner, p.ScriptProduct, p.ScriptVersion}
	}
	want := map[int]info{
		21:   {banner: "220 ftp.example.org FTP server (vsFTPd 3.0.5) ready\r\n"},
		25:   {banner: "220 mx.example.org ESMTP Exim 4.96"},
		5672: {product: "RabbitMQ", version: "3.13.7"},
		80:   {},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("banners and script properties = %+v, want %+v", got, want)
	}
}

func TestWriteLightProbesKeepsVsftpdHardMatchBeforeSoftMatches(t *testing.T) {
	src := `Probe TCP NULL q||
totalwaitms 6000
softmatch ftp m|^220 Welcome to ([-.\w]+) FTP.*\r\n$|i h/$1/
softmatch ftp m|^220[- ].*ftp server.*\r\n|i
match ftp m|^220 \(vsFTPd ([-.\w]+)\)\r\n$| p/vsftpd/ v/$1/ o/Unix/ cpe:/a:vsftpd:vsftpd:$1/
match ftp m|^220 ProFTPD (\d\S+) Server| p/ProFTPD/ v/$1/
softmatch ftp m|^220-\r?\n220 - ftp|i
Probe TCP GenericLines q|\r\n\r\n|
`
	var out strings.Builder
	if err := WriteLightProbes(&out, strings.NewReader(src)); err != nil {
		t.Fatal(err)
	}
	pattern := regexp.MustCompile(`^match \S+ m\|(.*)\|(i?)`)
	for _, c := range []struct{ banner, product string }{
		{"220 (vsFTPd 3.0.2)\r\n", "p/vsftpd/"},
		{"220 ProFTPD 1.3.8 Server (Debian) [::ffff:192.0.2.30]\r\n", "p/ProFTPD/"},
	} {
		first := ""
		for _, line := range strings.Split(out.String(), "\n") {
			m := pattern.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			expr := m[1]
			if m[2] == "i" {
				expr = "(?i)" + expr
			}
			if regexp.MustCompile(expr).MatchString(c.banner) {
				first = line
				break
			}
		}
		if !strings.Contains(first, c.product) {
			t.Errorf("first light match for %q = %q, want the hard match with %s", c.banner, first, c.product)
		}
	}
}

// REQ-SCAN-022
func TestServicesArgsSecondPassBound(t *testing.T) {
	opts := Options{MaxRate: 100, HostTimeout: 40 * time.Second, MaxRetries: 1, Standard: true}
	got, err := ServicesArgs([]string{"192.0.2.10", "192.0.2.11"}, []int{21, 6000}, opts)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"-Pn", "-sT", "-sV", "-p", "21,6000", "--max-rate", "100", "--host-timeout", "40000ms", "--max-retries", "1", "-n", "-oX", "-", "192.0.2.10", "192.0.2.11"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("services args = %q, want %q", got, want)
	}
	if args, err := ServicesArgs([]string{"192.0.2.1"}, []int{80}, Options{MaxRetries: -1}); err == nil {
		t.Errorf("negative retries: accepted: %q", args)
	}
}

// REQ-SCAN-022
func TestParseTimedOutHost(t *testing.T) {
	f, err := os.Open("testdata/timedout.xml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	hosts, err := Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	want := []Host{{Address: "127.0.0.1", Up: true, TimedOut: true}}
	if !reflect.DeepEqual(hosts, want) {
		t.Fatalf("hosts = %+v, want %+v", hosts, want)
	}
}
