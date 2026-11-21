//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"asi/internal/diff"
	"asi/internal/inventory"
	"asi/internal/scan/nmap"
	"asi/internal/scan/nmap/nmaptest"
	"asi/internal/scan/scantest"
	"asi/internal/store"
	"asi/internal/store/storetest"
)

type fakeNet struct {
	mu     sync.Mutex
	ports  map[string][]int
	titles map[string]string
}

func (n *fakeNet) up(addr string, ports ...int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.ports[addr] = ports
}

func (n *fakeNet) down(addr string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.ports, addr)
}

func (n *fakeNet) title(addr, title string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.titles[addr] = title
}

func (n *fakeNet) runner() *nmaptest.Runner {
	return &nmaptest.Runner{
		DiscoverFunc: func(_ context.Context, addrs []string, _ nmap.Options) ([]nmap.Host, error) {
			n.mu.Lock()
			defer n.mu.Unlock()
			var out []nmap.Host
			for _, a := range addrs {
				if _, ok := n.ports[a]; ok {
					out = append(out, nmap.Host{Address: a, Up: true})
				}
			}
			return out, nil
		},
		ServicesFunc: func(_ context.Context, addrs []string, ports []int, _ nmap.Options) ([]nmap.Host, error) {
			n.mu.Lock()
			defer n.mu.Unlock()
			var out []nmap.Host
			for _, a := range addrs {
				open, ok := n.ports[a]
				if !ok {
					continue
				}
				h := nmap.Host{Address: a, Up: true}
				for _, p := range open {
					if slices.Contains(ports, p) {
						h.Ports = append(h.Ports, nmap.Port{Number: p, Protocol: "tcp", State: "open", Service: "http"})
					}
				}
				out = append(out, h)
			}
			return out, nil
		},
	}
}

func (n *fakeNet) handler(w http.ResponseWriter, r *http.Request) {
	host := scantest.Target(r)
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	n.mu.Lock()
	title, ok := n.titles[host]
	n.mu.Unlock()
	if !ok {
		title = "ok " + host
	}
	fmt.Fprintf(w, "<html><title>%s</title></html>", title)
}

type cliEnv struct {
	t        *testing.T
	env      map[string]string
	st       *store.Store
	inv      *inventory.Inventory
	net      *fakeNet
	dir      string
	targets  string
	excludes string
}

func newCLIEnv(t *testing.T, targets, excludes string) *cliEnv {
	t.Helper()
	ctx := context.Background()
	dbURL := storetest.DatabaseURL(t)
	env := map[string]string{"ASI_DATABASE_URL": dbURL, "ASI_MASTER_KEY": testKey}
	if code, _, stderr := runCLI(env, "migrate"); code != 0 {
		t.Fatalf("migrate: exit %d, stderr %q", code, stderr)
	}
	st, err := store.Open(ctx, dbURL)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(st.Close)
	raw, err := base64.StdEncoding.DecodeString(testKey)
	if err != nil {
		t.Fatal(err)
	}
	key, err := store.NewKeyring(raw)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	c := &cliEnv{
		t: t, env: env, st: st, inv: inventory.New(st, key), dir: dir,
		net:      &fakeNet{ports: map[string][]int{}, titles: map[string]string{}},
		targets:  filepath.Join(dir, "targets.txt"),
		excludes: filepath.Join(dir, "exclude.txt"),
	}
	if err := os.WriteFile(c.targets, []byte("# lab\n"+targets+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.excludes, []byte(excludes+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return c
}

func (c *cliEnv) runCtx(ctx context.Context, r *nmaptest.Runner, args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	tr := &scantest.Transport{Handler: http.HandlerFunc(c.net.handler)}
	code := runWith(ctx, scanDeps{runner: r, transport: tr.For}, args, strings.NewReader(""), &stdout, &stderr, func(k string) string { return c.env[k] })
	return code, stdout.String(), stderr.String()
}

func (c *cliEnv) run(args ...string) (int, string, string) {
	return c.runCtx(context.Background(), c.net.runner(), args...)
}

func (c *cliEnv) mustRun(args ...string) string {
	c.t.Helper()
	code, stdout, stderr := c.run(args...)
	if code != 0 {
		c.t.Fatalf("%v: exit %d, stderr %q", args, code, stderr)
	}
	return stdout
}

func (c *cliEnv) scanArgs(name string, extra ...string) []string {
	return append([]string{"scan", "run", "--targets-file", c.targets, "--exclude-file", c.excludes,
		"--ports", "22,80", "--name", name, "--wait"}, extra...)
}

func (c *cliEnv) scan(name string, extra ...string) {
	c.t.Helper()
	c.mustRun(c.scanArgs(name, extra...)...)
}

func (c *cliEnv) export(run string) inventory.Export {
	c.t.Helper()
	out := filepath.Join(c.dir, "export-"+run+".json")
	args := []string{"export", "--format", "json", "--out", out}
	if run != "" {
		args = append(args, "--run", run)
	}
	c.mustRun(args...)
	data, err := os.ReadFile(out)
	if err != nil {
		c.t.Fatal(err)
	}
	var exp inventory.Export
	if err := json.Unmarshal(data, &exp); err != nil {
		c.t.Fatalf("decode export: %v\n%s", err, data)
	}
	return exp
}

func hostByAddr(exp inventory.Export, addr string) (inventory.ExportHost, bool) {
	for _, h := range exp.Hosts {
		if h.Address == addr {
			return h, true
		}
	}
	return inventory.ExportHost{}, false
}

func assertOneLineError(t *testing.T, what string, code int, stderr string, wants ...string) {
	t.Helper()
	if code != 1 || strings.Count(stderr, "\n") != 1 || !strings.HasSuffix(stderr, "\n") {
		t.Fatalf("%s: exit %d, stderr %q; want 1 and one line", what, code, stderr)
	}
	for _, w := range wants {
		if !strings.Contains(stderr, w) {
			t.Fatalf("%s: stderr %q does not contain %q", what, stderr, w)
		}
	}
}

func assertNoFile(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s exists (err %v)", path, err)
	}
}

func countRuns(t *testing.T, st *store.Store) int {
	t.Helper()
	var n int
	if err := st.Pool.QueryRow(context.Background(), `SELECT count(*) FROM runs`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestScanRun(t *testing.T) {
	ctx := context.Background()
	c := newCLIEnv(t, "192.0.2.0/29", "192.0.2.0\n192.0.2.7")
	c.net.up("192.0.2.1", 80)
	c.net.up("192.0.2.2", 22, 80, 8080)
	c.net.up("192.0.2.7", 80)
	r := c.net.runner()
	code, stdout, stderr := c.runCtx(ctx, r, c.scanArgs("s1")...)
	if code != 0 || !strings.HasPrefix(stdout, "run s1 status=completed ") {
		t.Fatalf("scan run: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}

	run, err := c.inv.RunByName(ctx, "s1")
	if err != nil {
		t.Fatal(err)
	}
	want := inventory.RunSettings{
		Targets: []string{"192.0.2.0/29"}, Excludes: []string{"192.0.2.0", "192.0.2.7"},
		Ports: []int{22, 80}, MaxRate: 100, Workers: 4,
	}
	if run.Status != inventory.RunCompleted || run.InactiveAfter != 3 || !reflect.DeepEqual(run.Settings, want) {
		t.Fatalf("run = %+v, want completed, inactive-after 3, settings %+v", run, want)
	}
	for _, call := range r.Calls() {
		if call.Opts.MaxRate < 1 || call.Opts.MaxRate > 100 {
			t.Fatalf("%s max rate %d", call.Method, call.Opts.MaxRate)
		}
		if slices.Contains(call.Addrs, "192.0.2.7") || slices.Contains(call.Addrs, "192.0.2.0") {
			t.Fatalf("%s contacted an excluded address: %v", call.Method, call.Addrs)
		}
	}
	exp := c.export("")
	if exp.Run != "s1" || len(exp.Hosts) != 2 {
		t.Fatalf("export = %+v", exp)
	}
	if h, _ := hostByAddr(exp, "192.0.2.2"); len(h.Services) != 2 || h.Services[0].Port != 22 || h.Services[1].Port != 80 {
		t.Fatalf("192.0.2.2 services = %+v", h.Services)
	}

	r2 := c.net.runner()
	code, stdout, stderr = c.runCtx(ctx, r2, c.scanArgs("s1", "--workers", "2")...)
	assertOneLineError(t, "duplicate name", code, stderr, "already exists", "s1")
	if stdout != "" || len(r2.Calls()) != 0 || countRuns(t, c.st) != 1 {
		t.Fatalf("duplicate name: stdout %q, calls %d, runs %d", stdout, len(r2.Calls()), countRuns(t, c.st))
	}

	failing := &nmaptest.Runner{DiscoverFunc: func(context.Context, []string, nmap.Options) ([]nmap.Host, error) {
		return nil, errors.New("nmap exploded")
	}}
	code, _, stderr = c.runCtx(ctx, failing, c.scanArgs("s2", "--inactive-after", "5", "--max-rate", "7", "--workers", "1")...)
	assertOneLineError(t, "failing nmap", code, stderr, "nmap exploded")
	run, err = c.inv.RunByName(ctx, "s2")
	if err != nil || run.Status != inventory.RunFailed || run.InactiveAfter != 5 || run.Settings.MaxRate != 7 || run.Settings.Workers != 1 {
		t.Fatalf("failed run = %+v, %v", run, err)
	}
}

var groupLine = regexp.MustCompile(`^group=(\d+) addresses=(\d+) hosts=(\d+) duration=(\S+)$`)

type shownGroup struct{ index, addrs, hosts int }

func showRun(t *testing.T, c *cliEnv, name string) (string, []shownGroup) {
	t.Helper()
	stdout := c.mustRun("scan", "show", name)
	lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
	var groups []shownGroup
	for _, l := range lines[1:] {
		m := groupLine.FindStringSubmatch(l)
		if m == nil {
			t.Fatalf("group line %q does not match", l)
		}
		if d, err := time.ParseDuration(m[4]); err != nil || d < 0 {
			t.Fatalf("duration %q: %v", m[4], err)
		}
		i, _ := strconv.Atoi(m[1])
		a, _ := strconv.Atoi(m[2])
		h, _ := strconv.Atoi(m[3])
		if len(groups) > 0 && i <= groups[len(groups)-1].index {
			t.Fatalf("groups not ordered by index:\n%s", stdout)
		}
		groups = append(groups, shownGroup{i, a, h})
	}
	return lines[0], groups
}

func TestScanShow(t *testing.T) {
	c := newCLIEnv(t, "192.0.2.0/25", "192.0.2.0")
	c.net.up("192.0.2.1", 80)
	c.net.up("192.0.2.100", 22)
	c.scan("big", "--workers", "2")

	first, groups := showRun(t, c, "big")
	if !strings.HasPrefix(first, "run big status=completed ") {
		t.Fatalf("first line %q", first)
	}
	addrs, hosts := 0, 0
	for _, g := range groups {
		addrs += g.addrs
		hosts += g.hosts
	}
	if len(groups) < 2 || addrs != 126 || hosts != 2 {
		t.Fatalf("groups %+v: %d addresses, %d hosts; want >= 2 groups, 126 addresses (network, broadcast and one exclude dropped), 2 hosts", groups, addrs, hosts)
	}

	code, stdout, stderr := c.run("scan", "show", "nope")
	assertOneLineError(t, "show unknown", code, stderr, "unknown run", "nope")
	if stdout != "" {
		t.Fatalf("show unknown: stdout %q", stdout)
	}
}

func TestScanResume(t *testing.T) {
	ctx := context.Background()
	c := newCLIEnv(t, "192.0.2.0/25", "192.0.2.0")
	c.net.up("192.0.2.1", 80)
	c.net.up("192.0.2.100", 80)

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	first := c.net.runner()
	inner := first.DiscoverFunc
	var discovers int
	var mu sync.Mutex
	first.DiscoverFunc = func(ctx context.Context, addrs []string, opts nmap.Options) ([]nmap.Host, error) {
		mu.Lock()
		discovers++
		n := discovers
		mu.Unlock()
		if n >= 2 {
			cancel()
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return inner(ctx, addrs, opts)
	}
	code, _, stderr := c.runCtx(runCtx, first, c.scanArgs("res", "--workers", "1", "--max-rate", "50", "--inactive-after", "2")...)
	assertOneLineError(t, "interrupted run", code, stderr, "paused")

	head, groups := showRun(t, c, "res")
	if !strings.HasPrefix(head, "run res status=paused ") || len(groups) != 1 || groups[0].index != 0 {
		t.Fatalf("after pause: %q %+v", head, groups)
	}
	run, err := c.inv.RunByName(ctx, "res")
	if err != nil {
		t.Fatal(err)
	}
	recorded, err := c.inv.RunGroups(ctx, run.ID)
	if err != nil || len(recorded) != 1 {
		t.Fatalf("groups = %+v, %v", recorded, err)
	}
	done := recorded[0].Addresses

	second := c.net.runner()
	code, stdout, stderr := c.runCtx(ctx, second, "scan", "resume", "res")
	if code != 0 || !strings.HasPrefix(stdout, "run res status=completed ") {
		t.Fatalf("resume: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	calls := second.Calls()
	if len(calls) == 0 {
		t.Fatal("resume made no nmap calls")
	}
	for _, call := range calls {
		for _, a := range call.Addrs {
			if slices.Contains(done, a) {
				t.Fatalf("resume rescanned %s of a finished group", a)
			}
		}
		if call.Opts.MaxRate != 25 || !slices.Equal(call.Opts.ProbePorts, []int{22, 80}) {
			t.Fatalf("resume did not use the stored settings: %+v", call)
		}
		if call.Method == "Services" && !slices.Equal(call.Ports, []int{22, 80}) {
			t.Fatalf("resume services ports %v", call.Ports)
		}
	}
	head, groups = showRun(t, c, "res")
	addrs := 0
	for _, g := range groups {
		addrs += g.addrs
	}
	if !strings.HasPrefix(head, "run res status=completed ") || addrs != 126 {
		t.Fatalf("after resume: %q %+v", head, groups)
	}
	exp := c.export("res")
	for _, a := range []string{"192.0.2.1", "192.0.2.100"} {
		if h, ok := hostByAddr(exp, a); !ok || h.Status != inventory.StatusActive || len(h.Services) != 1 {
			t.Fatalf("host %s after resume = %+v", a, h)
		}
	}

	third := c.net.runner()
	code, _, stderr = c.runCtx(ctx, third, "scan", "resume", "res")
	assertOneLineError(t, "resume completed", code, stderr, "already completed")
	if len(third.Calls()) != 0 {
		t.Fatalf("resume of a completed run called nmap")
	}

	code, _, stderr = c.run("scan", "resume", "nope")
	assertOneLineError(t, "resume unknown", code, stderr, "unknown run", "nope")
}

func TestScanResumeAfterSignal(t *testing.T) {
	bin := buildBinary(t)
	c := newCLIEnv(t, "192.0.2.0/29", "")
	fakeDir := t.TempDir()
	started := filepath.Join(fakeDir, "started")
	script := "#!/bin/sh\ntouch \"$FAKE_NMAP_STARTED\"\nexec sleep 60\n"
	if err := os.WriteFile(filepath.Join(fakeDir, "nmap"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, sig := range []os.Signal{os.Interrupt, syscall.SIGTERM} {
		name := "sig-" + strings.ReplaceAll(sig.String(), " ", "-")
		os.Remove(started)
		cmd := exec.Command(bin, c.scanArgs(name)...)
		cmd.Env = append(os.Environ(), "PATH="+fakeDir+string(os.PathListSeparator)+os.Getenv("PATH"),
			"ASI_DATABASE_URL="+c.env["ASI_DATABASE_URL"], "ASI_MASTER_KEY="+testKey, "FAKE_NMAP_STARTED="+started)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(15 * time.Second)
		for {
			if _, err := os.Stat(started); err == nil {
				break
			}
			if time.Now().After(deadline) {
				cmd.Process.Kill()
				t.Fatalf("%s: fake nmap never started; stderr %q", name, stderr.String())
			}
			time.Sleep(50 * time.Millisecond)
		}
		if err := cmd.Process.Signal(sig); err != nil {
			t.Fatal(err)
		}
		waitErr := make(chan error, 1)
		go func() { waitErr <- cmd.Wait() }()
		select {
		case err := <-waitErr:
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() == 0 {
				t.Fatalf("%s: wait = %v, want non-zero exit", name, err)
			}
		case <-time.After(20 * time.Second):
			cmd.Process.Kill()
			t.Fatalf("%s: asi did not stop", name)
		}
		head, _ := showRun(t, c, name)
		if !strings.HasPrefix(head, "run "+name+" status=paused ") {
			t.Fatalf("%s: %q, stderr %q", name, head, stderr.String())
		}
	}
}

func TestExport(t *testing.T) {
	c := newCLIEnv(t, "192.0.2.0/29", "192.0.2.0")
	c.net.up("192.0.2.1", 80)
	c.net.up("192.0.2.2", 80)
	c.scan("e1")
	c.net.down("192.0.2.2")
	c.net.up("192.0.2.3", 22)
	c.scan("e2")

	latest := c.export("")
	if latest.Schema != "asi.export/v1" || latest.Run != "e2" {
		t.Fatalf("latest export: schema %q run %q", latest.Schema, latest.Run)
	}
	if h, ok := hostByAddr(latest, "192.0.2.2"); !ok || h.Status != inventory.StatusUnstable || h.MissedRuns != 1 {
		t.Fatalf("192.0.2.2 in latest = %+v", h)
	}
	if h, ok := hostByAddr(latest, "192.0.2.3"); !ok || h.Status != inventory.StatusActive {
		t.Fatalf("192.0.2.3 in latest = %+v", h)
	}

	old := c.export("e1")
	if old.Run != "e1" || len(old.Hosts) != 2 {
		t.Fatalf("export as of e1 = %+v", old)
	}
	if h, ok := hostByAddr(old, "192.0.2.2"); !ok || h.Status != inventory.StatusActive {
		t.Fatalf("192.0.2.2 as of e1 = %+v", h)
	}

	out := filepath.Join(c.dir, "never.json")
	code, stdout, stderr := c.run("export", "--format", "json", "--out", out, "--run", "nope")
	assertOneLineError(t, "unknown run", code, stderr, "unknown run", "nope")
	if stdout != "" {
		t.Fatalf("stdout %q", stdout)
	}
	assertNoFile(t, out)

	code, _, _ = c.run("export", "--format", "xml", "--out", out)
	if code == 0 {
		t.Fatal("--format xml exited 0")
	}
	assertNoFile(t, out)
	for _, args := range [][]string{{"export", "--out", out}, {"export", "--format", "json"}} {
		code, _, stderr := c.run(args...)
		if code != 2 {
			t.Fatalf("%v: exit %d", args, code)
		}
		assertUsage(t, stderr)
	}
	assertNoFile(t, out)
}

func TestExportCSV(t *testing.T) {
	c := newCLIEnv(t, "192.0.2.0/29", "192.0.2.0")
	c.net.up("192.0.2.1", 22, 80)
	c.net.title("192.0.2.1", `Hello, "world"`)
	c.net.up("192.0.2.4")
	c.scan("c1")
	c.mustRun("host", "edit", "192.0.2.1", "--add-tag", "a", "--add-tag", "b,c")

	for _, run := range []string{"", "c1"} {
		out := filepath.Join(c.dir, "export"+run+".csv")
		args := []string{"export", "--format", "csv", "--out", out}
		if run != "" {
			args = append(args, "--run", run)
		}
		c.mustRun(args...)
		f, err := os.Open(out)
		if err != nil {
			t.Fatal(err)
		}
		records, err := csv.NewReader(f).ReadAll()
		f.Close()
		if err != nil {
			t.Fatalf("parse csv: %v", err)
		}
		header := records[0]
		for _, col := range []string{"address", "hostnames", "status", "port", "protocol", "service", "product", "version",
			"scheme", "status_code", "title", "technologies", "findings", "tags", "first_seen", "last_seen"} {
			if !slices.Contains(header, col) {
				t.Fatalf("header %v lacks %q", header, col)
			}
		}
		rows := map[string]map[string]string{}
		for _, rec := range records[1:] {
			row := map[string]string{}
			for i, col := range header {
				row[col] = rec[i]
			}
			rows[row["address"]+"/"+row["port"]] = row
		}
		if len(rows) != 3 {
			t.Fatalf("rows = %v, want 3 (two services, one host without services)", rows)
		}
		bare := rows["192.0.2.4/"]
		if bare == nil || bare["protocol"] != "" || bare["service"] != "" || bare["status"] != "active" {
			t.Fatalf("host without services row = %v", bare)
		}
		web := rows["192.0.2.1/80"]
		if web == nil || web["protocol"] != "tcp" || web["service"] != "http" || web["status"] != "active" ||
			web["title"] != `Hello, "world"` || web["tags"] != "a;b,c" {
			t.Fatalf("192.0.2.1/80 row = %v", web)
		}
		if _, err := time.Parse(time.RFC3339, web["first_seen"]); err != nil {
			t.Fatalf("first_seen %q: %v", web["first_seen"], err)
		}
		if py, err := exec.LookPath("python3"); err == nil {
			script := `import csv,sys
rows=list(csv.DictReader(open(sys.argv[1],newline="")))
need={"address","port","protocol","service","status"}
assert rows and need<=set(rows[0].keys()), rows
print(len(rows))`
			got, err := exec.Command(py, "-I", "-c", script, out).CombinedOutput()
			if err != nil || strings.TrimSpace(string(got)) != "3" {
				t.Fatalf("python csv.DictReader: %v\n%s", err, got)
			}
		}
	}
}

func TestDiff(t *testing.T) {
	ctx := context.Background()
	c := newCLIEnv(t, "192.0.2.0/29", "192.0.2.0")
	c.net.up("192.0.2.1", 80)
	c.net.up("192.0.2.2", 80)
	c.net.title("192.0.2.1", "Intranet v1")
	c.scan("d1")
	c.net.down("192.0.2.2")
	c.net.up("192.0.2.3", 80)
	c.net.title("192.0.2.1", "Intranet v2")
	c.scan("d2")

	out := filepath.Join(c.dir, "diff.json")
	c.mustRun("diff", "--from", "d1", "--to", "d2", "--format", "json", "--out", out)
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	from, err := c.inv.Export(ctx, "d1")
	if err != nil {
		t.Fatal(err)
	}
	to, err := c.inv.Export(ctx, "d2")
	if err != nil {
		t.Fatal(err)
	}
	want, err := json.Marshal(diff.Compute(from, to, diff.Options{}))
	if err != nil {
		t.Fatal(err)
	}
	var gotDoc, wantDoc map[string]any
	if err := json.Unmarshal(got, &gotDoc); err != nil {
		t.Fatalf("decode diff: %v\n%s", err, got)
	}
	if err := json.Unmarshal(want, &wantDoc); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotDoc, wantDoc) {
		t.Fatalf("diff = %s\nwant %s", got, want)
	}
	if gotDoc["schema"] != "asi.diff/v1" || gotDoc["from"] != "d1" || gotDoc["to"] != "d2" || len(gotDoc["changes"].([]any)) < 3 {
		t.Fatalf("diff = %s", got)
	}

	same := filepath.Join(c.dir, "same.json")
	c.mustRun("diff", "--from", "d1", "--to", "d1", "--format", "json", "--out", same)
	raw, err := os.ReadFile(same)
	if err != nil {
		t.Fatal(err)
	}
	var sameDoc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &sameDoc); err != nil || string(sameDoc["changes"]) != "[]" {
		t.Fatalf("same-run diff = %s (%v)", raw, err)
	}

	never := filepath.Join(c.dir, "never.json")
	for _, args := range [][]string{
		{"diff", "--from", "nope", "--to", "d2", "--format", "json", "--out", never},
		{"diff", "--from", "d1", "--to", "nope", "--format", "json", "--out", never},
	} {
		code, _, stderr := c.run(args...)
		assertOneLineError(t, strings.Join(args, " "), code, stderr, "unknown run", "nope")
		assertNoFile(t, never)
	}
	if code, _, _ := c.run("diff", "--from", "d1", "--to", "d2", "--format", "csv", "--out", never); code == 0 {
		t.Fatal("--format csv exited 0")
	}
	assertNoFile(t, never)
	for _, args := range [][]string{
		{"diff", "--to", "d2", "--format", "json", "--out", never},
		{"diff", "--from", "d1", "--format", "json", "--out", never},
		{"diff", "--from", "d1", "--to", "d2", "--format", "json"},
	} {
		code, _, stderr := c.run(args...)
		if code != 2 {
			t.Fatalf("%v: exit %d", args, code)
		}
		assertUsage(t, stderr)
	}
	assertNoFile(t, never)
}

func TestHostEdit(t *testing.T) {
	ctx := context.Background()
	c := newCLIEnv(t, "192.0.2.0/29", "192.0.2.0")
	c.net.up("192.0.2.1", 80)
	c.scan("h1")
	if err := c.inv.UpdateHostUserFields(ctx, "192.0.2.1", inventory.HostUserFields{Tags: []string{"keep"}, Owner: "web team"}); err != nil {
		t.Fatal(err)
	}

	check := func(what string, tags []string, notes string) {
		t.Helper()
		h, ok := hostByAddr(c.export(""), "192.0.2.1")
		if !ok || !slices.Equal(h.Tags, tags) || h.Notes != notes || h.Owner != "web team" {
			t.Fatalf("%s: host = tags %v notes %q owner %q; want tags %v notes %q", what, h.Tags, h.Notes, h.Owner, tags, notes)
		}
	}

	c.mustRun("host", "edit", "192.0.2.1", "--add-tag", "a", "--add-tag", "b", "--add-tag", "keep", "--notes", "first note")
	check("add", []string{"keep", "a", "b"}, "first note")
	c.mustRun("host", "edit", "--add-tag", "a", "--add-tag", "c", "192.0.2.1", "--remove-tag", "b")
	check("add and remove", []string{"keep", "a", "c"}, "first note")
	c.mustRun("host", "edit", "192.0.2.1", "--notes", "")
	check("clear notes", []string{"keep", "a", "c"}, "")
	c.mustRun("host", "edit", "192.0.2.1", "--notes", "owned by web team")
	c.scan("h2")
	check("after a later scan", []string{"keep", "a", "c"}, "owned by web team")

	code, stdout, stderr := c.run("host", "edit", "192.0.2.99", "--add-tag", "x")
	assertOneLineError(t, "unknown host", code, stderr, "unknown host", "192.0.2.99")
	if stdout != "" {
		t.Fatalf("stdout %q", stdout)
	}
	if code, _, _ := c.run("host", "edit", "nope", "--add-tag", "x"); code == 0 {
		t.Fatal("invalid address exited 0")
	}
	code, _, stderr = c.run("host", "edit", "--add-tag", "x")
	if code != 2 {
		t.Fatalf("missing address: exit %d", code)
	}
	assertUsage(t, stderr)
	check("after failed edits", []string{"keep", "a", "c"}, "owned by web team")
}
