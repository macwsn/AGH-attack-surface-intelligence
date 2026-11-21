//go:build integration

package web

import (
	"context"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"asi/internal/auth"
	"asi/internal/inventory"
	"asi/internal/scan"
	"asi/internal/scan/nmap"
	"asi/internal/scan/nmap/nmaptest"
	"asi/internal/scan/scantest"
	"asi/internal/schedule"
	"asi/internal/store"
	"asi/internal/store/storetest"
)

type browser struct {
	t    *testing.T
	base string
	c    *http.Client
	csrf string
}

func (b *browser) get(path string) (int, string) {
	b.t.Helper()
	resp, err := b.c.Get(b.base + path)
	if err != nil {
		b.t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if m := csrfInput.FindStringSubmatch(string(body)); m != nil {
		b.csrf = m[1]
	}
	return resp.StatusCode, string(body)
}

func (b *browser) post(path string, form url.Values) (int, string, string) {
	b.t.Helper()
	if form == nil {
		form = url.Values{}
	}
	form.Set("csrf_token", b.csrf)
	c := *b.c
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := c.PostForm(b.base+path, form)
	if err != nil {
		b.t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header.Get("Location"), string(body)
}

func signIn(t *testing.T, base, username, password string) *browser {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	b := &browser{t: t, base: base, c: &http.Client{Jar: jar}}
	b.get("/login")
	resp, err := b.c.PostForm(base+"/login", url.Values{"username": {username}, "password": {password}, "csrf_token": {b.csrf}})
	if err != nil {
		t.Fatalf("login %s: %v", username, err)
	}
	resp.Body.Close()
	if resp.Request.URL.Path != "/" {
		t.Fatalf("login %s ended at %s", username, resp.Request.URL)
	}
	b.get("/")
	return b
}

type scanEnv struct {
	mu    sync.Mutex
	block bool
	calls int
}

func (e *scanEnv) setBlock(v bool) {
	e.mu.Lock()
	e.block, e.calls = v, 0
	e.mu.Unlock()
}

var runPath = regexp.MustCompile(`^/runs/(\d+)\?msg=started$`)

// REQ-SCHEDULE-008
func TestScanPages(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st, err := store.Open(ctx, storetest.DatabaseURL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if _, err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	keys, err := store.NewKeyring(master)
	if err != nil {
		t.Fatal(err)
	}
	svc := auth.NewService(st, auth.Config{})
	cli := auth.Actor{Username: "test", Addr: "local"}
	for user, role := range map[string]string{"alice": auth.RoleAdmin, "eddie": auth.RoleEditor, "victor": auth.RoleViewer} {
		if err := svc.CreateUser(ctx, cli, user, user+"-password-123", role); err != nil {
			t.Fatal(err)
		}
	}
	clock := scantest.NewClock(time.Unix(0, 0))
	env := &scanEnv{}
	runner := &nmaptest.Runner{DiscoverFunc: func(ctx context.Context, _ []string, _ nmap.Options) ([]nmap.Host, error) {
		<-clock.After(2 * time.Second)
		env.mu.Lock()
		env.calls++
		hold := env.block && env.calls > 1
		env.mu.Unlock()
		if hold {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return nil, nil
	}}
	inv := inventory.New(st, keys)
	sched := &schedule.Scheduler{Store: schedule.NewStore(st), Scanner: &scan.Scanner{Store: inv, Runner: runner, Clock: clock}, Logf: t.Logf}
	sched.Start(ctx)
	t.Cleanup(sched.Wait)
	h, err := New(Deps{Store: st, Keyring: keys, Auth: svc, Scans: sched})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	alice := signIn(t, srv.URL, "alice", "alice-password-123")
	if code, body := alice.get("/scans"); code != 200 || !strings.Contains(body, "No scans yet.") || !strings.Contains(body, `href="/scans/new"`) {
		t.Fatalf("empty list = %d:\n%s", code, body)
	}
	code, body := alice.get("/scans/new")
	if code != 200 || !strings.Contains(body, `name="windows"`) || !strings.Contains(body, `name="timezone"`) || !strings.Contains(body, `name="max_rate"`) {
		t.Fatalf("new form = %d:\n%s", code, body)
	}
	form := url.Values{
		"name": {"campus"}, "targets": {"10.0.0.0/24\n# lab\n"}, "excludes": {"10.0.0.254"}, "ports": {"80,443"},
		"max_rate": {"50"}, "workers": {"1"}, "inactive_after": {"3"}, "signatures_dir": {""},
		"timezone": {"Europe/Warsaw"}, "windows": {"mon-fri 22:00-06:00"}, "frequency": {"daily"},
	}
	bad := url.Values{}
	for k, v := range form {
		bad[k] = v
	}
	bad.Set("ports", "80,99999")
	bad.Set("windows", "mon 25:00-06:00")
	bad.Set("timezone", "Mars/Olympus")
	code, _, body = alice.post("/scans", bad)
	if code != http.StatusUnprocessableEntity || !strings.Contains(body, `invalid port &#34;99999&#34;`) || !strings.Contains(body, "is not a time of day") ||
		!strings.Contains(body, `unknown timezone &#34;Mars/Olympus&#34;`) ||
		!strings.Contains(body, `aria-invalid="true"`) {
		t.Fatalf("invalid form = %d:\n%s", code, body)
	}
	code, loc, _ := alice.post("/scans", form)
	if code != http.StatusSeeOther || !strings.HasSuffix(loc, "?msg=created") {
		t.Fatalf("create = %d %s", code, loc)
	}
	scanPath := strings.TrimSuffix(loc, "?msg=created")
	if code, body := alice.get(loc); code != 200 || !strings.Contains(body, "Scan created.") || !strings.Contains(body, "Disabled") ||
		!strings.Contains(body, "mon-fri 22:00-06:00") || !strings.Contains(body, "10.0.0.0/24") || !strings.Contains(body, "80, 443") {
		t.Fatalf("scan page = %d:\n%s", code, body)
	}

	if code, loc, _ := alice.post(scanPath+"/enable", nil); code != http.StatusSeeOther || !strings.HasSuffix(loc, "msg=enabled") {
		t.Fatalf("enable = %d %s", code, loc)
	}
	if _, body := alice.get(scanPath); !strings.Contains(body, `<span class="status active">Enabled</span>`) && !strings.Contains(body, "Enabled.") {
		t.Fatalf("after enable:\n%s", body)
	}
	if code, _, _ := alice.post(scanPath+"/disable", nil); code != http.StatusSeeOther {
		t.Fatalf("disable = %d", code)
	}
	if _, body := alice.get("/scans"); !strings.Contains(body, `<span class="status inactive">Disabled</span>`) {
		t.Fatalf("list after disable:\n%s", body)
	}

	env.setBlock(true)
	code, loc, _ = alice.post(scanPath+"/start", nil)
	m := runPath.FindStringSubmatch(loc)
	if code != http.StatusSeeOther || m == nil {
		t.Fatalf("start = %d %s", code, loc)
	}
	runURL := "/runs/" + m[1]
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, body = alice.get(loc)
		if strings.Contains(body, `<td class="num">0</td>`) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("run page never showed a finished group:\n%s", body)
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, want := range []string{"Scan started.", "Running", "Pause run", "64 / 253", "25%", "Groups finished", "<td class=\"num\">2 s</td>",
		"Estimated time left", `<span class="value">6 s</span>`} {
		if !strings.Contains(body, want) {
			t.Errorf("run page lacks %q:\n%s", want, body)
		}
	}
	if code, _, _ := alice.post(scanPath+"/start", nil); code != http.StatusConflict {
		t.Errorf("second start = %d, want 409", code)
	}

	form.Set("ports", "8080")
	if _, body := alice.get(scanPath + "/edit"); !strings.Contains(body, "your changes apply from the next run") {
		t.Errorf("edit form during a run lacks the notice:\n%s", body)
	}
	if code, loc, _ := alice.post(scanPath, form); code != http.StatusSeeOther || !strings.HasSuffix(loc, "msg=saved") {
		t.Fatalf("update = %d %s", code, loc)
	}
	var target string
	if err := st.Pool.QueryRow(ctx, `SELECT target FROM audit_log WHERE actor = 'alice' AND action = 'scan.update'`).Scan(&target); err != nil || target != "campus: ports" {
		t.Errorf("audit of the edit = %q %v", target, err)
	}

	if code, loc, _ := alice.post(runURL+"/pause", nil); code != http.StatusSeeOther || !strings.HasSuffix(loc, "msg=paused") {
		t.Fatalf("pause = %d %s", code, loc)
	}
	if _, body := alice.get(runURL); !strings.Contains(body, "Paused by a user") || !strings.Contains(body, "Resume run") || strings.Contains(body, "Pause run") {
		t.Fatalf("run page after pause:\n%s", body)
	}
	env.setBlock(false)
	if code, _, _ := alice.post(runURL+"/resume", nil); code != http.StatusSeeOther {
		t.Fatalf("resume = %d", code)
	}
	deadline = time.Now().Add(10 * time.Second)
	for {
		_, body = alice.get(runURL)
		if strings.Contains(body, "Completed") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("run never completed:\n%s", body)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(body, "253 / 253") || !strings.Contains(body, "100%") || strings.Contains(body, "Resume run") {
		t.Errorf("completed run page:\n%s", body)
	}

	eddie := signIn(t, srv.URL, "eddie", "eddie-password-123")
	if code, body := eddie.get("/scans"); code != 200 || strings.Contains(body, `href="/scans/new"`) {
		t.Errorf("editor list = %d, new link shown: %v", code, strings.Contains(body, `href="/scans/new"`))
	}
	if code, body := eddie.get(scanPath); code != 200 || strings.Contains(body, "Edit scan") || !strings.Contains(body, "Start scan now") {
		t.Errorf("editor scan page = %d:\n%s", code, body)
	}
	for _, path := range []string{"/scans/new", scanPath + "/edit"} {
		if code, _ := eddie.get(path); code != http.StatusForbidden {
			t.Errorf("editor GET %s = %d, want 403", path, code)
		}
	}
	for _, path := range []string{"/scans", scanPath, scanPath + "/enable", scanPath + "/disable"} {
		if code, _, _ := eddie.post(path, form); code != http.StatusForbidden {
			t.Errorf("editor POST %s = %d, want 403", path, code)
		}
	}
	if code, _, _ := eddie.post(scanPath+"/start", nil); code != http.StatusSeeOther {
		t.Errorf("editor start = %d, want 303", code)
	}

	victor := signIn(t, srv.URL, "victor", "victor-password-123")
	for _, path := range []string{"/scans", scanPath, runURL} {
		if code, _ := victor.get(path); code != http.StatusForbidden {
			t.Errorf("viewer GET %s = %d, want 403", path, code)
		}
	}
	if code, _, _ := victor.post(runURL+"/pause", nil); code != http.StatusForbidden {
		t.Errorf("viewer pause = %d, want 403", code)
	}
}
