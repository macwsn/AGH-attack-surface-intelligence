//go:build integration

package web

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"asi/internal/auth"
	"asi/internal/inventory"
	"asi/internal/probe"
	"asi/internal/store"
	"asi/internal/store/storetest"
)

// REQ-WEB-016
func TestHostPageResponseTimes(t *testing.T) {
	ctx := context.Background()
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
	if err := svc.CreateUser(ctx, auth.Actor{Username: "test", Addr: "local"}, "victor", "victor-password-123", auth.RoleViewer); err != nil {
		t.Fatal(err)
	}
	inv := inventory.New(st, keys)
	const addr = "10.1.0.5"
	steady := []int64{100, 110, 90, 105, 95, 100, 120, 100, 100, 80, 1200}
	for i, ms := range steady {
		r, err := inv.CreateRun(ctx, inventory.RunSpec{Name: fmt.Sprintf("h-%d", i)})
		if err != nil {
			t.Fatal(err)
		}
		services := []inventory.ServiceResult{
			{Port: 80, Protocol: "tcp", State: "open", Service: "http", HTTP: &probe.HTTP{Scheme: "http", URL: "http://10.1.0.5/", StatusCode: 200, ResponseMS: ms}},
			{Port: 8443, Protocol: "tcp", State: "open", Service: "https", HTTP: &probe.HTTP{Scheme: "https", URL: "https://10.1.0.5:8443/", StatusCode: 200, ResponseMS: 700}},
		}
		if i == len(steady)-1 {
			services = append(services, inventory.ServiceResult{Port: 8085, Protocol: "tcp", State: "open", Service: "http",
				HTTP: &probe.HTTP{Scheme: "http", URL: "http://10.1.0.5:8085/", ResponseMS: 10000, Error: probe.ErrorTimeout}})
		}
		if err := inv.RecordGroup(ctx, r.ID, inventory.GroupResult{Index: 0, Addresses: []string{addr}, Hosts: []inventory.HostResult{{Address: addr, Services: services}}}); err != nil {
			t.Fatal(err)
		}
	}
	h, err := New(Deps{Store: st, Keyring: keys, Auth: svc})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	victor := signIn(t, srv.URL, "victor", "victor-password-123")

	code, body := victor.get("/hosts/" + addr)
	if code != http.StatusOK {
		t.Fatalf("host page = %d:\n%s", code, body)
	}
	rows := regexp.MustCompile(`(?s)<tr><td class="num addr">(\d+)/tcp</td>.*?</tr>`).FindAllStringSubmatch(body, -1)
	got := map[string]string{}
	for _, m := range rows {
		got[m[1]] = m[0]
	}
	for port, want := range map[string][]string{
		"80":   {`<td class="num">1200 ms</td>`, `<td class="num">100 ms</td>`, `<td class="num">10</td>`, `<span class="kind slow">Slower than usual</span>`},
		"8443": {`<td class="num">700 ms</td>`, `<td class="num">700 ms</td>`},
		"8085": {`<td class="num">10000 ms</td>`, `<td class="num">1</td>`, `<span class="kind timeout">Timed out</span>`},
	} {
		row, ok := got[port]
		if !ok {
			t.Fatalf("no row for port %s:\n%s", port, body)
		}
		for _, w := range want {
			if !strings.Contains(row, w) {
				t.Errorf("port %s row lacks %s:\n%s", port, w, row)
			}
		}
	}
	if strings.Contains(got["8443"], "Slower than usual") {
		t.Errorf("steady 700 ms service marked slower than usual:\n%s", got["8443"])
	}
	if strings.Contains(got["8085"], "Slower than usual") {
		t.Errorf("first measurement marked slower than usual:\n%s", got["8085"])
	}

	if code, _ := victor.get("/hosts/10.1.0.99"); code != http.StatusNotFound {
		t.Errorf("unknown host = %d", code)
	}
}
