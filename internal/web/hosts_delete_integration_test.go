//go:build integration

package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"asi/internal/auth"
	"asi/internal/diff"
	"asi/internal/inventory"
)

func auditRows(t *testing.T, site inventorySite, action string) []string {
	t.Helper()
	rows, err := site.deps.Store.Pool.Query(context.Background(),
		`SELECT actor || ' ' || target || ' ' || address FROM audit_log WHERE action = $1 ORDER BY id`, action)
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

func hasService(t *testing.T, inv *inventory.Inventory, address string, port int) bool {
	t.Helper()
	d, err := inv.HostDetail(context.Background(), address)
	if err != nil {
		t.Fatalf("HostDetail %s: %v", address, err)
	}
	for _, s := range d.Host.Services {
		if s.Port == port {
			return true
		}
	}
	return false
}

// REQ-INVENTORY-028
func TestHostAndServiceDeleteByRole(t *testing.T) {
	ctx := context.Background()
	site := seedInventorySite(t)
	cases := []struct {
		role    string
		allowed bool
		host    string
		svcHost string
	}{
		{auth.RoleViewer, false, "10.0.1.1", "10.0.1.2"},
		{auth.RoleOperator, false, "10.0.1.1", "10.0.1.2"},
		{auth.RoleEditor, true, "10.0.1.3", "10.0.1.4"},
		{auth.RoleAdmin, true, "10.0.1.5", "10.0.1.6"},
	}
	for _, tc := range cases {
		t.Run(tc.role, func(t *testing.T) {
			cookie, csrf := site.cookies[tc.role], site.csrf[tc.role]
			user := tc.role + "-user"
			hostDel := "/hosts/" + tc.host + "/delete"
			svcDel := "/hosts/" + tc.svcHost + "/services/22/tcp/delete"

			page := do(site.handler, http.MethodGet, "/hosts/"+tc.svcHost, nil, cookie).Body.String()
			hasControls := strings.Contains(page, `href="/hosts/`+tc.svcHost+`/delete"`) &&
				strings.Contains(page, `href="/hosts/`+tc.svcHost+`/services/22/tcp/delete"`)
			if hasControls != tc.allowed || (!tc.allowed && strings.Contains(page, "/delete")) {
				t.Fatalf("delete controls shown = %v, want %v", hasControls, tc.allowed)
			}

			for _, path := range []string{hostDel, svcDel} {
				rec := do(site.handler, http.MethodGet, path, nil, cookie)
				if !tc.allowed {
					if rec.Code != http.StatusForbidden {
						t.Fatalf("GET %s = %d, want 403", path, rec.Code)
					}
					if rec := postForm(site.handler, path, url.Values{}, cookie, csrf); rec.Code != http.StatusForbidden {
						t.Fatalf("POST %s = %d, want 403", path, rec.Code)
					}
					continue
				}
				body := rec.Body.String()
				if rec.Code != http.StatusOK || !strings.Contains(body, `<form method="post" action="`+path+`">`) ||
					!strings.Contains(body, `<button class="danger" type="submit">Delete `) {
					t.Fatalf("confirmation %s = %d:\n%s", path, rec.Code, body)
				}
				checkPageIsSafe(t, "confirmation", body)
				if strings.Contains(body, "style=") {
					t.Fatal("confirmation page has an inline style")
				}
			}
			if _, err := site.inv.HostDetail(ctx, tc.host); err != nil {
				t.Fatalf("host %s gone before the confirmed POST: %v", tc.host, err)
			}
			if !hasService(t, site.inv, tc.svcHost, 22) {
				t.Fatalf("service gone before the confirmed POST")
			}
			if !tc.allowed {
				return
			}

			rec := postForm(site.handler, svcDel, url.Values{}, cookie, csrf)
			if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/hosts/"+tc.svcHost+"?deleted=22%2Ftcp" {
				t.Fatalf("POST %s = %d %q", svcDel, rec.Code, rec.Header().Get("Location"))
			}
			if hasService(t, site.inv, tc.svcHost, 22) {
				t.Fatal("service still there after delete")
			}
			if page := do(site.handler, http.MethodGet, rec.Header().Get("Location"), nil, cookie).Body.String(); !strings.Contains(page, "Service 22/tcp deleted.") {
				t.Fatal("host page lacks the service deleted notice")
			}

			rec = postForm(site.handler, hostDel, url.Values{}, cookie, csrf)
			if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/hosts/?deleted="+tc.host {
				t.Fatalf("POST %s = %d %q", hostDel, rec.Code, rec.Header().Get("Location"))
			}
			if _, err := site.inv.HostDetail(ctx, tc.host); !errors.Is(err, inventory.ErrUnknownHost) {
				t.Fatalf("host after delete: %v", err)
			}
			if list := do(site.handler, http.MethodGet, "/hosts/?deleted="+tc.host, nil, cookie).Body.String(); !strings.Contains(list,
				`<div class="notice ok" role="status">Host `+tc.host+` deleted.</div>`) {
				t.Fatal("hosts list lacks the host deleted notice")
			}
			if got := auditRows(t, site, "service.delete"); !containsString(got, user+" "+tc.svcHost+":22/tcp 192.0.2.1") {
				t.Fatalf("service.delete audit rows %q", got)
			}
			if got := auditRows(t, site, "host.delete"); !containsString(got, user+" "+tc.host+" 192.0.2.1") {
				t.Fatalf("host.delete audit rows %q", got)
			}
		})
	}
	if n := len(auditRows(t, site, "host.delete")); n != 2 {
		t.Fatalf("host.delete rows = %d, want one per permitted role", n)
	}
	if n := len(auditRows(t, site, "service.delete")); n != 2 {
		t.Fatalf("service.delete rows = %d, want one per permitted role", n)
	}

	editor, csrf := site.cookies[auth.RoleEditor], site.csrf[auth.RoleEditor]
	for _, path := range []string{"/hosts/10.0.9.9/delete", "/hosts/nope/delete", "/hosts/10.0.0.2/services/443/tcp/delete",
		"/hosts/10.0.0.2/services/abc/tcp/delete", "/hosts/10.0.1.3/delete"} {
		if rec := do(site.handler, http.MethodGet, path, nil, editor); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, rec.Code)
		}
		if rec := postForm(site.handler, path, url.Values{}, editor, csrf); rec.Code != http.StatusNotFound {
			t.Errorf("POST %s = %d, want 404", path, rec.Code)
		}
	}
	if rec := postForm(site.handler, "/hosts/10.0.0.2/delete", url.Values{}, editor, ""); rec.Code != http.StatusForbidden {
		t.Errorf("POST without CSRF = %d, want 403", rec.Code)
	}
	if n := len(auditRows(t, site, "host.delete")) + len(auditRows(t, site, "service.delete")); n != 4 {
		t.Fatalf("rejected deletes wrote audit rows: %d", n)
	}
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// REQ-INVENTORY-029
func TestDeletedHostIsNewInTheNextRun(t *testing.T) {
	ctx := context.Background()
	site := seedInventorySite(t)
	const host = "10.0.0.2"
	if rec := postForm(site.handler, "/hosts/"+host+"/delete", url.Values{}, site.cookies[auth.RoleEditor], site.csrf[auth.RoleEditor]); rec.Code != http.StatusSeeOther {
		t.Fatalf("delete = %d", rec.Code)
	}
	run, err := site.inv.CreateRun(ctx, inventory.RunSpec{Name: "l4", InactiveAfter: 2})
	if err != nil {
		t.Fatal(err)
	}
	if err := site.inv.RecordGroup(ctx, run.ID, inventory.GroupResult{Index: 0, Addresses: []string{host},
		Hosts: []inventory.HostResult{{Address: host, Services: []inventory.ServiceResult{{Port: 22, Protocol: "tcp", State: "open", Service: "ssh"}}}}}); err != nil {
		t.Fatal(err)
	}
	from, err := site.inv.Export(ctx, "l3")
	if err != nil {
		t.Fatal(err)
	}
	to, err := site.inv.Export(ctx, "l4")
	if err != nil {
		t.Fatal(err)
	}
	var types []string
	for _, c := range diff.Compute(from, to, diff.Options{}).Changes {
		if c.Address == host {
			types = append(types, c.Type)
		}
	}
	if len(types) != 1 || types[0] != diff.HostNew {
		t.Fatalf("changes for the returned host = %v, want only %s", types, diff.HostNew)
	}
	d, err := site.inv.HostDetail(ctx, host)
	if err != nil {
		t.Fatal(err)
	}
	if d.Run != "l4" || len(d.History) == 0 {
		t.Fatalf("host detail run %q history %d", d.Run, len(d.History))
	}
	for _, h := range d.History {
		if h.Run != "l4" && h.Seen {
			t.Fatalf("returned host keeps history of the deleted one: %+v", d.History)
		}
	}
	page := do(site.handler, http.MethodGet, "/hosts/"+host, nil, site.cookies[auth.RoleViewer]).Body.String()
	if !strings.Contains(page, "<dt>First seen</dt><dd>"+isoTime(d.Host.FirstSeen)+"</dd>") {
		t.Fatalf("host page first seen is not the new run's time")
	}
}

// REQ-WEB-053
func TestHostDeleteConfirmationNeedsInventoryRead(t *testing.T) {
	e := newLeakEnv(t)
	for _, addr := range []string{auditHost, "10.9.9.9"} {
		for _, path := range []string{"/hosts/" + addr + "/delete", "/hosts/" + addr + "/services/22/tcp/delete"} {
			code, body := e.get("deleter", path)
			if code != http.StatusForbidden || strings.Contains(body, "services, its history") || strings.Contains(body, "ssh") || strings.Contains(body, auditTitle) {
				t.Errorf("GET %s as inventory.delete only = %d, want 403 without host data", path, code)
			}
		}
	}
	for _, path := range []string{"/hosts/" + auditHost + "/delete", "/hosts/" + auditHost + "/services/22/tcp/delete"} {
		if code, body := e.get(auth.RoleEditor, path); code != http.StatusOK || !strings.Contains(body, auditHost) {
			t.Errorf("GET %s as editor = %d, want the confirmation page", path, code)
		}
	}
	if code, loc, _ := e.post("deleter", "/hosts/"+auditHost+"/services/22/tcp/delete", url.Values{}); code != http.StatusSeeOther || !strings.HasPrefix(loc, "/hosts/"+auditHost+"?deleted=") {
		t.Errorf("POST service delete as inventory.delete only = %d %q, want 303", code, loc)
	}
	if code, loc, _ := e.post("deleter", "/hosts/"+auditHost+"/delete", url.Values{}); code != http.StatusSeeOther || !strings.HasPrefix(loc, "/hosts/?deleted=") {
		t.Errorf("POST host delete as inventory.delete only = %d %q, want 303", code, loc)
	}
}
