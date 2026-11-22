//go:build integration

package web

import (
	"context"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"asi/internal/auth"
)

// REQ-WEB-023
func TestViewerCannotChangeInventoryPages(t *testing.T) {
	ctx := context.Background()
	site := seedInventorySite(t)
	const host = "10.0.0.2"
	r, err := build(site.deps, files, []Feature{RegisterDashboard, RegisterInventory})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	bodies := map[string]func() url.Values{
		"POST /hosts/{address}": editForm,
	}
	targets := map[string]string{"{address}": host}

	var changing []Route
	for _, rt := range r.Routes() {
		if rt.Method != http.MethodGet && rt.Method != http.MethodHead {
			changing = append(changing, rt)
		}
	}
	if len(changing) == 0 {
		t.Fatal("the inventory and dashboard features register no state-changing route")
	}
	for _, rt := range changing {
		key := rt.Method + " " + rt.Path
		body, ok := bodies[key]
		if !ok {
			t.Errorf("%s has no row in this table; add one", key)
			continue
		}
		target := rt.Path
		for k, v := range targets {
			target = strings.ReplaceAll(target, k, v)
		}
		if strings.Contains(target, "{") {
			t.Errorf("%s: no value for a path parameter in %s", key, target)
			continue
		}
		t.Run(key, func(t *testing.T) {
			before, err := site.inv.GetHostUserFields(ctx, host)
			if err != nil {
				t.Fatal(err)
			}
			rec := postForm(r, target, body(), site.cookies[auth.RoleViewer], site.csrf[auth.RoleViewer])
			if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "403 Forbidden") {
				t.Errorf("viewer %s %s = %d, want the 403 page", rt.Method, target, rec.Code)
			}
			if after, _ := site.inv.GetHostUserFields(ctx, host); !reflect.DeepEqual(after, before) {
				t.Errorf("viewer request changed the host: %+v", after)
			}
			for _, role := range []string{auth.RoleOperator, auth.RoleEditor, auth.RoleAdmin} {
				rec := postForm(r, target, body(), site.cookies[role], site.csrf[role])
				if rec.Code != http.StatusSeeOther {
					t.Errorf("%s %s %s = %d, want 303", role, rt.Method, target, rec.Code)
				}
			}
			if after, _ := site.inv.GetHostUserFields(ctx, host); reflect.DeepEqual(after, before) {
				t.Errorf("permitted roles did not change the host")
			}
		})
	}

	page := do(r, http.MethodGet, "/hosts/"+host, nil, site.cookies[auth.RoleViewer]).Body.String()
	if strings.Contains(page, "<form method=\"post\" action=\"/hosts/") || strings.Contains(page, "Save changes") {
		t.Errorf("the host page shows the edit form to a viewer")
	}
}
