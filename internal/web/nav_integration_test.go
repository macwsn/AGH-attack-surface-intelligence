//go:build integration

package web

import (
	"net/http"
	"regexp"
	"slices"
	"strings"
	"testing"

	"asi/internal/auth"
)

// REQ-WEB-006
func TestNavGroupsPerBuiltinRole(t *testing.T) {
	e := newRolesEnv(t)
	for role, want := range map[string][]string{
		auth.RoleAdmin: adminNavLayout,
		auth.RoleEditor: {
			"Overview: Dashboard /, Changes /changes",
			"Inventory: Hosts /hosts/, Groups /groups",
			"Scanning: Scans /scans, Signatures /signatures",
			"Data: Import /import, Export /export, DefectDojo /defectdojo",
		},
		auth.RoleOperator: {
			"Overview: Dashboard /, Changes /changes",
			"Inventory: Hosts /hosts/, Groups /groups",
			"Data: Export /export, DefectDojo /defectdojo",
		},
		auth.RoleViewer: {
			"Overview: Dashboard /, Changes /changes",
			"Inventory: Hosts /hosts/, Groups /groups",
		},
	} {
		code, page := e.get(role, "/")
		if code != http.StatusOK {
			t.Fatalf("GET / as %s = %d", role, code)
		}
		if got := navLayout(t, page); !slices.Equal(got, want) {
			t.Errorf("%s navigation =\n%s\nwant\n%s", role, strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
	}
}

// REQ-WEB-006
func TestNavCurrentOnSubPages(t *testing.T) {
	e := newRolesEnv(t)
	current := regexp.MustCompile(`<a href="([^"]*)" aria-current="page">`)
	for path, want := range map[string]string{
		"/hosts/":          "/hosts/",
		"/hosts/10.0.0.1":  "/hosts/",
		"/hosts/entry":     "/hosts/",
		"/runs/" + e.runID: "/scans",
		"/changes":         "/changes",
		"/users/":          "/users/",
		"/roles":           "/roles",
		"/import":          "/import",
		"/signatures":      "/signatures",
	} {
		code, page := e.get(auth.RoleAdmin, path)
		if code != http.StatusOK {
			t.Errorf("GET %s = %d", path, code)
			continue
		}
		if got := current.FindAllStringSubmatch(page, -1); len(got) != 1 || got[0][1] != want {
			t.Errorf("%s: marked %v, want exactly %s", path, got, want)
		}
	}
}

// REQ-WEB-039
func TestHostsPageAddHostButton(t *testing.T) {
	e := newRolesEnv(t)
	button := `<a class="btn primary" href="/hosts/entry">Add host</a>`
	for role, want := range map[string]bool{
		auth.RoleAdmin:    true,
		auth.RoleEditor:   true,
		auth.RoleOperator: false,
		auth.RoleViewer:   false,
	} {
		code, page := e.get(role, "/hosts/")
		if code != http.StatusOK {
			t.Fatalf("GET /hosts/ as %s = %d", role, code)
		}
		main := page[strings.Index(page, "<main>"):]
		if got := strings.Contains(main, button); got != want {
			t.Errorf("%s: Add host button shown = %v, want %v", role, got, want)
		}
		nav := regexp.MustCompile(`(?s)<nav aria-label="Main">.*?</nav>`).FindString(page)
		if strings.Contains(nav, "/hosts/entry") || strings.Contains(nav, "Add host") {
			t.Errorf("%s: navigation still links to Add host:\n%s", role, nav)
		}
		if regexp.MustCompile(`style\s*=`).MatchString(page) {
			t.Errorf("%s: hosts page has inline styles", role)
		}
	}
	if code, _ := e.get(auth.RoleOperator, "/hosts/entry"); code != http.StatusForbidden {
		t.Errorf("GET /hosts/entry as operator = %d, want 403", code)
	}
}
