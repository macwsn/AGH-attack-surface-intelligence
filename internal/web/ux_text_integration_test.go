//go:build integration

package web

import (
	"context"
	"html"
	"io/fs"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"asi/internal/auth"
)

var (
	pageHead  = regexp.MustCompile(`(?s)<div class="page-head">.*?</div>\s*(?:<div class="actions">.*?</div>)?</div>`)
	ledeRE    = regexp.MustCompile(`(?s)<p class="lede">(.*?)</p>`)
	tagRE     = regexp.MustCompile(`<[^>]+>`)
	dangerRE  = regexp.MustCompile(`<(?:button|a) class="[^"]*\bdanger\b[^"]*"[^>]*>([^<]*)</(?:button|a)>`)
	sentences = regexp.MustCompile(`[.!?](\s|$)`)
)

func oneSentenceLede(t *testing.T, path, page string) {
	t.Helper()
	head := pageHead.FindString(page)
	ledes := ledeRE.FindAllStringSubmatch(head, -1)
	if len(ledes) != 1 {
		t.Errorf("%s: %d ledes in the page head, want 1:\n%s", path, len(ledes), head)
		return
	}
	text := strings.TrimSpace(html.UnescapeString(tagRE.ReplaceAllString(ledes[0][1], "")))
	if n := len(sentences.FindAllString(text, -1)); n != 1 || !strings.HasSuffix(text, ".") {
		t.Errorf("%s: lede %q is %d sentences, want one", path, text, n)
	}
}

// REQ-WEB-045
func TestListPagesHaveOneSentenceLede(t *testing.T) {
	e, _ := newAuditEnv(t)
	for _, path := range []string{"/hosts/", "/groups", "/changes", "/scans", "/signatures", "/users/", "/roles", "/audit",
		"/import", "/export", "/defectdojo"} {
		code, page := e.get(auth.RoleAdmin, path)
		if code != http.StatusOK {
			t.Errorf("GET %s = %d", path, code)
			continue
		}
		oneSentenceLede(t, path, page)
	}
}

// REQ-WEB-045
func TestDestructiveButtonsNameTheirObject(t *testing.T) {
	e, _ := newAuditEnv(t)
	ctx := context.Background()
	if err := e.svc.CreateRole(ctx, auth.Actor{Username: "setup"}, "auditor", []auth.Permission{auth.PermInventoryRead}); err != nil {
		t.Fatal(err)
	}
	e.addSession(t, "alice", auth.RoleViewer)
	src := "- id: my-panel\n  name: My panel\n  kind: admin-panel\n  confidence: 50\n  match:\n    all: [{type: status, value: 200}]\n"
	if code, _, body := e.post(auth.RoleAdmin, "/signatures", url.Values{"source": {src}}); code != http.StatusSeeOther {
		t.Fatalf("create signature = %d\n%s", code, body)
	}
	host := hostWithService(t, e)
	for path, want := range map[string]string{
		"/users/alice/delete":                        "Delete user alice",
		"/roles/auditor/delete":                      "Delete role auditor",
		"/signatures/my-panel":                       "Delete signature my-panel",
		"/hosts/" + host + "/delete":                 "Delete host " + host,
		"/hosts/" + host + "/services/22/tcp/delete": "Delete service " + host + " 22/tcp",
	} {
		code, page := e.get(auth.RoleAdmin, path)
		got := regexp.MustCompile(`<button class="danger"[^>]*>([^<]*)</button>`).FindAllStringSubmatch(page, -1)
		if code != http.StatusOK || len(got) != 1 || strings.TrimSpace(html.UnescapeString(got[0][1])) != want {
			t.Errorf("GET %s = %d, danger buttons %v, want %q", path, code, got, want)
		}
	}

	for _, path := range []string{"/signatures", "/users/", "/roles", "/hosts/" + host, "/scans"} {
		_, page := e.get(auth.RoleAdmin, path)
		for _, m := range dangerRE.FindAllStringSubmatch(page, -1) {
			label := html.UnescapeString(m[1])
			if len(strings.Fields(label)) < 3 {
				t.Errorf("%s: danger %q does not name its object", path, label)
			}
		}
	}

	err := fs.WalkDir(files, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".html") {
			return err
		}
		b, _ := fs.ReadFile(files, p)
		for _, m := range dangerRE.FindAllStringSubmatch(string(b), -1) {
			if !strings.Contains(m[1], "{{") && len(strings.Fields(m[1])) < 3 {
				t.Errorf("%s: danger button %q does not name its object", p, m[1])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func hostWithService(t *testing.T, e *usersEnv) string {
	t.Helper()
	const host = "10.0.0.5"
	code, _, body := e.post(auth.RoleAdmin, "/hosts/entry", url.Values{"address": {host}, "port": {"22"}, "protocol": {"tcp"}, "service": {"ssh"}})
	if code != http.StatusOK {
		t.Fatalf("add host = %d\n%s", code, body)
	}
	return host
}
