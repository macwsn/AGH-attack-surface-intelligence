//go:build integration

package main

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"asi/internal/auth"
	"asi/internal/store"
	"asi/internal/web"
)

func TestMigrateBackfillsHostSummaryForHostsScannedBeforeIt(t *testing.T) {
	ctx := context.Background()
	c := newCLIEnv(t, "192.0.2.0/29", "192.0.2.0")
	c.net.up("192.0.2.1", 22, 80)
	c.scan("before-upgrade")

	if _, err := c.st.Pool.Exec(ctx, `DELETE FROM host_summary`); err != nil {
		t.Fatalf("delete host_summary: %v", err)
	}
	c.mustRun("migrate")

	var rows int
	if err := c.st.Pool.QueryRow(ctx, `SELECT count(*) FROM host_summary`).Scan(&rows); err != nil {
		t.Fatal(err)
	}

	raw, err := base64.StdEncoding.DecodeString(testKey)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := store.NewKeyring(raw)
	if err != nil {
		t.Fatal(err)
	}
	svc := auth.NewService(c.st, auth.Config{})
	if err := svc.CreateUser(ctx, auth.Actor{Username: "test", Addr: "local"}, "vera", "vera-password-123", auth.RoleViewer); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	h, err := web.New(web.Deps{Store: c.st, Keyring: keys, Auth: svc})
	if err != nil {
		t.Fatalf("web.New: %v", err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar}
	_, login := httpGet(t, hc, srv.URL+"/login")
	m := csrfField.FindSubmatch(login)
	if m == nil {
		t.Fatal("login form has no CSRF token")
	}
	resp, err := hc.PostForm(srv.URL+"/login", url.Values{"username": {"vera"}, "password": {"vera-password-123"}, "csrf_token": {string(m[1])}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	code, page := httpGet(t, hc, srv.URL+"/hosts/")
	if code != http.StatusOK || rows != 1 || !strings.Contains(string(page), `href="/hosts/192.0.2.1"`) {
		t.Fatalf("after asi migrate: host_summary has %d rows, want 1; /hosts/ = %d, lists 192.0.2.1: %v",
			rows, code, strings.Contains(string(page), "192.0.2.1"))
	}
}
