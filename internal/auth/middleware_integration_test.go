//go:build integration

package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

type probeHandler struct {
	called    bool
	principal Principal
	ok        bool
}

func (h *probeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.called = true
	h.principal, h.ok = PrincipalFrom(r.Context())
	w.WriteHeader(http.StatusNoContent)
}

func serveWith(s *Service, p Permission, r *http.Request) (*httptest.ResponseRecorder, *probeHandler) {
	inner := &probeHandler{}
	rec := httptest.NewRecorder()
	s.RequirePermission(p)(inner).ServeHTTP(rec, r)
	return rec, inner
}

func requestWithToken(method, token string) *http.Request {
	r := httptest.NewRequest(method, "/x", nil)
	if token != "" {
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: token})
	}
	return r
}

func TestRequirePermission401(t *testing.T) {
	clock := newTestClock()
	s := newTestService(t, Config{Now: clock.Now})
	createSessTestUser(t, s, "alice", RoleAdmin)
	other, _ := randomToken()
	loggedOut := mustLogin(t, s, "alice")
	if err := s.Logout(context.Background(), loggedOut.Token, "192.0.2.1"); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	expired := mustLogin(t, s, "alice")
	clock.Advance(DefaultIdleTimeout)

	cases := map[string]string{"no cookie": "", "unknown": other, "garbled": "garbage", "logged out": loggedOut.Token, "expired": expired.Token}
	for name, tok := range cases {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			rec, inner := serveWith(s, PermInventoryRead, requestWithToken(method, tok))
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("%s %s: status %d, want 401", name, method, rec.Code)
			}
			if inner.called {
				t.Errorf("%s %s: inner handler called", name, method)
			}
		}
	}
}

func TestRequirePermission403(t *testing.T) {
	s := newTestService(t, Config{})
	createSessTestUser(t, s, "vera", RoleViewer)
	createSessTestUser(t, s, "olga", RoleOperator)
	vera := mustLogin(t, s, "vera")
	olga := mustLogin(t, s, "olga")

	for _, c := range []struct {
		token string
		perm  Permission
	}{{vera.Token, PermInventoryEdit}, {vera.Token, PermUserManage}, {olga.Token, PermScanRun}, {olga.Token, PermRoleManage}} {
		rec, inner := serveWith(s, c.perm, requestWithToken(http.MethodGet, c.token))
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403", c.perm, rec.Code)
		}
		if inner.called {
			t.Errorf("%s: inner handler called", c.perm)
		}
	}
}

func TestRequirePermissionAllowed(t *testing.T) {
	s := newTestService(t, Config{})
	createSessTestUser(t, s, "root", RoleAdmin)
	createSessTestUser(t, s, "vera", RoleViewer)
	root := mustLogin(t, s, "root")
	vera := mustLogin(t, s, "vera")

	for _, p := range AllPermissions {
		rec, inner := serveWith(s, p, requestWithToken(http.MethodGet, root.Token))
		if rec.Code != http.StatusNoContent || !inner.called {
			t.Fatalf("admin %s: status %d, called %v", p, rec.Code, inner.called)
		}
		if !inner.ok || inner.principal.Username != "root" || inner.principal.Role != RoleAdmin {
			t.Fatalf("admin %s: PrincipalFrom = %+v, %v", p, inner.principal, inner.ok)
		}
	}
	rec, inner := serveWith(s, PermInventoryRead, requestWithToken(http.MethodGet, vera.Token))
	if rec.Code != http.StatusNoContent || !inner.called || !inner.ok || inner.principal.Username != "vera" {
		t.Fatalf("viewer inventory.read: status %d, called %v, principal %+v", rec.Code, inner.called, inner.principal)
	}
}

func TestCSRFRequiredOnNonGet(t *testing.T) {
	s := newTestService(t, Config{})
	createSessTestUser(t, s, "root", RoleAdmin)
	createSessTestUser(t, s, "eddie", RoleEditor)
	root := mustLogin(t, s, "root")
	otherSameUser := mustLogin(t, s, "root")
	eddie := mustLogin(t, s, "eddie")

	tokens := []struct {
		name  string
		token string
		want  int
	}{
		{"missing", "", http.StatusForbidden},
		{"wrong", "not-the-token", http.StatusForbidden},
		{"other user's session", eddie.CSRFToken, http.StatusForbidden},
		{"same user's other session", otherSameUser.CSRFToken, http.StatusForbidden},
		{"truncated", root.CSRFToken[:len(root.CSRFToken)-1], http.StatusForbidden},
		{"correct", root.CSRFToken, http.StatusNoContent},
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		for _, tc := range tokens {
			r := requestWithToken(method, root.Token)
			if tc.token != "" {
				r.Header.Set(CSRFHeader, tc.token)
			}
			rec, inner := serveWith(s, PermInventoryEdit, r)
			if rec.Code != tc.want || inner.called != (tc.want == http.StatusNoContent) {
				t.Errorf("%s header %s: status %d called %v, want %d", method, tc.name, rec.Code, inner.called, tc.want)
			}
		}
		for _, tc := range tokens {
			form := url.Values{"csrf_token": {tc.token}, "name": {"x"}}.Encode()
			r := httptest.NewRequest(method, "/x", strings.NewReader(form))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: root.Token})
			rec, inner := serveWith(s, PermInventoryEdit, r)
			if rec.Code != tc.want || inner.called != (tc.want == http.StatusNoContent) {
				t.Errorf("%s form %s: status %d called %v, want %d", method, tc.name, rec.Code, inner.called, tc.want)
			}
		}
		rec, inner := serveWith(s, PermInventoryEdit, requestWithToken(method, ""))
		if rec.Code != http.StatusUnauthorized || inner.called {
			t.Errorf("%s without session: status %d called %v, want 401", method, rec.Code, inner.called)
		}
		r := requestWithToken(method, "")
		r.Header.Set(CSRFHeader, root.CSRFToken)
		rec, inner = serveWith(s, PermInventoryEdit, r)
		if rec.Code != http.StatusUnauthorized || inner.called {
			t.Errorf("%s CSRF token without session: status %d called %v, want 401", method, rec.Code, inner.called)
		}
	}
}

func TestCSRFNotRequiredOnGet(t *testing.T) {
	s := newTestService(t, Config{})
	createSessTestUser(t, s, "root", RoleAdmin)
	root := mustLogin(t, s, "root")
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		rec, inner := serveWith(s, PermInventoryRead, requestWithToken(method, root.Token))
		if rec.Code != http.StatusNoContent || !inner.called {
			t.Errorf("%s without CSRF token: status %d called %v, want 204", method, rec.Code, inner.called)
		}
	}
}
