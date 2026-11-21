package auth

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func sessionCookieFrom(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	var found *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookieName {
			if found != nil {
				t.Fatalf("more than one %s cookie set", SessionCookieName)
			}
			found = c
		}
	}
	if found == nil {
		t.Fatalf("no %s cookie in %v", SessionCookieName, rec.Header().Values("Set-Cookie"))
	}
	return found
}

func checkCookieAttrs(t *testing.T, c *http.Cookie, secure bool) {
	t.Helper()
	if c.Path != "/" {
		t.Errorf("Path = %q, want /", c.Path)
	}
	if !c.HttpOnly {
		t.Error("HttpOnly = false")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", c.SameSite)
	}
	if c.Secure != secure {
		t.Errorf("Secure = %v, want %v", c.Secure, secure)
	}
}

func TestSessionCookieAttributesPlain(t *testing.T) {
	s := NewService(nil, Config{})
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "http://asi.example/login", nil)
	s.SetSessionCookie(rec, r, Session{Token: "tok-plain"})
	c := sessionCookieFrom(t, rec)
	if c.Value != "tok-plain" {
		t.Errorf("Value = %q, want tok-plain", c.Value)
	}
	if c.MaxAge < 0 {
		t.Errorf("MaxAge = %d, want a live cookie", c.MaxAge)
	}
	checkCookieAttrs(t, c, false)
}

func TestSessionCookieAttributesTLS(t *testing.T) {
	s := NewService(nil, Config{})
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "https://asi.example/login", nil)
	r.TLS = &tls.ConnectionState{}
	s.SetSessionCookie(rec, r, Session{Token: "tok-tls"})
	c := sessionCookieFrom(t, rec)
	if c.Value != "tok-tls" {
		t.Errorf("Value = %q, want tok-tls", c.Value)
	}
	checkCookieAttrs(t, c, true)
}

func TestClearSessionCookie(t *testing.T) {
	s := NewService(nil, Config{})
	for _, secure := range []bool{false, true} {
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "http://asi.example/logout", nil)
		if secure {
			r.TLS = &tls.ConnectionState{}
		}
		s.ClearSessionCookie(rec, r)
		c := sessionCookieFrom(t, rec)
		if c.MaxAge >= 0 {
			t.Errorf("MaxAge = %d, want < 0", c.MaxAge)
		}
		if c.Value != "" {
			t.Errorf("Value = %q, want empty", c.Value)
		}
		checkCookieAttrs(t, c, secure)
	}
}

func TestPrincipalFromEmptyContext(t *testing.T) {
	if _, ok := PrincipalFrom(context.Background()); ok {
		t.Fatal("PrincipalFrom(empty context) ok = true")
	}
}

func TestRequirePermissionNoCookie(t *testing.T) {
	s := NewService(nil, Config{})
	called := false
	h := s.RequirePermission(PermInventoryRead)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, "/", nil))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s without cookie: status %d, want 401", method, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "not-a-token"})
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("garbled token: status %d, want 401", rec.Code)
	}
	if called {
		t.Error("inner handler called")
	}
}
