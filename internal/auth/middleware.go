package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"slices"
)

const (
	SessionCookieName = "asi_session"
	CSRFHeader        = "X-CSRF-Token"
	CSRFFormField     = "csrf_token"
)

type principalKey struct{}

func PrincipalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}

func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

func (s *Service) SetSessionCookie(w http.ResponseWriter, r *http.Request, sess Session) {
	http.SetCookie(w, sessionCookie(r, sess.Token, 0))
}

func (s *Service) ClearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, sessionCookie(r, "", -1))
}

func sessionCookie(r *http.Request, value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     SessionCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	}
}

func (s *Service) RequirePermission(p Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := r.Cookie(SessionCookieName)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
			principal, err := s.LookupSession(r.Context(), c.Value)
			if errors.Is(err, ErrNoSession) {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			if !slices.Contains(principal.Permissions, p) {
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return
			}
			if r.Method != http.MethodGet && r.Method != http.MethodHead && !ValidCSRF(r, principal.CSRFToken) {
				http.Error(w, "invalid or missing CSRF token", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), principal)))
		})
	}
}

func ValidCSRF(r *http.Request, want string) bool {
	got := r.Header.Get(CSRFHeader)
	if got == "" {
		got = postFormValue(r, CSRFFormField)
	}
	return got != "" && want != "" && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func postFormValue(r *http.Request, key string) string {
	if r.Method != http.MethodDelete || r.PostForm != nil {
		return r.PostFormValue(key)
	}
	c := r.WithContext(r.Context())
	c.Method = http.MethodPost
	v := c.PostFormValue(key)
	r.Form, r.PostForm, r.MultipartForm = c.Form, c.PostForm, c.MultipartForm
	return v
}
