package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"time"

	"asi/internal/auth"
)

const (
	loginCSRFCookie = "asi_login_csrf"
	maxFormBytes    = 64 << 10
)

type loginData struct {
	Username string
	Next     string
	Error    string
}

func RegisterShell(r *Router, d Deps) {
	r.Handle(http.MethodGet, "/login", Public(), r.loginForm)
	r.Handle(http.MethodPost, "/login", Public(), r.login)
	r.Handle(http.MethodPost, "/logout", SignedIn(), r.logout)
	r.Handle(http.MethodGet, "/static/{name}", Public(), r.staticFile)
	r.Handle(http.MethodGet, "/healthz", Public(), func(w http.ResponseWriter, req *http.Request) {
		ctx, cancel := context.WithTimeout(req.Context(), 2*time.Second)
		defer cancel()
		if d.Store == nil || d.Store.Pool.Ping(ctx) != nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintln(w, "ok")
	})
}

func (r *Router) loginForm(w http.ResponseWriter, req *http.Request) {
	r.renderLogin(w, req, http.StatusOK, loginData{Next: safeNext(req.URL.Query().Get("next"))})
}

func (r *Router) renderLogin(w http.ResponseWriter, req *http.Request, status int, data loginData) {
	token, err := randomToken()
	if err != nil {
		r.ServerError(w, req, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     loginCSRFCookie,
		Value:    token,
		Path:     "/login",
		MaxAge:   3600,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   req.TLS != nil,
	})
	r.Render(w, req, status, "login.html", View{Title: "Sign in", CSRFToken: token, Data: data})
}

func (r *Router) login(w http.ResponseWriter, req *http.Request) {
	req.Body = http.MaxBytesReader(w, req.Body, maxFormBytes)
	if err := req.ParseForm(); err != nil {
		r.Error(w, req, http.StatusBadRequest, "The form could not be read.")
		return
	}
	c, err := req.Cookie(loginCSRFCookie)
	got := req.PostForm.Get(auth.CSRFFormField)
	if err != nil || got == "" || subtle.ConstantTimeCompare([]byte(c.Value), []byte(got)) != 1 {
		r.Error(w, req, http.StatusForbidden, "Invalid or missing CSRF token. Reload the sign-in page and try again.")
		return
	}
	data := loginData{Username: req.PostForm.Get("username"), Next: safeNext(req.PostForm.Get("next"))}
	sess, err := r.auth.Login(req.Context(), data.Username, req.PostForm.Get("password"), clientAddr(req))
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials):
		data.Error = "Invalid username or password."
		r.renderLogin(w, req, http.StatusUnauthorized, data)
		return
	case errors.Is(err, auth.ErrRateLimited):
		data.Error = "Too many failed sign-in attempts. Try again later."
		r.renderLogin(w, req, http.StatusTooManyRequests, data)
		return
	case err != nil:
		r.ServerError(w, req, fmt.Errorf("login: %w", err))
		return
	}
	http.SetCookie(w, &http.Cookie{Name: loginCSRFCookie, Path: "/login", MaxAge: -1, HttpOnly: true,
		SameSite: http.SameSiteStrictMode, Secure: req.TLS != nil})
	r.auth.SetSessionCookie(w, req, sess)
	target := data.Next
	if target == "" {
		target = "/"
	}
	http.Redirect(w, req, target, http.StatusSeeOther)
}

func (r *Router) logout(w http.ResponseWriter, req *http.Request) {
	if c, err := req.Cookie(auth.SessionCookieName); err == nil {
		if err := r.auth.Logout(req.Context(), c.Value, clientAddr(req)); err != nil {
			r.ServerError(w, req, fmt.Errorf("logout: %w", err))
			return
		}
	}
	r.auth.ClearSessionCookie(w, req)
	http.Redirect(w, req, "/login", http.StatusSeeOther)
}

func (r *Router) staticFile(w http.ResponseWriter, req *http.Request) {
	name := "static/" + req.PathValue("name")
	if st, err := fs.Stat(r.static, name); err != nil || st.IsDir() {
		r.Error(w, req, http.StatusNotFound, "This file does not exist.")
		return
	}
	http.ServeFileFS(w, req, r.static, name)
}

func safeNext(next string) string {
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.ContainsFunc(next, unsafeNextRune) {
		return ""
	}
	return next
}

func unsafeNextRune(r rune) bool {
	return r < 0x20 || r == 0x7f || r == '\\'
}

func clientAddr(req *http.Request) string {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return host
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
