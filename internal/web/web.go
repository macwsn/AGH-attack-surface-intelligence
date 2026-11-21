package web

import (
	"context"
	"embed"
	"io/fs"
	"net/http"

	"asi/internal/auth"
	"asi/internal/schedule"
	"asi/internal/store"
)

//go:embed *.html static
var files embed.FS

type Feature func(r *Router, d Deps)

var features = []Feature{
	RegisterShell,
	RegisterDashboard,
	RegisterRuns,
	RegisterScans,
	RegisterSignatures,
}

type Auth interface {
	Login(ctx context.Context, username, password, addr string) (auth.Session, error)
	Logout(ctx context.Context, token, addr string) error
	LookupSession(ctx context.Context, token string) (auth.Principal, error)
	SetSessionCookie(w http.ResponseWriter, r *http.Request, sess auth.Session)
	ClearSessionCookie(w http.ResponseWriter, r *http.Request)
}

type Deps struct {
	Store         *store.Store
	Keyring       *store.Keyring
	Auth          Auth
	Scans         *schedule.Scheduler
	SignaturesDir string
}

func New(d Deps) (*Router, error) {
	return build(d, files, features)
}

func build(d Deps, fsys fs.FS, feats []Feature) (*Router, error) {
	pages, err := parsePages(fsys)
	if err != nil {
		return nil, err
	}
	r := &Router{auth: d.Auth, pages: pages, static: fsys}
	for _, f := range feats {
		f(r, d)
	}
	if err := r.finish(); err != nil {
		return nil, err
	}
	return r, nil
}
