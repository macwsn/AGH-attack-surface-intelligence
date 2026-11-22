package web

import (
	"context"
	"embed"
	"io/fs"
	"net/http"

	"asi/internal/auth"
	"asi/internal/detect"
	"asi/internal/inventory"
	"asi/internal/schedule"
	"asi/internal/store"
)

//go:embed *.html static
var files embed.FS

var partials = []string{"changes_chart.html", "availability_strip.html"}

type Feature func(r *Router, d Deps)

var features = []Feature{
	RegisterShell,
	RegisterDashboard,
	RegisterInventory,
	RegisterHostDelete,
	RegisterChanges,
	RegisterTimeline,
	RegisterGroups,
	RegisterScans,
	RegisterSignatures,
	RegisterAvailability,
	RegisterExchange,
	RegisterDefectDojo,
	RegisterUsers,
	RegisterRoles,
	RegisterAudit,
	RegisterAccount,
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
	Users         UserAdmin
	Roles         RoleAdmin
	Audit         AuditLog
	Inventory     Inventory
	Scans         *schedule.Scheduler
	DefectDojo    DefectDojo
	SignaturesDir string
	Signatures    *detect.Set
	Library       *detect.Library
}

func (d Deps) signatureSet(ctx context.Context) (*detect.Set, error) {
	if d.Library == nil {
		return d.Signatures, nil
	}
	return d.Library.Set(ctx)
}

func (d Deps) store() *inventory.Inventory {
	if inv, ok := d.Inventory.(*inventory.Inventory); ok && inv != nil {
		return inv
	}
	return inventory.New(d.Store, d.Keyring)
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
