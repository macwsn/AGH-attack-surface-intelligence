package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"asi/internal/auth"
)

type RoleAdmin interface {
	ListRoles(ctx context.Context) ([]auth.Role, error)
	CreateRole(ctx context.Context, actor auth.Actor, name string, perms []auth.Permission) error
	UpdateRole(ctx context.Context, actor auth.Actor, name string, perms []auth.Permission) error
	DeleteRole(ctx context.Context, actor auth.Actor, name string) error
}

type roleRow struct {
	auth.Role
	Path   string
	FormID string
	Ticks  []roleTick
}

type roleTick struct {
	Permission auth.Permission
	Granted    bool
}

type rolesPage struct {
	Permissions []auth.Permission
	Roles       []roleRow
	Custom      int
	Done        string
	Name        string
	Problem     string
	Confirm     *roleRow
	Create      roleRow
}

var roleDone = map[string]string{
	"created": "Role %s created.",
	"saved":   "Role %s saved.",
	"deleted": "Role %s deleted.",
}

func (p rolesPage) Message() string {
	f, ok := roleDone[p.Done]
	if !ok || p.Name == "" {
		return ""
	}
	return fmt.Sprintf(f, p.Name)
}

func RegisterRoles(r *Router, d Deps) {
	access := Require(auth.PermRoleManage)
	h := &roleHandlers{r: r, svc: d.Roles}
	r.NavIn(NavAdministration, "Roles", "/roles", access)
	r.Handle(http.MethodGet, "/roles", access, h.list)
	r.Handle(http.MethodPost, "/roles/create", access, h.create)
	r.Handle(http.MethodPost, "/roles/{name}", access, h.update)
	r.Handle(http.MethodGet, "/roles/{name}/delete", access, h.confirmDelete)
	r.Handle(http.MethodPost, "/roles/{name}/delete", access, h.remove)
}

type roleHandlers struct {
	r   *Router
	svc RoleAdmin
}

func newRoleRow(role auth.Role, i int) roleRow {
	row := roleRow{Role: role, Path: "/roles/" + url.PathEscape(role.Name), FormID: fmt.Sprintf("role-%d", i)}
	for _, p := range auth.AllPermissions {
		row.Ticks = append(row.Ticks, roleTick{Permission: p, Granted: slices.Contains(role.Permissions, p)})
	}
	return row
}

func formPermissions(req *http.Request) []auth.Permission {
	var perms []auth.Permission
	for _, p := range req.PostForm["perm"] {
		perms = append(perms, auth.Permission(p))
	}
	return perms
}

func (h *roleHandlers) ready(w http.ResponseWriter, req *http.Request) bool {
	if h.svc == nil {
		h.r.ServerError(w, req, errors.New("roles: role management is not configured"))
		return false
	}
	return true
}

func (h *roleHandlers) readForm(w http.ResponseWriter, req *http.Request) bool {
	if !readForm(w, req, maxFormBytes) {
		h.r.Error(w, req, http.StatusBadRequest, "The form could not be read.")
		return false
	}
	return true
}

func (h *roleHandlers) render(w http.ResponseWriter, req *http.Request, status int, page rolesPage) {
	roles, err := h.svc.ListRoles(req.Context())
	if err != nil {
		h.r.ServerError(w, req, err)
		return
	}
	page.Permissions = auth.AllPermissions
	for i, role := range roles {
		page.Roles = append(page.Roles, newRoleRow(role, i))
		if !role.Builtin {
			page.Custom++
		}
	}
	if page.Create.Ticks == nil {
		page.Create = newRoleRow(auth.Role{}, len(roles))
	}
	h.r.Render(w, req, status, "roles.html", View{Title: "Roles", Data: page})
}

func (h *roleHandlers) list(w http.ResponseWriter, req *http.Request) {
	if !h.ready(w, req) {
		return
	}
	q := req.URL.Query()
	h.render(w, req, http.StatusOK, rolesPage{Done: q.Get("done"), Name: q.Get("role")})
}

func (h *roleHandlers) create(w http.ResponseWriter, req *http.Request) {
	if !h.ready(w, req) || !h.readForm(w, req) {
		return
	}
	name := strings.TrimSpace(req.PostFormValue("name"))
	perms := formPermissions(req)
	var err error
	if name == "" {
		err = errEmptyRoleName
	} else {
		err = h.svc.CreateRole(req.Context(), userActor(req), name, perms)
	}
	h.done(w, req, "created", name, err, newRoleRow(auth.Role{Name: name, Permissions: perms}, 0))
}

func (h *roleHandlers) update(w http.ResponseWriter, req *http.Request) {
	if !h.ready(w, req) || !h.readForm(w, req) {
		return
	}
	name := req.PathValue("name")
	h.done(w, req, "saved", name, h.svc.UpdateRole(req.Context(), userActor(req), name, formPermissions(req)), roleRow{})
}

func (h *roleHandlers) confirmDelete(w http.ResponseWriter, req *http.Request) {
	if !h.ready(w, req) {
		return
	}
	name := req.PathValue("name")
	roles, err := h.svc.ListRoles(req.Context())
	if err != nil {
		h.r.ServerError(w, req, err)
		return
	}
	i := slices.IndexFunc(roles, func(r auth.Role) bool { return r.Name == name })
	switch {
	case i < 0:
		h.r.Error(w, req, http.StatusNotFound, "This role does not exist.")
	case roles[i].Builtin:
		_, problem := roleProblem(auth.ErrBuiltinRole, name)
		h.render(w, req, http.StatusConflict, rolesPage{Problem: problem})
	default:
		row := newRoleRow(roles[i], i)
		h.render(w, req, http.StatusOK, rolesPage{Confirm: &row})
	}
}

func (h *roleHandlers) remove(w http.ResponseWriter, req *http.Request) {
	if !h.ready(w, req) {
		return
	}
	name := req.PathValue("name")
	h.done(w, req, "deleted", name, h.svc.DeleteRole(req.Context(), userActor(req), name), roleRow{})
}

var errEmptyRoleName = errors.New("role name is empty")

func (h *roleHandlers) done(w http.ResponseWriter, req *http.Request, done, name string, err error, form roleRow) {
	if err == nil {
		http.Redirect(w, req, "/roles?done="+done+"&role="+url.QueryEscape(name), http.StatusSeeOther)
		return
	}
	status, problem := roleProblem(err, name)
	switch status {
	case 0:
		h.r.ServerError(w, req, err)
	case http.StatusNotFound:
		h.r.Error(w, req, status, problem)
	default:
		h.render(w, req, status, rolesPage{Problem: problem, Create: form})
	}
}

func roleProblem(err error, name string) (int, string) {
	switch {
	case errors.Is(err, auth.ErrBuiltinRole):
		return http.StatusConflict, fmt.Sprintf("Nothing was changed: %q is a built-in role and cannot be edited or deleted. Create a custom role instead.", name)
	case errors.Is(err, auth.ErrOwnRole):
		return http.StatusForbidden, fmt.Sprintf("Nothing was changed: %q is your own role. Another role manager has to change it.", name)
	case errors.Is(err, auth.ErrPermissionNotHeld):
		return http.StatusForbidden, "Nothing was changed: you can grant only permissions your own role has."
	case errors.Is(err, auth.ErrRoleExists):
		return http.StatusConflict, fmt.Sprintf("Role %q already exists. Choose another name.", name)
	case errors.Is(err, auth.ErrRoleInUse):
		return http.StatusConflict, fmt.Sprintf("Nothing was changed: role %q is assigned to a user. Give its users another role first.", name)
	case errors.Is(err, auth.ErrUnknownPermission):
		return http.StatusUnprocessableEntity, "Nothing was changed: " + err.Error() + ". Tick only the listed permissions."
	case errors.Is(err, errEmptyRoleName):
		return http.StatusUnprocessableEntity, "Enter a role name."
	case errors.Is(err, auth.ErrUnknownRole):
		return http.StatusNotFound, "This role does not exist."
	}
	return 0, ""
}
