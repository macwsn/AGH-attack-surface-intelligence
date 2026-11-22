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

type UserAdmin interface {
	ListUsers(ctx context.Context) ([]auth.User, error)
	GetUser(ctx context.Context, username string) (auth.User, error)
	ListRoles(ctx context.Context) ([]auth.Role, error)
	CreateUser(ctx context.Context, actor auth.Actor, username, password, role string) error
	SetUserRole(ctx context.Context, actor auth.Actor, username, role string) error
	ResetPasswordKeepSession(ctx context.Context, actor auth.Actor, username, password, session string) error
	ChangePassword(ctx context.Context, actor auth.Actor, current, password, session string) error
	SetUserDisabled(ctx context.Context, actor auth.Actor, username string, disabled bool) error
	DeleteUser(ctx context.Context, actor auth.Actor, username string) error
}

type userRow struct {
	auth.User
	Path   string
	Manage bool
}

type usersPage struct {
	Users    []userRow
	Roles    []auth.Role
	Disabled int
	Done     string
	Name     string
	Problem  string
	Confirm  *userRow
	Create   userCreateForm
}

type userCreateForm struct {
	Username        string
	Role            string
	UsernameProblem string
	PasswordProblem string
}

var userDone = map[string]string{
	"created":  "User %s created.",
	"role":     "Role of %s changed.",
	"password": "Password of %s reset.",
	"disabled": "User %s disabled. Their sessions have ended.",
	"enabled":  "User %s enabled.",
	"deleted":  "User %s deleted.",
}

func (p usersPage) Count() string {
	if len(p.Users) == 1 {
		return "1 user"
	}
	return fmt.Sprintf("%d users", len(p.Users))
}

func (p usersPage) Message() string {
	f, ok := userDone[p.Done]
	if !ok || p.Name == "" {
		return ""
	}
	return fmt.Sprintf(f, p.Name)
}

func RegisterUsers(r *Router, d Deps) {
	access := Require(auth.PermUserManage)
	h := &userHandlers{r: r, svc: d.Users}
	r.NavIn(NavAdministration, "Users", "/users/", access)
	r.Handle(http.MethodGet, "/users/{$}", access, h.list)
	r.Handle(http.MethodPost, "/users/create", access, h.create)
	r.Handle(http.MethodPost, "/users/{username}/role", access, h.setRole)
	r.Handle(http.MethodPost, "/users/{username}/password", access, h.resetPassword)
	r.Handle(http.MethodPost, "/users/{username}/disable", access, h.setDisabled(true))
	r.Handle(http.MethodPost, "/users/{username}/enable", access, h.setDisabled(false))
	r.Handle(http.MethodGet, "/users/{username}/delete", access, h.confirmDelete)
	r.Handle(http.MethodPost, "/users/{username}/delete", access, h.remove)
}

type userHandlers struct {
	r   *Router
	svc UserAdmin
}

func userActor(req *http.Request) auth.Actor {
	p, _ := auth.PrincipalFrom(req.Context())
	return auth.Actor{Username: p.Username, Addr: clientAddr(req)}
}

func userPath(name string) string { return "/users/" + url.PathEscape(name) }

func (h *userHandlers) ready(w http.ResponseWriter, req *http.Request) bool {
	if h.svc == nil {
		h.r.ServerError(w, req, errors.New("users: user management is not configured"))
		return false
	}
	return true
}

func (h *userHandlers) render(w http.ResponseWriter, req *http.Request, status int, page usersPage) {
	ctx := req.Context()
	users, err := h.svc.ListUsers(ctx)
	if err != nil {
		h.r.ServerError(w, req, err)
		return
	}
	if page.Roles, err = h.svc.ListRoles(ctx); err != nil {
		h.r.ServerError(w, req, err)
		return
	}
	p, _ := auth.PrincipalFrom(ctx)
	for _, u := range users {
		page.Users = append(page.Users, userRow{User: u, Path: userPath(u.Username), Manage: mayManage(p, u, page.Roles)})
		if u.Disabled {
			page.Disabled++
		}
	}
	h.r.Render(w, req, status, "users.html", View{Title: "Users", Data: page})
}

func mayManage(p auth.Principal, u auth.User, roles []auth.Role) bool {
	if u.Username == p.Username {
		return false
	}
	for _, r := range roles {
		if r.Name == u.Role {
			for _, perm := range r.Permissions {
				if !slices.Contains(p.Permissions, perm) {
					return false
				}
			}
			return true
		}
	}
	return false
}

func (h *userHandlers) list(w http.ResponseWriter, req *http.Request) {
	if !h.ready(w, req) {
		return
	}
	q := req.URL.Query()
	h.render(w, req, http.StatusOK, usersPage{Done: q.Get("done"), Name: q.Get("user")})
}

func (h *userHandlers) create(w http.ResponseWriter, req *http.Request) {
	if !h.ready(w, req) {
		return
	}
	form := userCreateForm{Username: strings.TrimSpace(req.PostFormValue("username")), Role: req.PostFormValue("role")}
	if form.Username == "" {
		form.UsernameProblem = "Enter a username."
		h.render(w, req, http.StatusUnprocessableEntity, usersPage{Problem: "Enter a username.", Create: form})
		return
	}
	err := h.svc.CreateUser(req.Context(), userActor(req), form.Username, req.PostFormValue("password"), form.Role)
	h.done(w, req, "created", form.Username, form.Role, form, err)
}

func (h *userHandlers) setRole(w http.ResponseWriter, req *http.Request) {
	if !h.ready(w, req) {
		return
	}
	name, role := req.PathValue("username"), req.PostFormValue("role")
	h.done(w, req, "role", name, role, userCreateForm{}, h.svc.SetUserRole(req.Context(), userActor(req), name, role))
}

func (h *userHandlers) resetPassword(w http.ResponseWriter, req *http.Request) {
	if !h.ready(w, req) {
		return
	}
	name := req.PathValue("username")
	var session string
	if c, err := req.Cookie(auth.SessionCookieName); err == nil {
		session = c.Value
	}
	err := h.svc.ResetPasswordKeepSession(req.Context(), userActor(req), name, req.PostFormValue("password"), session)
	h.done(w, req, "password", name, "", userCreateForm{}, err)
}

func (h *userHandlers) setDisabled(disabled bool) http.HandlerFunc {
	done := "enabled"
	if disabled {
		done = "disabled"
	}
	return func(w http.ResponseWriter, req *http.Request) {
		if !h.ready(w, req) {
			return
		}
		name := req.PathValue("username")
		h.done(w, req, done, name, "", userCreateForm{}, h.svc.SetUserDisabled(req.Context(), userActor(req), name, disabled))
	}
}

func (h *userHandlers) confirmDelete(w http.ResponseWriter, req *http.Request) {
	if !h.ready(w, req) {
		return
	}
	u, err := h.svc.GetUser(req.Context(), req.PathValue("username"))
	if errors.Is(err, auth.ErrUnknownUser) {
		h.r.Error(w, req, http.StatusNotFound, "This user does not exist.")
		return
	}
	if err != nil {
		h.r.ServerError(w, req, err)
		return
	}
	h.render(w, req, http.StatusOK, usersPage{Confirm: &userRow{User: u, Path: userPath(u.Username)}})
}

func (h *userHandlers) remove(w http.ResponseWriter, req *http.Request) {
	if !h.ready(w, req) {
		return
	}
	name := req.PathValue("username")
	h.done(w, req, "deleted", name, "", userCreateForm{}, h.svc.DeleteUser(req.Context(), userActor(req), name))
}

func (h *userHandlers) done(w http.ResponseWriter, req *http.Request, done, name, role string, form userCreateForm, err error) {
	if err == nil {
		http.Redirect(w, req, "/users/?done="+done+"&user="+url.QueryEscape(name), http.StatusSeeOther)
		return
	}
	status, problem := userProblem(err, name, role)
	if status == 0 {
		h.r.ServerError(w, req, err)
		return
	}
	if status == http.StatusNotFound {
		h.r.Error(w, req, status, problem)
		return
	}
	if form.Username != "" {
		switch {
		case errors.Is(err, auth.ErrUserExists):
			form.UsernameProblem = problem
		case errors.Is(err, auth.ErrPasswordTooShort):
			form.PasswordProblem = problem
		}
	}
	h.render(w, req, status, usersPage{Problem: problem, Create: form})
}

func userProblem(err error, name, role string) (int, string) {
	switch {
	case errors.Is(err, auth.ErrLastAdmin):
		return http.StatusConflict, fmt.Sprintf("Nothing was changed: %q is the last enabled admin. Make another user an admin first.", name)
	case errors.Is(err, auth.ErrOwnAccount):
		return http.StatusForbidden, "Nothing was changed: you cannot reset your own password, disable or delete yourself here. Change your password on the Account page."
	case errors.Is(err, auth.ErrStrongerUser):
		return http.StatusForbidden, fmt.Sprintf("Nothing was changed: user %q has permissions your role does not have.", name)
	case errors.Is(err, auth.ErrOwnRole):
		return http.StatusForbidden, "Nothing was changed: you cannot change your own role."
	case errors.Is(err, auth.ErrPermissionNotHeld):
		return http.StatusForbidden, fmt.Sprintf("Nothing was changed: role %q has permissions your role does not have.", role)
	case errors.Is(err, auth.ErrUserExists):
		return http.StatusConflict, fmt.Sprintf("User %q already exists. Choose another username.", name)
	case errors.Is(err, auth.ErrPasswordTooShort):
		return http.StatusUnprocessableEntity, "Nothing was changed: the password must be at least 12 characters."
	case errors.Is(err, auth.ErrUnknownRole):
		return http.StatusUnprocessableEntity, fmt.Sprintf("Nothing was changed: role %q does not exist.", role)
	case errors.Is(err, auth.ErrUnknownUser):
		return http.StatusNotFound, "This user does not exist."
	}
	return 0, ""
}
