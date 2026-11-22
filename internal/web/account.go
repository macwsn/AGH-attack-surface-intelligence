package web

import (
	"errors"
	"net/http"
	"unicode/utf8"

	"asi/internal/auth"
)

type accountPage struct {
	Done     bool
	Problems passwordProblems
}

type passwordProblems struct {
	Current  string
	Password string
	Repeat   string
}

func RegisterAccount(r *Router, d Deps) {
	h := &accountHandlers{r: r, svc: d.Users}
	r.Handle(http.MethodGet, "/account", SignedIn(), h.show)
	r.Handle(http.MethodPost, "/account/password", SignedIn(), h.changePassword)
}

type accountHandlers struct {
	r   *Router
	svc UserAdmin
}

func (h *accountHandlers) render(w http.ResponseWriter, req *http.Request, status int, page accountPage) {
	h.r.Render(w, req, status, "account.html", View{Title: "Your account", Data: page})
}

func (h *accountHandlers) show(w http.ResponseWriter, req *http.Request) {
	h.render(w, req, http.StatusOK, accountPage{Done: req.URL.Query().Get("done") == "password"})
}

func (h *accountHandlers) changePassword(w http.ResponseWriter, req *http.Request) {
	current, password := req.PostFormValue("current_password"), req.PostFormValue("password")
	var p passwordProblems
	switch {
	case utf8.RuneCountInString(password) < auth.MinPasswordLength:
		p.Password = "The new password must be at least 12 characters."
	case password != req.PostFormValue("repeat"):
		p.Repeat = "The two new passwords do not match. Type the same password twice."
	}
	if p != (passwordProblems{}) {
		h.render(w, req, http.StatusUnprocessableEntity, accountPage{Problems: p})
		return
	}
	if h.svc == nil {
		h.r.ServerError(w, req, errors.New("account: user management is not configured"))
		return
	}
	var session string
	if c, err := req.Cookie(auth.SessionCookieName); err == nil {
		session = c.Value
	}
	err := h.svc.ChangePassword(req.Context(), userActor(req), current, password, session)
	status := http.StatusUnprocessableEntity
	switch {
	case err == nil:
		http.Redirect(w, req, "/account?done=password", http.StatusSeeOther)
		return
	case errors.Is(err, auth.ErrInvalidCredentials):
		p.Current = "The current password is wrong. Nothing was changed."
	case errors.Is(err, auth.ErrRateLimited):
		status = http.StatusTooManyRequests
		p.Current = "Too many wrong passwords. Wait a few minutes and try again."
	case errors.Is(err, auth.ErrSamePassword):
		p.Password = "The new password must differ from the current one."
	case errors.Is(err, auth.ErrPasswordTooShort):
		p.Password = "The new password must be at least 12 characters."
	default:
		h.r.ServerError(w, req, err)
		return
	}
	h.render(w, req, status, accountPage{Problems: p})
}
