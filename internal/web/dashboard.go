package web

import "net/http"

func RegisterDashboard(r *Router, d Deps) {
	r.Nav("Dashboard", "/", SignedIn())
	r.Handle(http.MethodGet, "/{$}", SignedIn(), func(w http.ResponseWriter, req *http.Request) {
		r.Render(w, req, http.StatusOK, "dashboard.html", View{Title: "Dashboard"})
	})
}
