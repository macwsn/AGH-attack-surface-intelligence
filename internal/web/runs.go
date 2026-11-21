package web

import (
	"errors"
	"fmt"
	"net/http"

	"asi/internal/auth"
	"asi/internal/inventory"
	"asi/internal/scan"
)

type runPage struct {
	Run      inventory.Run
	Progress scan.Progress
	Groups   []inventory.GroupInfo
	Failed   []inventory.FailedGroup
}

func RegisterRuns(r *Router, d Deps) {
	r.Handle(http.MethodGet, "/runs/by-name/{name}", Require(auth.PermInventoryRead), func(w http.ResponseWriter, req *http.Request) {
		if d.Store == nil {
			r.ServerError(w, req, errors.New("run page: no database"))
			return
		}
		inv := inventory.New(d.Store, d.Keyring)
		name := req.PathValue("name")
		run, err := inv.RunByName(req.Context(), name)
		if errors.Is(err, inventory.ErrUnknownRun) {
			r.Error(w, req, http.StatusNotFound, fmt.Sprintf("There is no run named %q.", name))
			return
		}
		if err != nil {
			r.ServerError(w, req, err)
			return
		}
		groups, err := inv.RunGroups(req.Context(), run.ID)
		if err != nil {
			r.ServerError(w, req, err)
			return
		}
		failed, err := inv.FailedGroups(req.Context(), run.ID)
		if err != nil {
			r.ServerError(w, req, err)
			return
		}
		data := runPage{Run: run, Progress: scan.RunProgress(run, groups, failed), Groups: groups, Failed: failed}
		r.Render(w, req, http.StatusOK, "run.html", View{Title: "Run " + run.Name, Data: data})
	})
}
