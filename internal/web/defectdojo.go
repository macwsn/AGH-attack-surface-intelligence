package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"asi/internal/auth"
	"asi/internal/exchange/defectdojo"
	"asi/internal/inventory"
)

type DefectDojo interface {
	View(ctx context.Context) (defectdojo.View, error)
	Configure(ctx context.Context, actor auth.Actor, c defectdojo.Config) error
	TestConnection(ctx context.Context) error
	CheckStoredTests(ctx context.Context) error
	Export(ctx context.Context, actor auth.Actor, run string) (defectdojo.Result, error)
	ForceExport(ctx context.Context, actor auth.Actor, run string) (defectdojo.Result, error)
	Choices(ctx context.Context, productID int) (defectdojo.Choices, error)
}

type runLister interface {
	ListRuns(ctx context.Context) ([]inventory.Run, error)
}

type dojoPreviewer interface {
	Preview(ctx context.Context, run string) (defectdojo.Result, error)
}

type dojoPage struct {
	Settings defectdojo.View
	Form     defectdojo.Config
	Run      string
	CanEdit  bool
	OK       string
	Error    string
	Confirm  bool
	Exported bool
	Runs     []string
	Choices  *defectdojo.Choices
	Preview  bool
}

func RegisterDefectDojo(r *Router, d Deps) {
	access := Require(auth.PermExport)
	var runs runLister = d.Inventory
	if runs == nil && d.Store != nil {
		runs = d.store()
	}
	r.NavIn(NavData, "DefectDojo", "/defectdojo", access)
	r.Handle(http.MethodGet, "/defectdojo", access, func(w http.ResponseWriter, req *http.Request) {
		page := dojoPage{}
		if id, err := strconv.Atoi(req.URL.Query().Get("product_id")); err == nil && id > 0 && d.DefectDojo != nil {
			v, err := d.DefectDojo.View(req.Context())
			if err != nil {
				r.ServerError(w, req, err)
				return
			}
			page.Form = defectdojo.Config{BaseURL: v.BaseURL, ProductID: id}
			if id == v.ProductID {
				page.Form.EngagementID = v.EngagementID
			}
		}
		r.renderDojo(w, req, d.DefectDojo, runs, http.StatusOK, page, nil)
	})
	r.Handle(http.MethodPost, "/defectdojo/settings", Require(auth.PermScanConfigure), func(w http.ResponseWriter, req *http.Request) {
		c := defectdojo.Config{
			BaseURL:      req.PostFormValue("base_url"),
			Token:        req.PostFormValue("token"),
			ProductID:    formInt(req, "product_id"),
			EngagementID: formInt(req, "engagement_id"),
			Force:        req.PostFormValue("force") == "1",
		}
		if d.DefectDojo == nil {
			r.ServerError(w, req, errors.New("defectdojo: service not configured"))
			return
		}
		err := d.DefectDojo.Configure(req.Context(), dojoActor(req), c)
		if !can(req, auth.PermExport) {
			if err == nil {
				http.Redirect(w, req, "/defectdojo", http.StatusSeeOther)
				return
			}
			msg, status := dojoError(err)
			if status == http.StatusInternalServerError {
				r.ServerError(w, req, err)
				return
			}
			r.Error(w, req, status, msg)
			return
		}
		c.Token, c.Force = "", false
		r.renderDojo(w, req, d.DefectDojo, runs, http.StatusOK, dojoPage{Form: c,
			OK: "Saved. The API token is stored encrypted and is not shown again."}, err)
	})
	r.Handle(http.MethodPost, "/defectdojo/test", access, func(w http.ResponseWriter, req *http.Request) {
		if d.DefectDojo == nil {
			r.ServerError(w, req, errors.New("defectdojo: service not configured"))
			return
		}
		err := d.DefectDojo.TestConnection(req.Context())
		if err == nil {
			err = d.DefectDojo.CheckStoredTests(req.Context())
		}
		r.renderDojo(w, req, d.DefectDojo, runs, http.StatusOK, dojoPage{OK: "Connection works: DefectDojo accepted the token and found the engagement."}, err)
	})
	r.Handle(http.MethodPost, "/defectdojo/export", access, func(w http.ResponseWriter, req *http.Request) {
		if d.DefectDojo == nil {
			r.ServerError(w, req, errors.New("defectdojo: service not configured"))
			return
		}
		run := strings.TrimSpace(req.PostFormValue("run"))
		if pv, ok := d.DefectDojo.(dojoPreviewer); ok && req.PostFormValue("preview") == "1" {
			res, err := pv.Preview(req.Context(), run)
			if errors.Is(err, inventory.ErrUnknownRun) {
				err = fmt.Errorf("%w: run %q does not exist", inventory.ErrUnknownRun, run)
			}
			r.renderDojo(w, req, d.DefectDojo, runs, http.StatusOK, dojoPage{Run: run, OK: previewText(res)}, err)
			return
		}
		export := d.DefectDojo.Export
		if req.PostFormValue("force") == "1" {
			export = d.DefectDojo.ForceExport
		}
		res, err := export(req.Context(), dojoActor(req), run)
		page := dojoPage{Run: run, Exported: err == nil, Confirm: errors.Is(err, defectdojo.ErrOlderRun),
			OK: fmt.Sprintf("Exported run %s: %d hosts and %d services to test %d, %d findings to test %d.",
				res.Run, res.Hosts, res.Services, res.NmapTestID, res.Findings, res.FindingsTestID)}
		for _, r := range res.Recreated {
			page.OK += " " + capitalize(r) + "."
		}
		if errors.Is(err, inventory.ErrUnknownRun) {
			err = fmt.Errorf("%w: run %q does not exist", inventory.ErrUnknownRun, run)
		}
		r.renderDojo(w, req, d.DefectDojo, runs, http.StatusOK, page, err)
	})
}

func previewText(res defectdojo.Result) string {
	target := func(path string, id int) string {
		if path == defectdojo.ReimportPath {
			return fmt.Sprintf("updates test %d", id)
		}
		return "creates a new test"
	}
	return fmt.Sprintf("Preview of run %s: an export sends 2 tests to DefectDojo. The Nmap scan with %s and %s %s; the findings with %s %s. Nothing was sent.",
		res.Run, plural(res.Hosts, "host"), plural(res.Services, "service"), target(res.NmapPath, res.NmapTestID),
		plural(res.Findings, "finding"), target(res.FindingsPath, res.FindingsTestID))
}

func (r *Router) renderDojo(w http.ResponseWriter, req *http.Request, svc DefectDojo, runs runLister, status int, page dojoPage, actionErr error) {
	if svc == nil {
		r.ServerError(w, req, errors.New("defectdojo: service not configured"))
		return
	}
	v, err := svc.View(req.Context())
	if err != nil {
		r.ServerError(w, req, err)
		return
	}
	page.Settings = v
	_, page.Preview = svc.(dojoPreviewer)
	p, _ := auth.PrincipalFrom(req.Context())
	page.CanEdit = slices.Contains(p.Permissions, auth.PermScanConfigure)
	if page.Form == (defectdojo.Config{}) {
		page.Form = defectdojo.Config{BaseURL: v.BaseURL, ProductID: v.ProductID, EngagementID: v.EngagementID}
	}
	if runs != nil {
		list, err := runs.ListRuns(req.Context())
		if err != nil {
			r.ServerError(w, req, err)
			return
		}
		for _, run := range list {
			if run.Status == inventory.RunCompleted {
				page.Runs = append(page.Runs, run.Name)
			}
		}
	}
	if page.CanEdit && v.TokenSet {
		if ch, err := svc.Choices(req.Context(), page.Form.ProductID); err == nil {
			ch.Products = withChoice(ch.Products, page.Form.ProductID)
			ch.Engagements = withChoice(ch.Engagements, page.Form.EngagementID)
			page.Choices = &ch
		}
	}
	if actionErr != nil {
		page.OK = ""
		page.Error, status = dojoError(actionErr)
		if status == http.StatusInternalServerError {
			r.ServerError(w, req, actionErr)
			return
		}
	}
	r.Render(w, req, status, "defectdojo.html", View{Title: "DefectDojo", Data: page})
}

func withChoice(list []defectdojo.Choice, id int) []defectdojo.Choice {
	if id < 1 || slices.ContainsFunc(list, func(c defectdojo.Choice) bool { return c.ID == id }) {
		return list
	}
	return append(list, defectdojo.Choice{ID: id})
}

func dojoError(err error) (string, int) {
	var apiErr *defectdojo.APIError
	switch {
	case errors.Is(err, defectdojo.ErrInvalidConfig):
		return capitalize(strings.TrimPrefix(err.Error(), defectdojo.ErrInvalidConfig.Error()+": ")) + ".", http.StatusBadRequest
	case errors.Is(err, defectdojo.ErrOlderRun):
		return capitalize(strings.TrimPrefix(err.Error(), defectdojo.ErrOlderRun.Error()+": ")) + ".", http.StatusConflict
	case errors.Is(err, defectdojo.ErrTestsMissing):
		return capitalize(strings.TrimPrefix(err.Error(), defectdojo.ErrTestsMissing.Error()+": ")) + ".", http.StatusConflict
	case errors.Is(err, defectdojo.ErrNotSaved):
		return capitalize(err.Error()) + ". Check the values or save without the connection test.", http.StatusBadGateway
	case errors.Is(err, defectdojo.ErrNotConfigured):
		return capitalize(err.Error()) + ".", http.StatusConflict
	case errors.Is(err, inventory.ErrUnknownRun):
		return capitalize(strings.TrimPrefix(err.Error(), inventory.ErrUnknownRun.Error()+": ")) + ".", http.StatusNotFound
	case errors.As(err, &apiErr), strings.HasPrefix(err.Error(), "defectdojo "):
		return "DefectDojo request failed: " + err.Error(), http.StatusBadGateway
	}
	return "", http.StatusInternalServerError
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func formInt(req *http.Request, name string) int {
	n, err := strconv.Atoi(strings.TrimSpace(req.PostFormValue(name)))
	if err != nil {
		return 0
	}
	return n
}

func dojoActor(req *http.Request) auth.Actor {
	p, _ := auth.PrincipalFrom(req.Context())
	return auth.Actor{Username: p.Username, Addr: clientAddr(req)}
}
