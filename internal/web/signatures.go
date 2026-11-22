package web

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"asi/internal/auth"
	"asi/internal/detect"
	"asi/internal/inventory"
	"asi/internal/probe"
)

const maxImportBytes = 1 << 20

type signatureList struct {
	Signatures     []detect.Stored
	Enabled        int
	Builtin        []detect.Stored
	BuiltinEnabled int
	Done           string
	ID             string
	Import         string
	Problem        *signatureProblem
}

type signatureForm struct {
	ID       string
	Source   string
	Guided   *guidedForm
	Note     string
	Enabled  bool
	Builtin  bool
	Address  string
	Port     string
	Protocol string
	Since    string
	Problem  *signatureProblem
	Test     *signatureTest
	CanHunt  bool
}

type signatureProblem struct {
	Rule   string
	Detail string
	Field  string
}

type guidedForm struct {
	detect.Form
	Rows           []conditionRow
	Problems       map[string]string
	Kinds          []string
	Matchers       []string
	VersionSources []string
}

type conditionRow struct {
	detect.Condition
	Index   int
	Problem string
}

func newGuidedForm(f detect.Form) *guidedForm {
	return &guidedForm{Form: f, Kinds: detect.Kinds, Matchers: detect.FormMatchers, VersionSources: detect.VersionSources}
}

func guidedOf(form url.Values) detect.Form {
	f := detect.Form{ID: form.Get("f_id"), Name: form.Get("f_name"), Kind: form.Get("f_kind"), Category: form.Get("f_category"),
		Confidence: form.Get("f_confidence"), Any: form.Get("f_group") == "any", VersionFrom: form.Get("f_version_from"),
		VersionName: form.Get("f_version_name"), Version: form.Get("f_version"), Path: form.Get("f_path")}
	matchers, names, values := form["c_matcher"], form["c_name"], form["c_value"]
	for i, m := range matchers {
		c := detect.Condition{Matcher: m}
		if i < len(names) {
			c.Name = names[i]
		}
		if i < len(values) {
			c.Value = values[i]
		}
		f.Conditions = append(f.Conditions, c)
	}
	return f
}

func (f *signatureForm) setGuided(g detect.Form) {
	f.Guided = newGuidedForm(g)
	if src, err := g.YAML(); err == nil {
		f.Source = string(src)
	}
}

type signatureTest struct {
	Service string
	Run     string
	detect.Evaluation
}

const signatureTemplate = `- id: admin-panel-login
  name: Admin panel login form
  kind: admin-panel
  confidence: 80
  match:
    all:
      - {type: status, value: 200}
      - {type: title_regex, value: '(?i)admin'}
`

var signatureDone = map[string]string{
	"created":  "Signature %s created.",
	"saved":    "Signature %s saved.",
	"enabled":  "Signature %s enabled.",
	"disabled": "Signature %s disabled.",
	"deleted":  "Signature %s deleted.",
	"imported": "Imported %s signatures.",
}

func (s signatureList) Message() string {
	f, ok := signatureDone[s.Done]
	if !ok {
		return ""
	}
	return fmt.Sprintf(f, s.ID)
}

func RegisterSignatures(r *Router, d Deps) {
	lib := d.Library
	if lib == nil {
		lib = detect.NewLibrary(d.Store, d.Keyring, d.SignaturesDir)
	}
	inv := inventory.New(d.Store, d.Keyring)
	access := Require(auth.PermSignatureManage)
	reads := Require(auth.PermSignatureManage, auth.PermInventoryRead)
	h := &signatureHandlers{r: r, lib: lib, inv: inv}
	r.NavIn(NavScanning, "Signatures", "/signatures", access)
	r.Handle(http.MethodGet, "/signatures", access, h.list)
	r.Handle(http.MethodGet, "/signatures/new", access, h.newForm)
	r.Handle(http.MethodPost, "/signatures", access, h.create)
	r.Handle(http.MethodGet, "/signatures/export", access, h.export)
	r.Handle(http.MethodPost, "/signatures/import", access, h.importYAML)
	r.Handle(http.MethodPost, "/signatures/test", reads, h.test)
	r.Handle(http.MethodPost, "/signatures/form", access, h.redraw)
	r.Handle(http.MethodPost, "/signatures/hunt", reads, h.hunt)
	r.Handle(http.MethodGet, "/signatures/hunts/{id}", reads, h.huntResults)
	r.Handle(http.MethodGet, "/signatures/hunts/{id}/csv", Require(auth.PermSignatureManage, auth.PermInventoryRead, auth.PermExport), h.huntCSV)
	r.Handle(http.MethodPost, "/signatures/hunts/{id}/save", reads, h.saveHunt)
	r.Handle(http.MethodGet, "/signatures/{id}", access, h.editForm)
	r.Handle(http.MethodPost, "/signatures/{id}", access, h.update)
	r.Handle(http.MethodPost, "/signatures/{id}/enable", access, h.setEnabled(true))
	r.Handle(http.MethodPost, "/signatures/{id}/disable", access, h.setEnabled(false))
	r.Handle(http.MethodPost, "/signatures/{id}/delete", access, h.remove)
}

type signatureHandlers struct {
	r   *Router
	lib *detect.Library
	inv *inventory.Inventory
}

func actor(req *http.Request) detect.Actor {
	p, _ := auth.PrincipalFrom(req.Context())
	return detect.Actor{Username: p.Username, Addr: clientAddr(req)}
}

func problemOf(err error) *signatureProblem {
	var re *detect.RuleError
	if errors.As(err, &re) {
		return &signatureProblem{Rule: re.Rule, Detail: re.Detail, Field: re.Field}
	}
	return nil
}

func (h *signatureHandlers) renderList(w http.ResponseWriter, req *http.Request, status int, data signatureList) {
	list, err := h.lib.List(req.Context())
	if err != nil {
		h.r.ServerError(w, req, err)
		return
	}
	data.Signatures = list
	for _, s := range list {
		if s.Enabled {
			data.Enabled++
		}
	}
	if data.Builtin, err = h.lib.Builtin(req.Context()); err != nil {
		h.r.ServerError(w, req, err)
		return
	}
	for _, s := range data.Builtin {
		if s.Enabled {
			data.BuiltinEnabled++
		}
	}
	h.r.Render(w, req, status, "signatures.html", View{Title: "Signatures", Data: data})
}

func (h *signatureHandlers) list(w http.ResponseWriter, req *http.Request) {
	q := req.URL.Query()
	h.renderList(w, req, http.StatusOK, signatureList{Done: q.Get("done"), ID: q.Get("id")})
}

func (h *signatureHandlers) renderForm(w http.ResponseWriter, req *http.Request, status int, f signatureForm) {
	title := "New signature"
	if f.ID != "" {
		title = "Signature " + f.ID
	}
	if f.Protocol == "" {
		f.Protocol = "tcp"
	}
	f.CanHunt = can(req, auth.PermInventoryRead)
	if g := f.Guided; g != nil {
		g.Rows = g.Rows[:0]
		for i, c := range g.Conditions {
			g.Rows = append(g.Rows, conditionRow{Condition: c, Index: i})
		}
		if p := f.Problem; p != nil && p.Field != "" {
			msg := p.Detail
			if p.Rule != "" && p.Rule != detect.RuleSchema {
				msg = "Rule violated: " + p.Rule + ". " + p.Detail
			}
			g.Problems = map[string]string{p.Field: msg}
			for i := range g.Rows {
				g.Rows[i].Problem = g.Problems[detect.ConditionField(g.Group(), i)]
			}
		}
	}
	h.r.Render(w, req, status, "signature.html", View{Title: title, Data: f})
}

var newGuided = detect.Form{Kind: "technology", Confidence: "80", Conditions: []detect.Condition{{Matcher: "header"}}}

func (h *signatureHandlers) newForm(w http.ResponseWriter, req *http.Request) {
	f := signatureForm{Source: signatureTemplate, Enabled: true}
	if req.URL.Query().Get("view") != "yaml" {
		f.setGuided(newGuided)
	}
	h.renderForm(w, req, http.StatusOK, f)
}

func (h *signatureHandlers) editForm(w http.ResponseWriter, req *http.Request) {
	s, err := h.lib.Get(req.Context(), req.PathValue("id"))
	if errors.Is(err, detect.ErrUnknownSignature) {
		h.r.Error(w, req, http.StatusNotFound, "This signature does not exist.")
		return
	}
	if err != nil {
		h.r.ServerError(w, req, err)
		return
	}
	f := signatureForm{ID: s.ID, Source: s.Source, Enabled: s.Enabled, Builtin: s.Builtin}
	if !s.Builtin && req.URL.Query().Get("view") != "yaml" {
		if g, ok := detect.FormOf([]byte(s.Source)); ok {
			f.setGuided(g)
		} else {
			f.Note = "The form cannot show this signature: it uses both all and any, a HEAD request, a cookie value or a match group the form does not offer. Edit it as YAML."
		}
	}
	h.renderForm(w, req, http.StatusOK, f)
}

func (h *signatureHandlers) redraw(w http.ResponseWriter, req *http.Request) {
	if !readForm(w, req, maxFormBytes) {
		h.r.Error(w, req, http.StatusBadRequest, "The form could not be read.")
		return
	}
	f := formOf(req)
	f.ID = req.PostForm.Get("id")
	if f.Guided != nil {
		g := f.Guided.Form
		if req.PostForm.Get("add") != "" {
			g.Conditions = append(g.Conditions, detect.Condition{Matcher: "header"})
		}
		if i, err := strconv.Atoi(req.PostForm.Get("remove")); err == nil && i >= 0 && i < len(g.Conditions) {
			g.Conditions = slices.Delete(g.Conditions, i, i+1)
		}
		f.setGuided(g)
		if req.PostForm.Get("view") == "yaml" {
			f.Guided = nil
		}
	}
	h.renderForm(w, req, http.StatusOK, f)
}

func readForm(w http.ResponseWriter, req *http.Request, limit int64) bool {
	req.Body = http.MaxBytesReader(w, req.Body, limit)
	return req.ParseForm() == nil
}

func formOf(req *http.Request) signatureForm {
	f := signatureForm{
		Source:   strings.ReplaceAll(req.PostForm.Get("source"), "\r\n", "\n"),
		Enabled:  req.PostForm.Get("enabled") != "",
		Address:  strings.TrimSpace(req.PostForm.Get("address")),
		Port:     strings.TrimSpace(req.PostForm.Get("port")),
		Protocol: req.PostForm.Get("protocol"),
	}
	if req.PostForm.Get("mode") == "form" {
		f.setGuided(guidedOf(req.PostForm))
	}
	return f
}

func (h *signatureHandlers) saved(w http.ResponseWriter, req *http.Request, f signatureForm, done, id string, err error) {
	if err == nil {
		http.Redirect(w, req, "/signatures?done="+done+"&id="+url.QueryEscape(id), http.StatusSeeOther)
		return
	}
	if errors.Is(err, detect.ErrUnknownSignature) {
		h.r.Error(w, req, http.StatusNotFound, "This signature does not exist.")
		return
	}
	if f.Problem = problemOf(err); f.Problem == nil {
		h.r.ServerError(w, req, err)
		return
	}
	h.renderForm(w, req, http.StatusUnprocessableEntity, f)
}

func (h *signatureHandlers) create(w http.ResponseWriter, req *http.Request) {
	if !readForm(w, req, maxFormBytes) {
		h.r.Error(w, req, http.StatusBadRequest, "The form could not be read.")
		return
	}
	f := formOf(req)
	sig, err := h.lib.Create(req.Context(), actor(req), f.Source, f.Enabled)
	h.saved(w, req, f, "created", sig.ID, err)
}

func (h *signatureHandlers) update(w http.ResponseWriter, req *http.Request) {
	if !readForm(w, req, maxFormBytes) {
		h.r.Error(w, req, http.StatusBadRequest, "The form could not be read.")
		return
	}
	f := formOf(req)
	f.ID = req.PathValue("id")
	_, err := h.lib.Update(req.Context(), actor(req), f.ID, f.Source, f.Enabled)
	h.saved(w, req, f, "saved", f.ID, err)
}

func (h *signatureHandlers) setEnabled(on bool) http.HandlerFunc {
	done := "disabled"
	if on {
		done = "enabled"
	}
	return func(w http.ResponseWriter, req *http.Request) {
		id := req.PathValue("id")
		h.listAction(w, req, done, id, h.lib.SetEnabled(req.Context(), actor(req), id, on))
	}
}

func (h *signatureHandlers) remove(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")
	h.listAction(w, req, "deleted", id, h.lib.Delete(req.Context(), actor(req), id))
}

func (h *signatureHandlers) listAction(w http.ResponseWriter, req *http.Request, done, id string, err error) {
	if err == nil {
		http.Redirect(w, req, "/signatures?done="+done+"&id="+url.QueryEscape(id), http.StatusSeeOther)
		return
	}
	if errors.Is(err, detect.ErrUnknownSignature) {
		h.r.Error(w, req, http.StatusNotFound, "This signature does not exist.")
		return
	}
	p := problemOf(err)
	if p == nil {
		h.r.ServerError(w, req, err)
		return
	}
	h.renderList(w, req, http.StatusUnprocessableEntity, signatureList{Problem: p})
}

func (h *signatureHandlers) importYAML(w http.ResponseWriter, req *http.Request) {
	if !readForm(w, req, maxImportBytes+maxFormBytes) {
		h.r.Error(w, req, http.StatusRequestEntityTooLarge, "The import is larger than 1 MiB.")
		return
	}
	data := req.PostForm.Get("yaml")
	ids, err := h.lib.Import(req.Context(), actor(req), []byte(data))
	if err == nil {
		http.Redirect(w, req, "/signatures?done=imported&id="+strconv.Itoa(len(ids)), http.StatusSeeOther)
		return
	}
	p := problemOf(err)
	if p == nil {
		h.r.ServerError(w, req, err)
		return
	}
	h.renderList(w, req, http.StatusUnprocessableEntity, signatureList{Import: data, Problem: p})
}

func (h *signatureHandlers) export(w http.ResponseWriter, req *http.Request) {
	out, err := h.lib.Export(req.Context())
	if err != nil {
		h.r.ServerError(w, req, err)
		return
	}
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="signatures.yaml"`)
	_, _ = w.Write(out)
}

func (h *signatureHandlers) test(w http.ResponseWriter, req *http.Request) {
	if !readForm(w, req, maxFormBytes) {
		h.r.Error(w, req, http.StatusBadRequest, "The form could not be read.")
		return
	}
	f := formOf(req)
	f.ID = req.PostForm.Get("id")
	sig, err := detect.ParseOne([]byte(f.Source))
	if err != nil {
		f.Problem = problemOf(err)
		h.renderForm(w, req, http.StatusUnprocessableEntity, f)
		return
	}
	port, perr := strconv.Atoi(f.Port)
	_, aerr := netip.ParseAddr(f.Address)
	var bad string
	switch {
	case aerr != nil:
		bad = fmt.Sprintf("%q is not an address. Enter the IPv4 address of a scanned service.", f.Address)
	case perr != nil || port < 1 || port > 65535:
		bad = fmt.Sprintf("%q is not a port. Enter a port between 1 and 65535.", f.Port)
	case f.Protocol != "tcp" && f.Protocol != "udp":
		bad = fmt.Sprintf("%q is not a protocol. Choose tcp or udp.", f.Protocol)
	}
	if bad != "" {
		f.Problem = &signatureProblem{Detail: bad}
		h.renderForm(w, req, http.StatusUnprocessableEntity, f)
		return
	}
	var (
		stored *probe.HTTP
		body   []byte
	)
	t := &signatureTest{Service: fmt.Sprintf("%s %d/%s", f.Address, port, f.Protocol)}
	stored, body, t.Run, err = h.inv.LatestHTTP(req.Context(), f.Address, port, f.Protocol)
	if err != nil {
		if !errors.Is(err, inventory.ErrUnknownService) {
			h.r.ServerError(w, req, err)
			return
		}
		f.Problem = &signatureProblem{Detail: fmt.Sprintf("No stored observation of %s. Enter the address and port of a scanned service.", t.Service)}
		h.renderForm(w, req, http.StatusUnprocessableEntity, f)
		return
	}
	t.Evaluation, _ = sig.EvaluateHistory(stored, body)
	f.Test = t
	h.renderForm(w, req, http.StatusOK, f)
}
