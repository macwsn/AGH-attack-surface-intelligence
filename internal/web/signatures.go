package web

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"asi/internal/auth"
	"asi/internal/detect"
	"asi/internal/inventory"
	"asi/internal/probe"
)

const maxImportBytes = 1 << 20

type signatureList struct {
	Signatures []detect.Stored
	Enabled    int
	Done       string
	ID         string
	Import     string
	Problem    *signatureProblem
}

type signatureForm struct {
	ID       string
	Source   string
	Enabled  bool
	Address  string
	Port     string
	Protocol string
	Problem  *signatureProblem
	Test     *signatureTest
}

type signatureProblem struct {
	Rule   string
	Detail string
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
	lib := detect.NewLibrary(d.Store, d.SignaturesDir)
	inv := inventory.New(d.Store, d.Keyring)
	access := Require(auth.PermSignatureManage)
	h := &signatureHandlers{r: r, lib: lib, inv: inv}
	r.Nav("Signatures", "/signatures", access)
	r.Handle(http.MethodGet, "/signatures", access, h.list)
	r.Handle(http.MethodGet, "/signatures/new", access, h.newForm)
	r.Handle(http.MethodPost, "/signatures", access, h.create)
	r.Handle(http.MethodGet, "/signatures/export", access, h.export)
	r.Handle(http.MethodPost, "/signatures/import", access, h.importYAML)
	r.Handle(http.MethodPost, "/signatures/test", access, h.test)
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
		return &signatureProblem{Rule: re.Rule, Detail: re.Detail}
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
	h.r.Render(w, req, status, "signature.html", View{Title: title, Data: f})
}

func (h *signatureHandlers) newForm(w http.ResponseWriter, req *http.Request) {
	h.renderForm(w, req, http.StatusOK, signatureForm{Source: signatureTemplate, Enabled: true})
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
	h.renderForm(w, req, http.StatusOK, signatureForm{ID: s.ID, Source: s.Source, Enabled: s.Enabled})
}

func readForm(w http.ResponseWriter, req *http.Request, limit int64) bool {
	req.Body = http.MaxBytesReader(w, req.Body, limit)
	return req.ParseForm() == nil
}

func formOf(req *http.Request) signatureForm {
	return signatureForm{
		Source:   strings.ReplaceAll(req.PostForm.Get("source"), "\r\n", "\n"),
		Enabled:  req.PostForm.Get("enabled") != "",
		Address:  strings.TrimSpace(req.PostForm.Get("address")),
		Port:     strings.TrimSpace(req.PostForm.Get("port")),
		Protocol: req.PostForm.Get("protocol"),
	}
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
	var stored *probe.HTTP
	t := &signatureTest{Service: fmt.Sprintf("%s %d/%s", f.Address, port, f.Protocol)}
	stored, t.Run, err = h.inv.LatestHTTP(req.Context(), f.Address, port, f.Protocol)
	if err != nil {
		if !errors.Is(err, inventory.ErrUnknownService) {
			h.r.ServerError(w, req, err)
			return
		}
		f.Problem = &signatureProblem{Detail: fmt.Sprintf("No stored observation of %s. Enter the address and port of a scanned service.", t.Service)}
		h.renderForm(w, req, http.StatusUnprocessableEntity, f)
		return
	}
	t.Evaluation = sig.EvaluateStored(stored)
	f.Test = t
	h.renderForm(w, req, http.StatusOK, f)
}
