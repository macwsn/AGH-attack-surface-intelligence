package web

import (
	"encoding/csv"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"asi/internal/auth"
	"asi/internal/detect"
	"asi/internal/exchange"
	"asi/internal/inventory"
)

const huntPageSize = 50

type huntPage struct {
	Hunt       inventory.Hunt
	Results    []inventory.HuntResult
	Total      int
	From, To   int
	Page       int
	Pages      int
	PrevURL    string
	NextURL    string
	Took       string
	Saved      bool
	Recorded   *int
	Problem    *signatureProblem
	SinceLabel string
	CanExport  bool
	CanRecord  bool
}

func (h *signatureHandlers) hunt(w http.ResponseWriter, req *http.Request) {
	if !readForm(w, req, maxFormBytes) {
		h.r.Error(w, req, http.StatusBadRequest, "The form could not be read.")
		return
	}
	f := formOf(req)
	f.ID = req.PostForm.Get("id")
	f.Since = req.PostForm.Get("since")
	sig, err := detect.ParseOne([]byte(f.Source))
	if err != nil {
		f.Problem = problemOf(err)
		h.renderForm(w, req, http.StatusUnprocessableEntity, f)
		return
	}
	spec := inventory.HuntSpec{Signature: sig, Source: f.Source}
	if f.Since != "" {
		d, err := inventory.ParseSince(f.Since)
		if err != nil {
			f.Problem = &signatureProblem{Detail: fmt.Sprintf("%q is not a period. Choose one of the listed periods.", f.Since)}
			h.renderForm(w, req, http.StatusUnprocessableEntity, f)
			return
		}
		spec.Since = time.Now().Add(-d)
	}
	a := actor(req)
	spec.Actor, spec.Addr = a.Username, a.Addr
	hunt, err := h.inv.RunHunt(req.Context(), spec)
	if err != nil {
		h.r.ServerError(w, req, err)
		return
	}
	http.Redirect(w, req, "/signatures/hunts/"+strconv.FormatInt(hunt.ID, 10), http.StatusSeeOther)
}

func (h *signatureHandlers) loadHunt(w http.ResponseWriter, req *http.Request) (inventory.Hunt, bool) {
	var hunt inventory.Hunt
	id, err := strconv.ParseInt(req.PathValue("id"), 10, 64)
	if err == nil {
		hunt, err = h.inv.GetHunt(req.Context(), id)
		if err == nil {
			return hunt, true
		}
		if !errors.Is(err, inventory.ErrUnknownHunt) {
			h.r.ServerError(w, req, err)
			return hunt, false
		}
	}
	h.r.Error(w, req, http.StatusNotFound, "This hunt does not exist. Start a hunt from a signature.")
	return hunt, false
}

func (h *signatureHandlers) huntResults(w http.ResponseWriter, req *http.Request) {
	hunt, ok := h.loadHunt(w, req)
	if !ok {
		return
	}
	q := req.URL.Query()
	p := huntPage{Hunt: hunt, Saved: q.Get("saved") != ""}
	if n, err := strconv.Atoi(q.Get("recorded")); err == nil {
		p.Recorded = &n
	}
	p.Page, _ = strconv.Atoi(q.Get("page"))
	h.renderHunt(w, req, http.StatusOK, p)
}

func (h *signatureHandlers) renderHunt(w http.ResponseWriter, req *http.Request, status int, p huntPage) {
	p.Total = p.Hunt.Matched + p.Hunt.NotEvaluable
	p.Pages = max(1, (p.Total+huntPageSize-1)/huntPageSize)
	p.Page = min(max(p.Page, 1), p.Pages)
	offset := (p.Page - 1) * huntPageSize
	err := h.inv.HuntResults(req.Context(), p.Hunt.ID, offset, huntPageSize, func(r inventory.HuntResult) error {
		p.Results = append(p.Results, r)
		return nil
	})
	if err != nil {
		h.r.ServerError(w, req, err)
		return
	}
	if len(p.Results) > 0 {
		p.From, p.To = offset+1, offset+len(p.Results)
	}
	base := fmt.Sprintf("/signatures/hunts/%d?page=", p.Hunt.ID)
	if p.Page > 1 {
		p.PrevURL = base + strconv.Itoa(p.Page-1)
	}
	if p.Page < p.Pages {
		p.NextURL = base + strconv.Itoa(p.Page+1)
	}
	p.Took = p.Hunt.Duration.Round(time.Millisecond).String()
	p.CanExport, p.CanRecord = can(req, auth.PermExport), can(req, auth.PermInventoryEdit)
	p.SinceLabel = "all stored runs"
	if p.Hunt.Since != nil {
		p.SinceLabel = "runs started since " + zonedTime(*p.Hunt.Since, nil)
	}
	h.r.Render(w, req, status, "hunt.html", View{Title: "Hunt for " + p.Hunt.SignatureID, Data: p})
}

func (h *signatureHandlers) huntCSV(w http.ResponseWriter, req *http.Request) {
	hunt, ok := h.loadHunt(w, req)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="hunt-%d-%s.csv"`, hunt.ID, hunt.SignatureID))
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"address", "port", "protocol", "evaluable", "first_run", "last_run", "matches_latest_run", "version"})
	err := h.inv.HuntResults(req.Context(), hunt.ID, 0, 0, func(r inventory.HuntResult) error {
		return cw.Write(exchange.NeutralizeRow([]string{r.Address, strconv.Itoa(r.Port), r.Protocol, strconv.FormatBool(r.Evaluable),
			r.FirstRun, r.LastRun, strconv.FormatBool(r.InLatest), r.Version}))
	})
	cw.Flush()
	if err == nil {
		err = cw.Error()
	}
	if err != nil {
		h.r.ServerError(w, req, err)
	}
}

func (h *signatureHandlers) saveHunt(w http.ResponseWriter, req *http.Request) {
	hunt, ok := h.loadHunt(w, req)
	if !ok {
		return
	}
	if !readForm(w, req, maxFormBytes) {
		h.r.Error(w, req, http.StatusBadRequest, "The form could not be read.")
		return
	}
	if req.PostForm.Get("record") != "" && !can(req, auth.PermInventoryEdit) {
		h.r.Error(w, req, http.StatusForbidden, "Your role does not allow recording findings.")
		return
	}
	ctx, a := req.Context(), actor(req)
	stored, err := h.lib.Get(ctx, hunt.SignatureID)
	switch {
	case errors.Is(err, detect.ErrUnknownSignature):
		_, err = h.lib.Create(ctx, a, hunt.Source, true)
	case err == nil:
		_, err = h.lib.Update(ctx, a, hunt.SignatureID, hunt.Source, stored.Enabled)
	}
	if err != nil {
		p := problemOf(err)
		if p == nil {
			h.r.ServerError(w, req, err)
			return
		}
		h.renderHunt(w, req, http.StatusUnprocessableEntity, huntPage{Hunt: hunt, Problem: p})
		return
	}
	done := fmt.Sprintf("/signatures/hunts/%d?saved=1", hunt.ID)
	if req.PostForm.Get("record") != "" {
		n, err := h.inv.RecordHuntFindings(ctx, hunt.ID, a.Username, a.Addr)
		if errors.Is(err, inventory.ErrStaleHunt) {
			h.renderHunt(w, req, http.StatusConflict, huntPage{Hunt: hunt, Saved: true, Problem: &signatureProblem{
				Detail: "No findings were recorded: a run newer than " + hunt.LatestRun + " exists. Hunt again to record findings of the latest run."}})
			return
		}
		if err != nil {
			h.r.ServerError(w, req, err)
			return
		}
		done += "&recorded=" + strconv.Itoa(n)
	}
	http.Redirect(w, req, done, http.StatusSeeOther)
}

func (huntPage) N(n int) string {
	s := strconv.Itoa(n)
	if n < 1000 {
		return s
	}
	var out []byte
	for i := range len(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, " "...)
		}
		out = append(out, s[i])
	}
	return string(out)
}
