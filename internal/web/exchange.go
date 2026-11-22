package web

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"asi/internal/auth"
	"asi/internal/diff"
	"asi/internal/exchange"
	"asi/internal/inventory"
)

const (
	maxUploadBody   = exchange.MaxUploadBytes + 1<<20
	entryServiceRow = 3
)

type exportPage struct {
	Run, Status, Query, Tag string
	Hosts                   int
	AsOf                    string
	Error                   string
	Runs                    []inventory.Run
}

type importPage struct {
	Format       string
	Name         string
	DryRun       bool
	Error        string
	Report       *reportView
	Token        string
	ConfirmHosts int
	Columns      []exchange.CSVColumn
}

type reportView struct {
	exchange.Report
	Changes []changeView
	Changed int
}

const (
	pendingTTL   = 15 * time.Minute
	pendingBytes = 3 * exchange.MaxUploadBytes
)

type pendingImport struct {
	user    string
	format  string
	name    string
	data    []byte
	expires time.Time
}

type pendingImports struct {
	mu    sync.Mutex
	items map[string]pendingImport
	now   func() time.Time
}

var errPendingGone = errors.New("pending import expired or unknown")

func (c *pendingImports) put(user, format, name string, data []byte) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("import token: %w", err)
	}
	token := hex.EncodeToString(b)
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	total := len(data)
	for k, p := range c.items {
		if p.user == user || now.After(p.expires) {
			delete(c.items, k)
			continue
		}
		total += len(p.data)
	}
	for total > pendingBytes && len(c.items) > 0 {
		oldest := ""
		for k, p := range c.items {
			if oldest == "" || p.expires.Before(c.items[oldest].expires) {
				oldest = k
			}
		}
		total -= len(c.items[oldest].data)
		delete(c.items, oldest)
	}
	c.items[token] = pendingImport{user: user, format: format, name: name, data: data, expires: now.Add(pendingTTL)}
	return token, nil
}

func (c *pendingImports) take(token, user string) (pendingImport, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.items[token]
	if !ok || p.user != user {
		return pendingImport{}, errPendingGone
	}
	delete(c.items, token)
	if c.now().After(p.expires) {
		return pendingImport{}, errPendingGone
	}
	return p, nil
}

func (v reportView) Counts() string {
	return plural(v.Hosts, "host") + " and " + plural(v.Services, "service")
}

type changeView struct {
	Type, Label, Where string
	Fields             []diff.FieldChange
}

type entryPage struct {
	Form    exchange.HostForm
	Editing string
	Exists  string
	Report  *reportView
	Error   string
}

type entryRow struct {
	N       int
	Service exchange.ServiceForm
}

func (p entryPage) Rows() []entryRow {
	rows := make([]entryRow, len(p.Form.Services))
	for i, s := range p.Form.Services {
		rows[i] = entryRow{N: i + 1, Service: s}
	}
	return rows
}

func RegisterExchange(r *Router, d Deps) {
	inv := d.store()
	r.NavIn(NavData, "Import", "/import", Require(auth.PermImport))
	r.NavIn(NavData, "Export", "/export", Require(auth.PermExport))

	r.Handle(http.MethodGet, "/export", Require(auth.PermExport), func(w http.ResponseWriter, req *http.Request) {
		data := exportFilter(req)
		runs, err := inv.ListRuns(req.Context())
		if err != nil {
			r.ServerError(w, req, err)
			return
		}
		data.Runs = runs
		exp, err := filteredExport(req, inv)
		if errors.Is(err, inventory.ErrUnknownRun) {
			data.Error = fmt.Sprintf("Run %q does not exist. Pick a run from the list.", data.Run)
			r.Render(w, req, http.StatusNotFound, "export.html", View{Title: "Export", Data: data})
			return
		}
		if err != nil {
			r.ServerError(w, req, err)
			return
		}
		data.Hosts, data.AsOf = len(exp.Hosts), exp.Run
		r.Render(w, req, http.StatusOK, "export.html", View{Title: "Export", Data: data})
	})
	for _, format := range []string{"json", "csv"} {
		r.Handle(http.MethodGet, "/export."+format, Require(auth.PermExport), func(w http.ResponseWriter, req *http.Request) {
			exp, err := filteredExport(req, inv)
			if errors.Is(err, inventory.ErrUnknownRun) {
				r.Error(w, req, http.StatusNotFound, fmt.Sprintf("Run %q does not exist.", req.URL.Query().Get("run")))
				return
			}
			if err != nil {
				r.ServerError(w, req, err)
				return
			}
			var buf bytes.Buffer
			contentType := "text/csv; charset=utf-8"
			if format == "csv" {
				err = exchange.WriteCSV(&buf, exp)
			} else {
				contentType = "application/json"
				err = exchange.WriteJSON(&buf, exp)
			}
			if err != nil {
				r.ServerError(w, req, err)
				return
			}
			w.Header().Set("Content-Type", contentType)
			w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="asi-export-%s.%s"`, safeName(exp.Run), format))
			_, _ = buf.WriteTo(w)
		})
	}

	pending := &pendingImports{items: map[string]pendingImport{}, now: time.Now}
	importFile := func(w http.ResponseWriter, req *http.Request, page importPage, data []byte) (importPage, int, bool) {
		batch, err := exchange.Parse(page.Format, data)
		if err != nil {
			page.Error = "The file could not be read: " + err.Error()
			return page, http.StatusBadRequest, true
		}
		sigs, err := d.signatureSet(req.Context())
		if err != nil {
			r.ServerError(w, req, err)
			return page, 0, false
		}
		rep, err := exchange.Apply(req.Context(), inv, batch, exchange.Options{Name: page.Name, DryRun: page.DryRun,
			Source: inventory.SourceImport, Signatures: sigs, Actor: editorOf(req)})
		var status int
		page.Report, page.Error, status = applied(rep, err)
		if status >= 500 {
			r.ServerError(w, req, errors.New(page.Error))
			return page, 0, false
		}
		return page, status, true
	}
	render := func(w http.ResponseWriter, req *http.Request, status int, page importPage) {
		page.Columns = exchange.CSVColumns
		r.Render(w, req, htmxStatus(req, status), "import.html", View{Title: "Import", Data: page})
	}
	r.Handle(http.MethodGet, "/import", Require(auth.PermImport), func(w http.ResponseWriter, req *http.Request) {
		render(w, req, http.StatusOK, importPage{DryRun: true})
	})
	for _, format := range []string{"csv", "json"} {
		r.Handle(http.MethodGet, "/import/sample."+format, Require(auth.PermImport), func(w http.ResponseWriter, req *http.Request) {
			data, err := exchange.Sample(format)
			if err != nil {
				r.ServerError(w, req, err)
				return
			}
			contentType := "text/csv; charset=utf-8"
			if format == "json" {
				contentType = "application/json"
			}
			w.Header().Set("Content-Type", contentType)
			w.Header().Set("Content-Disposition", `attachment; filename="asi-import-sample.`+format+`"`)
			_, _ = w.Write(data)
		})
	}
	r.Handle(http.MethodPost, "/import", Require(auth.PermImport), func(w http.ResponseWriter, req *http.Request) {
		page, data, status := readUpload(w, req)
		if status == http.StatusOK {
			var ok bool
			if page, status, ok = importFile(w, req, page, data); !ok {
				return
			}
			if status == http.StatusOK && page.DryRun && page.Report != nil && page.Report.Hosts > 0 {
				p, _ := auth.PrincipalFrom(req.Context())
				token, err := pending.put(p.Username, page.Format, page.Name, data)
				if err != nil {
					r.ServerError(w, req, err)
					return
				}
				page.Token, page.ConfirmHosts = token, page.Report.Hosts
			}
		}
		render(w, req, status, page)
	})
	r.Handle(http.MethodPost, "/import/confirm", Require(auth.PermImport), func(w http.ResponseWriter, req *http.Request) {
		req.Body = http.MaxBytesReader(w, req.Body, maxFormBytes)
		if err := req.ParseForm(); err != nil {
			r.Error(w, req, http.StatusBadRequest, "The form could not be read.")
			return
		}
		p, _ := auth.PrincipalFrom(req.Context())
		up, err := pending.take(req.PostForm.Get("token"), p.Username)
		if err != nil {
			render(w, req, http.StatusGone, importPage{DryRun: true,
				Error: "This dry run has expired or was started by another user, so nothing was imported. Upload the file again."})
			return
		}
		page, status, ok := importFile(w, req, importPage{Format: up.format, Name: up.name}, up.data)
		if !ok {
			return
		}
		page.DryRun = true
		render(w, req, status, page)
	})

	r.Handle(http.MethodGet, "/hosts/entry", Require(auth.PermInventoryCreate), func(w http.ResponseWriter, req *http.Request) {
		form := exchange.HostForm{Address: strings.TrimSpace(req.URL.Query().Get("address"))}
		if form.Address != "" {
			if !allowed(req, auth.PermInventoryRead) {
				r.Error(w, req, http.StatusForbidden, "Your role does not allow viewing hosts.")
				return
			}
			exp, err := inv.Export(req.Context(), "")
			if err != nil {
				r.ServerError(w, req, err)
				return
			}
			found := false
			for _, h := range exp.Hosts {
				if h.Address == form.Address {
					form, found = exchange.FormFromHost(h), true
				}
			}
			if !found {
				r.Error(w, req, http.StatusNotFound, fmt.Sprintf("Host %q is not in the inventory.", form.Address))
				return
			}
			if !allowed(req, auth.PermInventoryEdit) {
				r.Error(w, req, http.StatusForbidden, "Your role does not allow editing hosts.")
				return
			}
		}
		form.Pad(entryServiceRow)
		r.Render(w, req, http.StatusOK, "host_entry.html", View{Title: "Add or edit a host", Data: entryPage{Form: form, Editing: form.Address}})
	})
	r.Handle(http.MethodPost, "/hosts/entry", Require(auth.PermInventoryCreate), func(w http.ResponseWriter, req *http.Request) {
		req.Body = http.MaxBytesReader(w, req.Body, maxFormBytes)
		if err := req.ParseForm(); err != nil {
			r.Error(w, req, http.StatusBadRequest, "The form could not be read.")
			return
		}
		form := exchange.HostFormFrom(req.PostForm)
		page := entryPage{Form: form, Editing: strings.TrimSpace(req.PostForm.Get("editing"))}
		addr := canonicalAddress(form.Address)
		if page.Editing != "" && canonicalAddress(page.Editing) != addr {
			page.Editing = ""
		}
		if page.Editing != "" && !allowed(req, auth.PermInventoryEdit) {
			r.Error(w, req, http.StatusForbidden, "Your role does not allow editing hosts.")
			return
		}
		if page.Editing == "" && addr != "" {
			_, err := inv.GetHostUserFields(req.Context(), addr)
			if err == nil {
				page.Exists = addr
				page.Form.Pad(entryServiceRow)
				r.Render(w, req, http.StatusConflict, "host_entry.html", View{Title: "Add or edit a host", Data: page})
				return
			}
			if !errors.Is(err, inventory.ErrUnknownHost) {
				r.ServerError(w, req, err)
				return
			}
		}
		sigs, err := d.signatureSet(req.Context())
		if err != nil {
			r.ServerError(w, req, err)
			return
		}
		rep, err := exchange.Apply(req.Context(), inv, form.Batch(), exchange.Options{Source: inventory.SourceManual,
			Signatures: sigs, ReplaceUserFields: true, KeepStored: true, Actor: editorOf(req)})
		var status int
		page.Report, page.Error, status = applied(rep, err)
		if status >= 500 {
			r.ServerError(w, req, errors.New(page.Error))
			return
		}
		if status == http.StatusOK && rep.Invalid > 0 {
			status = http.StatusUnprocessableEntity
		}
		if status == http.StatusOK {
			page.Editing = addr
		}
		page.Form.Pad(entryServiceRow)
		r.Render(w, req, status, "host_entry.html", View{Title: "Add or edit a host", Data: page})
	})
}

func applied(rep exchange.Report, err error) (*reportView, string, int) {
	view := &reportView{Report: rep}
	for _, c := range rep.Changes.Changes {
		where := c.Address
		if c.Port != nil {
			where = fmt.Sprintf("%s:%d/%s", c.Address, *c.Port, c.Protocol)
		}
		label, kind := changeLabel(c.Type)
		if kind == "changed" || kind == "returned" {
			view.Changed++
		}
		view.Changes = append(view.Changes, changeView{Type: kind, Label: label, Where: where, Fields: c.Fields})
	}
	switch {
	case errors.Is(err, exchange.ErrNothingToImport):
		return view, "Nothing was imported: no row is valid.", http.StatusUnprocessableEntity
	case errors.Is(err, inventory.ErrRunExists):
		return view, fmt.Sprintf("A run named %q already exists. Choose another name.", rep.Run), http.StatusConflict
	case err != nil:
		return nil, err.Error(), http.StatusInternalServerError
	}
	return view, "", http.StatusOK
}

func changeLabel(t string) (string, string) {
	switch t {
	case diff.HostNew:
		return "New host", "new"
	case diff.ServiceNew:
		return "New service", "new"
	case diff.HostReturned, diff.ServiceReturned:
		return "Returned", "returned"
	case diff.HostMissing, diff.ServiceMissing:
		return "Missing", "missing"
	case diff.HostInactive, diff.ServiceInactive:
		return "Inactive", "missing"
	}
	return "Changed", "changed"
}

func allowed(req *http.Request, perm auth.Permission) bool {
	p, ok := auth.PrincipalFrom(req.Context())
	return ok && slices.Contains(p.Permissions, perm)
}

func canonicalAddress(s string) string {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return ""
	}
	return a.Unmap().String()
}

func readUpload(w http.ResponseWriter, req *http.Request) (importPage, []byte, int) {
	page := importPage{}
	req.Body = http.MaxBytesReader(w, req.Body, maxUploadBody)
	mr, err := req.MultipartReader()
	if err != nil {
		page.Error = "Choose a file to upload."
		return page, nil, http.StatusBadRequest
	}
	var (
		data     []byte
		filename string
		gotFile  bool
	)
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return uploadError(page, err)
		}
		switch part.FormName() {
		case "file":
			filename, gotFile = part.FileName(), true
			if data, err = exchange.ReadAll(part); err != nil {
				return uploadError(page, err)
			}
		case "format", "name", "dry_run":
			v, err := io.ReadAll(io.LimitReader(part, 256))
			if err != nil {
				return uploadError(page, err)
			}
			switch part.FormName() {
			case "format":
				page.Format = strings.TrimSpace(string(v))
			case "name":
				page.Name = strings.TrimSpace(string(v))
			case "dry_run":
				page.DryRun = len(v) > 0
			}
		}
		part.Close()
	}
	if page.Format == "" {
		page.Format = strings.TrimPrefix(strings.ToLower(path.Ext(filename)), ".")
	}
	if !gotFile || len(data) == 0 {
		page.Error = "Choose a file to upload."
		return page, nil, http.StatusBadRequest
	}
	if page.Format != "json" && page.Format != "csv" {
		page.Error = fmt.Sprintf("%q is not a format. Choose JSON or CSV.", page.Format)
		return page, nil, http.StatusBadRequest
	}
	return page, data, http.StatusOK
}

func uploadError(page importPage, err error) (importPage, []byte, int) {
	var mbe *http.MaxBytesError
	if errors.Is(err, exchange.ErrTooLarge) || errors.As(err, &mbe) {
		page.Error = fmt.Sprintf("The file is larger than %d MiB. Split it and upload the parts.", exchange.MaxUploadBytes>>20)
		return page, nil, http.StatusRequestEntityTooLarge
	}
	page.Error = "The upload could not be read. Try again."
	return page, nil, http.StatusBadRequest
}

func htmxStatus(req *http.Request, status int) int {
	if req.Header.Get("HX-Request") != "" {
		return http.StatusOK
	}
	return status
}

func exportFilter(req *http.Request) exportPage {
	q := req.URL.Query()
	return exportPage{Run: strings.TrimSpace(q.Get("run")), Status: q.Get("status"), Query: strings.TrimSpace(q.Get("q")),
		Tag: strings.TrimSpace(q.Get("tag"))}
}

func filteredExport(req *http.Request, inv *inventory.Inventory) (inventory.Export, error) {
	f := exportFilter(req)
	exp, err := inv.Report(req.Context(), f.Run)
	if err != nil {
		return inventory.Export{}, err
	}
	return exchange.Filter{Status: f.Status, Query: f.Query, Tag: f.Tag}.Apply(exp), nil
}

func safeName(s string) string {
	if s == "" {
		return "empty"
	}
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			return r
		}
		return '_'
	}, s)
}
