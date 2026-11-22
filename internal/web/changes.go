package web

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"asi/internal/auth"
	"asi/internal/diff"
	"asi/internal/inventory"
)

type Inventory interface {
	ListRuns(ctx context.Context) ([]inventory.Run, error)
	Export(ctx context.Context, asOfRun string) (inventory.Export, error)
	HostTimeline(ctx context.Context, address string) (inventory.Timeline, error)
}

type changeKind struct {
	Type  string
	Label string
	Mark  string
}

var changeKinds = []changeKind{
	{diff.HostNew, "New host", "new"},
	{diff.HostMissing, "Missing host", "missing"},
	{diff.HostReturned, "Returned host", "returned"},
	{diff.HostInactive, "Inactive host", "inactive"},
	{diff.ServiceNew, "New service", "new"},
	{diff.ServiceMissing, "Missing service", "missing"},
	{diff.ServiceReturned, "Returned service", "returned"},
	{diff.ServiceInactive, "Inactive service", "inactive"},
	{diff.ServiceChanged, "Changed service", "changed"},
}

type changeField struct {
	Field string
	Old   string
	New   string
}

type changeRow struct {
	changeKind
	Address  string
	Timeline string
	Host     string
	Service  string
	Fields   []changeField
	HTTPGone bool
}

func (r changeRow) Folded() bool { return len(r.Fields) > maxInlineFields }

const maxInlineFields = 5

type changesData struct {
	Runs  []inventory.Run
	Kinds []changeKind
	From  string
	To    string
	Type  string
	Total int
	Rows  []changeRow
	Empty bool
}

func RegisterChanges(r *Router, d Deps) {
	inv := d.Inventory
	if inv == nil && d.Store != nil {
		inv = inventory.New(d.Store, d.Keyring)
	}
	access := Require(auth.PermInventoryRead)
	r.NavIn(NavOverview, "Changes", "/changes", access)
	r.Handle(http.MethodGet, "/changes", access, func(w http.ResponseWriter, req *http.Request) {
		r.changesPage(w, req, inv)
	})
	r.Handle(http.MethodGet, "/changes.json", access, func(w http.ResponseWriter, req *http.Request) {
		r.changesJSON(w, req, inv)
	})
}

func (r *Router) changesPage(w http.ResponseWriter, req *http.Request, inv Inventory) {
	if inv == nil {
		r.ServerError(w, req, errors.New("changes: no inventory configured"))
		return
	}
	q := req.URL.Query()
	data := changesData{Kinds: changeKinds, From: q.Get("from"), To: q.Get("to"), Type: q.Get("type")}
	if data.Type != "" && !slices.ContainsFunc(changeKinds, func(k changeKind) bool { return k.Type == data.Type }) {
		r.Error(w, req, http.StatusBadRequest, fmt.Sprintf("Unknown change type %q. Pick a type from the list on the changes page.", data.Type))
		return
	}
	if (data.From == "") != (data.To == "") {
		r.Error(w, req, http.StatusBadRequest, "Pick both a from run and a to run.")
		return
	}
	runs, err := inv.ListRuns(req.Context())
	if err != nil {
		r.ServerError(w, req, err)
		return
	}
	data.Runs = runs
	if data.From == "" {
		var completed []string
		for _, run := range runs {
			if run.Status == inventory.RunCompleted {
				completed = append(completed, run.Name)
			}
		}
		if len(completed) < 2 {
			data.Empty = true
			r.Render(w, req, http.StatusOK, "changes.html", View{Title: "Changes", Data: data})
			return
		}
		data.From, data.To = completed[1], completed[0]
	}
	dd, err := diff.Between(req.Context(), inv, data.From, data.To, diff.Options{})
	var unknown *diff.UnknownRunError
	if errors.As(err, &unknown) {
		r.Error(w, req, http.StatusNotFound, fmt.Sprintf("Run %q does not exist. Pick a run from the list on the changes page.", unknown.Name))
		return
	}
	if err != nil {
		r.ServerError(w, req, err)
		return
	}
	data.Total = len(dd.Changes)
	for _, c := range dd.Changes {
		if data.Type != "" && c.Type != data.Type {
			continue
		}
		data.Rows = append(data.Rows, newChangeRow(c))
	}
	r.Render(w, req, http.StatusOK, "changes.html", View{Title: "Changes", Data: data})
}

func (r *Router) changesJSON(w http.ResponseWriter, req *http.Request, inv Inventory) {
	if inv == nil {
		r.ServerError(w, req, errors.New("changes: no inventory configured"))
		return
	}
	q := req.URL.Query()
	from, to := q.Get("from"), q.Get("to")
	if from == "" || to == "" {
		http.Error(w, "from and to are required", http.StatusBadRequest)
		return
	}
	dd, err := diff.Between(req.Context(), inv, from, to, diff.Options{})
	var unknown *diff.UnknownRunError
	if errors.As(err, &unknown) {
		http.Error(w, unknown.Error(), http.StatusNotFound)
		return
	}
	var buf bytes.Buffer
	if err == nil {
		err = diff.WriteJSON(&buf, dd)
	}
	if err != nil {
		r.ServerError(w, req, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = buf.WriteTo(w)
}

func newChangeRow(c diff.Change) changeRow {
	row := changeRow{Address: c.Address, Timeline: "/hosts/" + url.PathEscape(c.Address) + "/timeline", Host: hostURL(c.Address)}
	for _, k := range changeKinds {
		if k.Type == c.Type {
			row.changeKind = k
		}
	}
	if c.Port != nil {
		row.Service = fmt.Sprintf("%d/%s", *c.Port, c.Protocol)
	}
	var httpFields, httpGone int
	statusGone := false
	for _, f := range c.Fields {
		cf := changeField{Field: f.Field, Old: fieldText(f.Old), New: fieldText(f.New)}
		if cf.Old == "" && cf.New == "" {
			continue
		}
		if strings.HasPrefix(cf.Field, "http.") {
			httpFields++
			if cf.New == "" {
				httpGone++
				statusGone = statusGone || cf.Field == "http.status_code"
			}
		}
		row.Fields = append(row.Fields, cf)
	}
	if c.Type == "service_changed" && statusGone && httpGone == httpFields {
		row.HTTPGone = true
		row.Fields = slices.DeleteFunc(row.Fields, func(f changeField) bool { return strings.HasPrefix(f.Field, "http.") })
	}
	return row
}

func fieldText(v any) string {
	switch v := v.(type) {
	case nil:
		return ""
	case []string:
		return strings.Join(v, ", ")
	case []any:
		parts := make([]string, len(v))
		for i, p := range v {
			parts[i] = fieldText(p)
		}
		return strings.Join(parts, ", ")
	}
	return fmt.Sprint(v)
}
