package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"asi/internal/auth"
)

type AuditLog interface {
	ListAudit(ctx context.Context, f auth.AuditFilter, offset, limit int) ([]auth.AuditEntry, int, error)
	ListAuditActions(ctx context.Context) ([]string, error)
}

const auditPageSize = 50

type auditFilter struct {
	Actor, Action, Target, From, To string
	Page                            int
}

type auditRow struct {
	auth.AuditEntry
	When string
}

type auditPage struct {
	Filter      auditFilter
	Actions     []string
	Rows        []auditRow
	Total       string
	First, Last int
	Page, Pages int
	PrevURL     string
	NextURL     string
	Filtered    bool
}

func (f auditFilter) url(page int) string {
	q := url.Values{}
	for k, v := range map[string]string{"actor": f.Actor, "action": f.Action, "target": f.Target, "from": f.From, "to": f.To} {
		if v != "" {
			q.Set(k, v)
		}
	}
	if page > 1 {
		q.Set("page", strconv.Itoa(page))
	}
	if len(q) == 0 {
		return "/audit"
	}
	return "/audit?" + q.Encode()
}

var auditTimeLayouts = []string{"2006-01-02 15:04", "2006-01-02T15:04", "2006-01-02"}

func parseAuditTime(s string, end bool) (time.Time, bool) {
	for _, layout := range auditTimeLayouts {
		t, err := time.ParseInLocation(layout, s, time.Local)
		if err != nil {
			continue
		}
		if end && layout == "2006-01-02" {
			return t.AddDate(0, 0, 1), true
		}
		if end {
			return t.Add(time.Minute), true
		}
		return t, true
	}
	return time.Time{}, false
}

func parseAuditFilter(q url.Values) (auditFilter, auth.AuditFilter, string) {
	get := func(k string) string { return strings.TrimSpace(q.Get(k)) }
	f := auditFilter{Actor: get("actor"), Action: get("action"), Target: get("target"), From: get("from"), To: get("to"), Page: 1}
	af := auth.AuditFilter{Actor: f.Actor, Action: f.Action, Target: f.Target}
	var ok bool
	if f.From != "" {
		if af.Since, ok = parseAuditTime(f.From, false); !ok {
			return f, af, fmt.Sprintf("From %q is not a date like 2026-11-21 or 2026-11-21 14:05.", f.From)
		}
	}
	if f.To != "" {
		if af.Until, ok = parseAuditTime(f.To, true); !ok {
			return f, af, fmt.Sprintf("To %q is not a date like 2026-11-21 or 2026-11-21 14:05.", f.To)
		}
	}
	if p := get("page"); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 {
			return f, af, fmt.Sprintf("Page %q is not a positive number.", p)
		}
		f.Page = n
	}
	return f, af, ""
}

func RegisterAudit(r *Router, d Deps) {
	access := Require(auth.PermUserManage)
	r.NavIn(NavAdministration, "Audit log", "/audit", access)
	r.Handle(http.MethodGet, "/audit", access, func(w http.ResponseWriter, req *http.Request) {
		if d.Audit == nil {
			r.ServerError(w, req, errors.New("audit: audit log is not configured"))
			return
		}
		f, af, problem := parseAuditFilter(req.URL.Query())
		if problem != "" {
			r.Error(w, req, http.StatusBadRequest, problem)
			return
		}
		entries, total, err := d.Audit.ListAudit(req.Context(), af, (f.Page-1)*auditPageSize, auditPageSize)
		if err != nil {
			r.ServerError(w, req, err)
			return
		}
		actions, err := d.Audit.ListAuditActions(req.Context())
		if err != nil {
			r.ServerError(w, req, err)
			return
		}
		if f.Action != "" && !slices.Contains(actions, f.Action) {
			actions = append(actions, f.Action)
		}
		pages := max(1, (total+auditPageSize-1)/auditPageSize)
		v := auditPage{Filter: f, Actions: actions, Total: count(total), Page: f.Page, Pages: pages,
			Filtered: f.Actor != "" || f.Action != "" || f.Target != "" || f.From != "" || f.To != ""}
		if len(entries) > 0 {
			v.First = (f.Page-1)*auditPageSize + 1
			v.Last = v.First + len(entries) - 1
		}
		if f.Page > 1 {
			v.PrevURL = f.url(min(f.Page-1, pages))
		}
		if f.Page < pages {
			v.NextURL = f.url(f.Page + 1)
		}
		for _, e := range entries {
			v.Rows = append(v.Rows, auditRow{AuditEntry: e, When: zonedFormat(e.At, nil, zonedSecondsLayout)})
		}
		r.Render(w, req, http.StatusOK, "audit.html", View{Title: "Audit log", Data: v})
	})
}
