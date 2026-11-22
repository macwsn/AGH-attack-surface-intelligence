package web

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"asi/internal/auth"
	"asi/internal/inventory"
)

func RegisterInventory(r *Router, d Deps) {
	inv := d.store()
	r.NavIn(NavInventory, "Hosts", "/hosts/", Require(auth.PermInventoryRead))
	r.Handle(http.MethodGet, "/hosts/{$}", Require(auth.PermInventoryRead), func(w http.ResponseWriter, req *http.Request) {
		f, problem := parseHostFilter(req.URL.Query())
		if problem != "" {
			r.Error(w, req, http.StatusBadRequest, problem)
			return
		}
		page, err := inv.ListHosts(req.Context(), f.query())
		if errors.Is(err, inventory.ErrInvalidQuery) {
			r.Error(w, req, http.StatusBadRequest, "The filter is not valid. Change it and try again.")
			return
		}
		if err != nil {
			r.ServerError(w, req, err)
			return
		}
		v := newHostsView(f, page, time.Now())
		v.Deleted = req.URL.Query().Get("deleted")
		p, ok := auth.PrincipalFrom(req.Context())
		v.CanCreate = ok && slices.Contains(p.Permissions, auth.PermInventoryCreate)
		r.Render(w, req, http.StatusOK, "inventory.html", View{Title: "Hosts", Data: v})
	})
	r.Handle(http.MethodGet, "/hosts/{address}", Require(auth.PermInventoryRead), func(w http.ResponseWriter, req *http.Request) {
		address := req.PathValue("address")
		d, err := inv.HostDetail(req.Context(), address)
		if errors.Is(err, inventory.ErrUnknownHost) {
			r.Error(w, req, http.StatusNotFound, fmt.Sprintf("No host %q is in the inventory.", address))
			return
		}
		if err != nil {
			r.ServerError(w, req, err)
			return
		}
		v := newHostView(d, time.Now())
		if v.Timings, err = inv.ResponseTimes(req.Context(), d.Host.Address); err != nil {
			r.ServerError(w, req, err)
			return
		}
		p, ok := auth.PrincipalFrom(req.Context())
		if ok && slices.Contains(p.Permissions, auth.PermInventoryEdit) {
			v.Form = newHostForm(d.Host)
		}
		v.CanDelete = ok && slices.Contains(p.Permissions, auth.PermInventoryDelete)
		v.Saved = req.URL.Query().Get("saved") == "1"
		v.EditOpen = v.Form != nil && req.URL.Query().Get("edit") == "1"
		v.Deleted = req.URL.Query().Get("deleted")
		r.Render(w, req, http.StatusOK, "host.html", View{Title: d.Host.Address, Data: v})
	})
	r.Handle(http.MethodPost, "/hosts/{address}", Require(auth.PermInventoryEdit), func(w http.ResponseWriter, req *http.Request) {
		address := req.PathValue("address")
		form := parseHostForm(req)
		if len(form.Problems) > 0 && !can(req, auth.PermInventoryRead) {
			r.Error(w, req, http.StatusBadRequest, form.problemText())
			return
		}
		d, err := inv.HostDetail(req.Context(), address)
		if errors.Is(err, inventory.ErrUnknownHost) {
			r.Error(w, req, http.StatusNotFound, fmt.Sprintf("No host %q is in the inventory.", address))
			return
		}
		if err != nil {
			r.ServerError(w, req, err)
			return
		}
		if len(form.Problems) > 0 {
			v := newHostView(d, time.Now())
			if v.Timings, err = inv.ResponseTimes(req.Context(), d.Host.Address); err != nil {
				r.ServerError(w, req, err)
				return
			}
			v.Form = form
			r.Render(w, req, http.StatusUnprocessableEntity, "host.html", View{Title: d.Host.Address, Data: v})
			return
		}
		p, _ := auth.PrincipalFrom(req.Context())
		editor := inventory.Editor{Username: p.Username, Addr: clientAddr(req)}
		err = inv.EditHostUserFields(req.Context(), editor, d.Host.Address, form.fields())
		if errors.Is(err, inventory.ErrUnknownHost) {
			r.Error(w, req, http.StatusNotFound, fmt.Sprintf("No host %q is in the inventory.", address))
			return
		}
		if err != nil {
			r.ServerError(w, req, err)
			return
		}
		http.Redirect(w, req, "/hosts/"+url.PathEscape(d.Host.Address)+"?saved=1", http.StatusSeeOther)
	})
}

func RegisterHostDelete(r *Router, d Deps) {
	inv := inventory.New(d.Store, d.Keyring)
	access := Require(auth.PermInventoryDelete)
	confirm := Require(auth.PermInventoryDelete, auth.PermInventoryRead)
	r.Handle(http.MethodGet, "/hosts/{address}/delete", confirm, func(w http.ResponseWriter, req *http.Request) {
		if h, ok := r.deleteTarget(w, req, inv); ok {
			r.Render(w, req, http.StatusOK, "host_delete.html", View{Title: "Delete host " + h.Address, Data: h})
		}
	})
	r.Handle(http.MethodPost, "/hosts/{address}/delete", access, func(w http.ResponseWriter, req *http.Request) {
		h, ok := r.deleteTarget(w, req, inv)
		if !ok {
			return
		}
		err := inv.DeleteHost(req.Context(), editorOf(req), h.Address)
		if r.deleteFailed(w, req, h, err) {
			return
		}
		http.Redirect(w, req, "/hosts/?deleted="+url.QueryEscape(h.Address), http.StatusSeeOther)
	})
	r.Handle(http.MethodGet, "/hosts/{address}/services/{port}/{protocol}/delete", confirm, func(w http.ResponseWriter, req *http.Request) {
		if h, ok := r.deleteTarget(w, req, inv); ok {
			r.Render(w, req, http.StatusOK, "host_delete.html", View{Title: "Delete service " + h.Service.Key, Data: h})
		}
	})
	r.Handle(http.MethodPost, "/hosts/{address}/services/{port}/{protocol}/delete", access, func(w http.ResponseWriter, req *http.Request) {
		h, ok := r.deleteTarget(w, req, inv)
		if !ok {
			return
		}
		err := inv.DeleteService(req.Context(), editorOf(req), h.Address, h.Service.Port, h.Service.Protocol)
		if r.deleteFailed(w, req, h, err) {
			return
		}
		http.Redirect(w, req, "/hosts/"+url.PathEscape(h.Address)+"?deleted="+url.QueryEscape(h.Service.Key), http.StatusSeeOther)
	})
}

type deleteView struct {
	Address  string
	HostPath string
	Services int
	Service  *serviceView
}

func editorOf(req *http.Request) inventory.Editor {
	p, _ := auth.PrincipalFrom(req.Context())
	return inventory.Editor{Username: p.Username, Addr: clientAddr(req)}
}

func (r *Router) deleteTarget(w http.ResponseWriter, req *http.Request, inv *inventory.Inventory) (deleteView, bool) {
	address := req.PathValue("address")
	d, err := inv.HostDetail(req.Context(), address)
	if errors.Is(err, inventory.ErrUnknownHost) {
		r.Error(w, req, http.StatusNotFound, fmt.Sprintf("No host %q is in the inventory.", address))
		return deleteView{}, false
	}
	if err != nil {
		r.ServerError(w, req, err)
		return deleteView{}, false
	}
	v := deleteView{Address: d.Host.Address, HostPath: "/hosts/" + url.PathEscape(d.Host.Address), Services: len(d.Host.Services)}
	if req.PathValue("port") == "" {
		return v, true
	}
	key := req.PathValue("port") + "/" + req.PathValue("protocol")
	for _, s := range newHostView(d, time.Now()).Services {
		if s.Key == key {
			v.Service = &s
			return v, true
		}
	}
	r.Error(w, req, http.StatusNotFound, fmt.Sprintf("Host %s has no service %s.", d.Host.Address, key))
	return deleteView{}, false
}

func (r *Router) deleteFailed(w http.ResponseWriter, req *http.Request, v deleteView, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, inventory.ErrUnknownHost):
		r.Error(w, req, http.StatusNotFound, fmt.Sprintf("No host %q is in the inventory.", v.Address))
	case errors.Is(err, inventory.ErrUnknownService):
		r.Error(w, req, http.StatusNotFound, fmt.Sprintf("Host %s has no service %s.", v.Address, v.Service.Key))
	default:
		r.ServerError(w, req, err)
	}
	return true
}

const (
	maxTags        = 32
	maxTagLen      = 64
	maxShortField  = 200
	maxNotesLength = 10000
)

var criticalities = []string{"", "low", "medium", "high", "critical"}

type hostForm struct {
	Tags, DisplayName, Owner, Criticality, StatusOverride, Notes string
	Criticalities, Overrides                                     []option
	Problems                                                     map[string]string
}

func newHostForm(h inventory.ExportHost) *hostForm {
	f := &hostForm{Tags: strings.Join(h.Tags, ", "), DisplayName: h.DisplayName, Owner: h.Owner,
		Criticality: h.Criticality, StatusOverride: h.StatusOverride, Notes: h.Notes}
	f.options()
	return f
}

func (f *hostForm) options() {
	f.Criticalities, f.Overrides = nil, nil
	for _, c := range criticalities {
		label := "Not set"
		if c != "" {
			label = strings.ToUpper(c[:1]) + c[1:]
		}
		f.Criticalities = append(f.Criticalities, option{Value: c, Label: label, Selected: f.Criticality == c})
	}
	if !slices.Contains(criticalities, f.Criticality) {
		f.Criticalities = append(f.Criticalities, option{Value: f.Criticality, Label: f.Criticality, Selected: true})
	}
	f.Overrides = append(f.Overrides, option{Value: "", Label: "None", Selected: f.StatusOverride == ""})
	for _, s := range []inventory.Status{inventory.StatusActive, inventory.StatusUnstable, inventory.StatusInactive} {
		f.Overrides = append(f.Overrides, option{Value: string(s), Label: statusLabels[s], Selected: f.StatusOverride == string(s)})
	}
	if _, ok := statusLabels[inventory.Status(f.StatusOverride)]; !ok && f.StatusOverride != "" {
		f.Overrides = append(f.Overrides, option{Value: f.StatusOverride, Label: f.StatusOverride, Selected: true})
	}
}

func parseHostForm(req *http.Request) *hostForm {
	f := &hostForm{Tags: req.PostFormValue("tags"), DisplayName: strings.TrimSpace(req.PostFormValue("display_name")),
		Owner: strings.TrimSpace(req.PostFormValue("owner")), Criticality: req.PostFormValue("criticality"),
		StatusOverride: req.PostFormValue("status_override"), Notes: strings.TrimSpace(req.PostFormValue("notes")),
		Problems: map[string]string{}}
	tags := splitTags(f.Tags)
	switch {
	case len(tags) > maxTags:
		f.Problems["tags"] = fmt.Sprintf("Use at most %d tags; this has %d.", maxTags, len(tags))
	default:
		for _, t := range tags {
			if utf8.RuneCountInString(t) > maxTagLen {
				f.Problems["tags"] = fmt.Sprintf("Tag %q is longer than %d characters.", t, maxTagLen)
				break
			}
		}
	}
	short := func(name, label, value string) {
		if utf8.RuneCountInString(value) > maxShortField {
			f.Problems[name] = fmt.Sprintf("%s is %d characters long; use at most %d.", label, utf8.RuneCountInString(value), maxShortField)
		}
	}
	short("display_name", "The display name", f.DisplayName)
	short("owner", "The owner", f.Owner)
	if n := utf8.RuneCountInString(f.Notes); n > maxNotesLength {
		f.Problems["notes"] = fmt.Sprintf("The notes are %d characters long; use at most %d.", n, maxNotesLength)
	}
	if !slices.Contains(criticalities, f.Criticality) {
		f.Problems["criticality"] = fmt.Sprintf("Criticality %q is not one of low, medium, high or critical.", f.Criticality)
	}
	switch inventory.Status(f.StatusOverride) {
	case "", inventory.StatusActive, inventory.StatusUnstable, inventory.StatusInactive:
	default:
		f.Problems["status_override"] = fmt.Sprintf("Status override %q is not one of active, unstable or inactive.", f.StatusOverride)
	}
	f.options()
	return f
}

func (f *hostForm) problemText() string {
	fields := make([]string, 0, len(f.Problems))
	for k := range f.Problems {
		fields = append(fields, k)
	}
	sort.Strings(fields)
	problems := make([]string, len(fields))
	for i, k := range fields {
		problems[i] = f.Problems[k]
	}
	return "Nothing was saved. " + strings.Join(problems, " ")
}

func splitTags(s string) []string {
	var out []string
	for _, t := range strings.Split(s, ",") {
		if t = strings.TrimSpace(t); t != "" && !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	return out
}

func (f *hostForm) fields() inventory.HostUserFields {
	return inventory.HostUserFields{Tags: splitTags(f.Tags), Notes: f.Notes, DisplayName: f.DisplayName, Owner: f.Owner,
		Criticality: f.Criticality, StatusOverride: f.StatusOverride}
}

type hostFilter struct {
	Status, Port, Service, Technology, FindingKind, Tag, Text, Sort string
	Desc                                                            bool
	Page                                                            int
}

var hostSorts = map[string]bool{"address": true, "display_name": true, "status": true, "interest": true, "last_seen": true}

func parseHostFilter(v url.Values) (hostFilter, string) {
	get := func(k string) string { return strings.TrimSpace(v.Get(k)) }
	f := hostFilter{Status: get("status"), Port: get("port"), Service: get("service"), Technology: get("technology"),
		FindingKind: get("finding"), Tag: get("tag"), Text: get("q"), Sort: get("sort"), Desc: get("dir") == "desc", Page: 1}
	switch inventory.Status(f.Status) {
	case "", inventory.StatusActive, inventory.StatusUnstable, inventory.StatusInactive:
	default:
		return f, fmt.Sprintf("Status %q is not one of active, unstable or inactive.", f.Status)
	}
	if f.Port != "" {
		if p, err := strconv.Atoi(f.Port); err != nil || p < 1 || p > 65535 {
			return f, fmt.Sprintf("Port %q is not a number between 1 and 65535.", f.Port)
		}
	}
	if f.Sort != "" && !hostSorts[f.Sort] {
		return f, fmt.Sprintf("Hosts cannot be sorted by %q.", f.Sort)
	}
	if p := get("page"); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 {
			return f, fmt.Sprintf("Page %q is not a positive number.", p)
		}
		f.Page = n
	}
	return f, ""
}

func (f hostFilter) query() inventory.HostQuery {
	port, _ := strconv.Atoi(f.Port)
	return inventory.HostQuery{Status: f.Status, Port: port, Service: f.Service, Technology: f.Technology,
		FindingKind: f.FindingKind, Tag: f.Tag, Text: f.Text, Sort: f.Sort, Desc: f.Desc, Page: f.Page,
		PerPage: inventory.DefaultPerPage}
}

func (f hostFilter) url() string {
	v := url.Values{}
	set := func(k, val string) {
		if val != "" {
			v.Set(k, val)
		}
	}
	set("q", f.Text)
	set("status", f.Status)
	set("port", f.Port)
	set("service", f.Service)
	set("technology", f.Technology)
	set("finding", f.FindingKind)
	set("tag", f.Tag)
	set("sort", f.Sort)
	if f.Desc {
		v.Set("dir", "desc")
	}
	if f.Page > 1 {
		v.Set("page", strconv.Itoa(f.Page))
	}
	if len(v) == 0 {
		return "/hosts/"
	}
	return "/hosts/?" + v.Encode()
}

type option struct {
	Value, Label string
	Selected     bool
}

type sortColumn struct {
	Label, URL, AriaSort string
	Num                  bool
}

type mark struct{ Class, Label string }

type hostRowView struct {
	Address, URL, DisplayName, Hostnames string
	Status                               inventory.Status
	StatusLabel                          string
	Ports, Technologies                  string
	PortList                             []portView
	Kinds                                []mark
	Tags                                 []string
	Interest                             int
	InterestHigh                         bool
	LastSeen, LastSeenExact              string
}

type portView struct {
	Port   int
	Status inventory.Status
	Label  string
}

func (p portView) Off() bool { return p.Status != "" && p.Status != inventory.StatusActive }

type hostsView struct {
	Filter       hostFilter
	Statuses     []option
	FindingKinds []option
	Columns      []sortColumn
	Rows         []hostRowView
	Total        string
	HostWord     string
	From, To     string
	Page, Pages  int
	PrevURL      string
	NextURL      string
	Filtered     bool
	ClearURL     string
	Deleted      string
	CanCreate    bool
}

var kindLabels = []mark{
	{"admin-panel", "Admin panel"}, {"staging", "Staging"}, {"iot", "IoT"}, {"interesting-header", "Header"},
	{"interesting-cookie", "Cookie"}, {"outdated", "Outdated version"}, {"technology", "Technology"}, {"custom", "Custom"},
}

func kindMark(kind string) mark {
	for _, m := range kindLabels {
		if m.Class == kind {
			return m
		}
	}
	return mark{Class: "custom", Label: kind}
}

func newHostsView(f hostFilter, p inventory.HostPage, now time.Time) hostsView {
	v := hostsView{Filter: f, Page: p.Page, Total: count(p.Total), HostWord: "hosts", ClearURL: "/hosts/"}
	if p.Total == 1 {
		v.HostWord = "host"
	}
	v.Filtered = f.Status != "" || f.Port != "" || f.Service != "" || f.Technology != "" || f.FindingKind != "" ||
		f.Tag != "" || f.Text != ""
	v.Statuses = []option{{Value: "", Label: "Any", Selected: f.Status == ""}}
	for _, s := range []inventory.Status{inventory.StatusActive, inventory.StatusUnstable, inventory.StatusInactive} {
		v.Statuses = append(v.Statuses, option{Value: string(s), Label: statusLabels[s], Selected: f.Status == string(s)})
	}
	v.FindingKinds = []option{{Value: "", Label: "Any", Selected: f.FindingKind == ""}}
	for _, m := range kindLabels {
		if m.Class == "technology" {
			continue
		}
		v.FindingKinds = append(v.FindingKinds, option{Value: m.Class, Label: m.Label, Selected: f.FindingKind == m.Class})
	}
	current := f.Sort
	if current == "" {
		current = "address"
	}
	for _, c := range []struct {
		key, label string
		num        bool
	}{{"address", "Address", false}, {"display_name", "Name", false}, {"status", "Status", false},
		{"interest", "Interest", true}, {"last_seen", "Last seen", false}} {
		next := f
		next.Page, next.Sort, next.Desc = 1, c.key, c.key == "interest" || c.key == "last_seen"
		col := sortColumn{Label: c.label, Num: c.num}
		if c.key == current {
			next.Desc = !f.Desc
			col.AriaSort = "ascending"
			if f.Desc {
				col.AriaSort = "descending"
			}
		}
		col.URL = next.url()
		v.Columns = append(v.Columns, col)
	}
	pages := (p.Total + p.PerPage - 1) / p.PerPage
	v.Pages = max(pages, 1)
	if len(p.Hosts) > 0 {
		from := (p.Page-1)*p.PerPage + 1
		v.From, v.To = count(from), count(from+len(p.Hosts)-1)
	}
	if p.Page > 1 {
		prev := f
		prev.Page = min(p.Page-1, v.Pages)
		v.PrevURL = prev.url()
	}
	if p.Page < pages {
		next := f
		next.Page = p.Page + 1
		v.NextURL = next.url()
	}
	for _, h := range p.Hosts {
		row := hostRowView{Address: h.Address, URL: "/hosts/" + url.PathEscape(h.Address), DisplayName: h.DisplayName,
			Hostnames: strings.Join(h.Hostnames, ", "), Status: h.Status, StatusLabel: statusLabels[h.Status],
			Technologies: strings.Join(h.Technologies, ", "), Tags: h.Tags, Interest: h.InterestScore,
			InterestHigh: h.InterestScore >= 70}
		ports := make([]string, len(h.Ports))
		for i, port := range h.Ports {
			ports[i] = strconv.Itoa(port)
			st := h.PortStatus[port]
			row.PortList = append(row.PortList, portView{Port: port, Status: st, Label: statusLabels[st]})
		}
		row.Ports = strings.Join(ports, ", ")
		for _, k := range h.FindingKinds {
			if k == "technology" {
				continue
			}
			row.Kinds = append(row.Kinds, kindMark(k))
		}
		row.LastSeen, row.LastSeenExact = ago(h.LastSeen, now), isoTime(h.LastSeen)
		v.Rows = append(v.Rows, row)
	}
	return v
}

type kv struct{ Key, Value string }

type serviceView struct {
	Key, Name, State, Product string
	Port                      int
	Protocol                  string
	Status                    inventory.Status
	StatusLabel               string
	Kinds                     []kindCount
	HTTP                      *httpView
	Technologies              []inventory.Technology
	Findings                  []findingView
	Volatile                  []volatileView
}

type volatileView struct {
	Field  string
	Values []string
}

type httpView struct {
	URL, Title, Server string
	StatusCode         int
	Redirects          []string
	Headers            []kv
	Cookies            []string
	TLS                *tlsView
}

type tlsView struct {
	Subject, Issuer, NotAfter, SANs string
	SelfSigned                      bool
}

type findingView struct {
	Mark                                 mark
	Name, SignatureID, Version, Evidence string
	Confidence                           int
}

type historyView struct {
	Run, Date string
	Seen      bool
	Services  string
}

type hostView struct {
	Address, DisplayName, Hostnames string
	Status                          inventory.Status
	StatusLabel                     string
	MissedRuns                      int
	Stability                       int
	Interest                        int
	InterestHigh                    bool
	FirstSeen, LastSeen             string
	Tags                            []string
	Owner, Criticality, Notes       string
	StatusOverride                  string
	Run                             string
	Services                        []serviceView
	History                         []historyView
	Form                            *hostForm
	Saved                           bool
	EditOpen                        bool
	CanDelete                       bool
	Deleted                         string
	Timings                         []inventory.ServiceTiming
	Window                          int
	Availability                    availabilityView
}

func newHostView(d inventory.HostDetail, now time.Time) hostView {
	h := d.Host
	v := hostView{Address: h.Address, DisplayName: h.DisplayName, Hostnames: strings.Join(h.Hostnames, ", "),
		Status: h.Status, StatusLabel: statusLabels[h.Status], MissedRuns: h.MissedRuns,
		Stability: int(h.Stability*100 + 0.5), Interest: h.InterestScore, InterestHigh: h.InterestScore >= 70,
		FirstSeen: isoTime(h.FirstSeen), LastSeen: isoTime(h.LastSeen), Tags: h.Tags, Owner: h.Owner,
		Criticality: h.Criticality, Notes: h.Notes, StatusOverride: h.StatusOverride, Run: d.Run, Window: inventory.TimingWindow,
		Availability: availabilityOf(h.Address, h.Availability.Profile())}
	for _, s := range h.Services {
		sv := serviceView{Key: fmt.Sprintf("%d/%s", s.Port, s.Protocol), Port: s.Port, Protocol: s.Protocol, Name: s.Service, State: s.State,
			Product: strings.TrimSpace(s.Product + " " + s.Version), Status: s.Status, StatusLabel: statusLabels[s.Status],
			Technologies: inventory.Reported(s.Technologies, h.Stability)}
		for _, f := range s.Findings {
			m := kindMark(f.Kind)
			sv.Kinds = countKind(sv.Kinds, m)
			sv.Findings = append(sv.Findings, findingView{Mark: m, Name: f.Name, SignatureID: f.SignatureID,
				Version: f.Version, Evidence: f.Evidence, Confidence: f.Confidence})
		}
		for _, f := range s.Volatile {
			vv := volatileView{Field: f.Field}
			for _, val := range f.Values {
				vv.Values = append(vv.Values, fieldText(val))
			}
			sv.Volatile = append(sv.Volatile, vv)
		}
		if s.HTTP != nil {
			hv := &httpView{URL: s.HTTP.URL, Title: s.HTTP.Title, Server: s.HTTP.Headers["server"],
				StatusCode: s.HTTP.StatusCode, Redirects: s.HTTP.RedirectChain}
			names := make([]string, 0, len(s.HTTP.Headers))
			for k := range s.HTTP.Headers {
				names = append(names, k)
			}
			sort.Strings(names)
			for _, k := range names {
				hv.Headers = append(hv.Headers, kv{k, s.HTTP.Headers[k]})
			}
			for _, c := range s.HTTP.Cookies {
				flags := []string{c.Name}
				if c.HTTPOnly {
					flags = append(flags, "HttpOnly")
				}
				if c.Secure {
					flags = append(flags, "Secure")
				}
				if c.SameSite != "" {
					flags = append(flags, "SameSite="+c.SameSite)
				}
				hv.Cookies = append(hv.Cookies, strings.Join(flags, "; "))
			}
			if t := s.HTTP.TLS; t != nil {
				hv.TLS = &tlsView{Subject: t.SubjectCN, Issuer: t.IssuerCN, SANs: strings.Join(t.SANs, ", "),
					NotAfter: certExpiry(t.NotAfter, now), SelfSigned: t.SelfSigned}
			}
			sv.HTTP = hv
		}
		v.Services = append(v.Services, sv)
	}
	for _, e := range d.History {
		v.History = append(v.History, historyView{Run: e.Run, Date: isoTime(e.StartedAt), Seen: e.Seen,
			Services: strings.Join(e.Services, ", ")})
	}
	return v
}

type kindCount struct {
	mark
	Count int
}

func countKind(kinds []kindCount, m mark) []kindCount {
	for i := range kinds {
		if kinds[i].mark == m {
			kinds[i].Count++
			return kinds
		}
	}
	return append(kinds, kindCount{mark: m, Count: 1})
}

func isoTime(t time.Time) string {
	return zonedTime(t, nil)
}

func ago(t time.Time, now time.Time) string {
	d := now.Sub(t)
	switch {
	case t.IsZero():
		return ""
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return plural(int(d/time.Minute), "minute") + " ago"
	case d < 24*time.Hour:
		return plural(int(d/time.Hour), "hour") + " ago"
	}
	return isoTime(t)
}

func plural(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return strconv.Itoa(n) + " " + unit + "s"
}

func certExpiry(notAfter string, now time.Time) string {
	t, err := time.Parse(time.RFC3339, notAfter)
	if err != nil {
		return notAfter
	}
	days := int(t.Sub(now).Hours() / 24)
	switch {
	case t.Before(now):
		return isoTime(t) + ", expired"
	case days < 30:
		return isoTime(t) + ", expires in " + plural(days, "day")
	}
	return isoTime(t)
}

func count(n int) string {
	s := strconv.Itoa(n)
	if n < 1000 {
		return s
	}
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteString(" ")
		}
		b.WriteRune(c)
	}
	return b.String()
}
