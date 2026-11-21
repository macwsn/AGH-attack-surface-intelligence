package web

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"asi/internal/auth"
	"asi/internal/inventory"
	"asi/internal/scan"
	"asi/internal/schedule"
)

const (
	maxScanFormBytes = 1 << 20
	runListLimit     = 20
	timeLayout       = "2006-01-02 15:04"
)

var scanMessages = map[string]string{
	"created":  "Scan created. Enable it to run on its schedule.",
	"saved":    "Changes saved. They apply from the next run.",
	"enabled":  "Scan enabled. It runs in its windows.",
	"disabled": "Scan disabled. The scheduler starts no new runs of it.",
	"started":  "Scan started.",
	"paused":   "Run paused. It stays paused until you resume it.",
	"resumed":  "Run resumed.",
}

type scanRow struct {
	Definition schedule.Definition
	Windows    string
	Frequency  string
	LastRun    *runRow
}

type runRow struct {
	ID       int64
	Name     string
	Status   string
	Held     bool
	Started  string
	Finished string
}

type scanListData struct {
	Scans        []scanRow
	CanConfigure bool
}

type scanData struct {
	scanRow
	Message      string
	Settings     inventory.RunSettings
	Ports        string
	Timezone     string
	Runs         []runRow
	CanConfigure bool
	Open         bool
}

type scanForm struct {
	ID            int64
	Name          string
	Targets       string
	Excludes      string
	Ports         string
	MaxRate       string
	Workers       string
	InactiveAfter string
	SignaturesDir string
	Timezone      string
	Windows       string
	Frequency     string
	Every         string
	Problems      map[string]string
	RunOpen       bool
}

type groupRow struct {
	Index     int
	Addresses int
	Hosts     int
	Duration  string
	Completed string
}

type runData struct {
	Run        runRow
	Definition schedule.Definition
	Message    string
	Progress   schedule.Progress
	Busy       string
	Left       string
	NextWindow string
	Groups     []groupRow
	CanPause   bool
	CanResume  bool
	Running    bool
}

func RegisterScans(r *Router, d Deps) {
	configure, run := Require(auth.PermScanConfigure), Require(auth.PermScanRun)
	h := &scanHandlers{r: r, s: d.Scans}
	r.Nav("Scans", "/scans", run)
	r.Handle(http.MethodGet, "/scans", run, h.list)
	r.Handle(http.MethodGet, "/scans/new", configure, h.newForm)
	r.Handle(http.MethodPost, "/scans", configure, h.create)
	r.Handle(http.MethodGet, "/scans/{id}", run, h.show)
	r.Handle(http.MethodGet, "/scans/{id}/edit", configure, h.editForm)
	r.Handle(http.MethodPost, "/scans/{id}", configure, h.update)
	r.Handle(http.MethodPost, "/scans/{id}/enable", configure, h.setEnabled(true))
	r.Handle(http.MethodPost, "/scans/{id}/disable", configure, h.setEnabled(false))
	r.Handle(http.MethodPost, "/scans/{id}/start", run, h.start)
	r.Handle(http.MethodGet, "/runs/{id}", run, h.runPage)
	r.Handle(http.MethodPost, "/runs/{id}/pause", run, h.pause)
	r.Handle(http.MethodPost, "/runs/{id}/resume", run, h.resume)
}

type scanHandlers struct {
	r *Router
	s *schedule.Scheduler
}

func can(req *http.Request, p auth.Permission) bool {
	pr, ok := auth.PrincipalFrom(req.Context())
	return ok && slices.Contains(pr.Permissions, p)
}

func scanActor(req *http.Request) auth.Actor {
	pr, _ := auth.PrincipalFrom(req.Context())
	return auth.Actor{Username: pr.Username, Addr: clientAddr(req)}
}

func pathID(req *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(req.PathValue("id"), 10, 64)
	return id, err == nil && id > 0
}

func formatTime(t *time.Time) string {
	if t == nil || t.IsZero() {
		return ""
	}
	return t.Local().Format(timeLayout)
}

func toRunRow(run schedule.Run) runRow {
	started := run.StartedAt
	return runRow{ID: run.ID, Name: run.Name, Status: string(run.Status), Held: run.Held,
		Started: formatTime(&started), Finished: formatTime(run.FinishedAt)}
}

func toScanRow(d schedule.Definition) scanRow {
	w := schedule.FormatWindows(d.Schedule.Windows)
	if w == "" {
		w = "any time"
	}
	return scanRow{Definition: d, Windows: strings.ReplaceAll(w, "\n", "; "), Frequency: d.Schedule.Frequency.String()}
}

func (h *scanHandlers) notFound(w http.ResponseWriter, req *http.Request, err error) bool {
	if errors.Is(err, schedule.ErrUnknownDefinition) {
		h.r.Error(w, req, http.StatusNotFound, "This scan does not exist.")
		return true
	}
	if errors.Is(err, schedule.ErrUnknownRun) {
		h.r.Error(w, req, http.StatusNotFound, "This run does not exist.")
		return true
	}
	return false
}

func (h *scanHandlers) fail(w http.ResponseWriter, req *http.Request, err error) {
	switch {
	case h.notFound(w, req, err):
	case errors.Is(err, schedule.ErrRunOpen):
		h.r.Error(w, req, http.StatusConflict, "This scan already has a run in progress or paused. Open that run to pause or resume it.")
	case errors.Is(err, schedule.ErrNotPaused):
		h.r.Error(w, req, http.StatusConflict, "This run is not paused, so it cannot be resumed.")
	case errors.Is(err, schedule.ErrNotOpen):
		h.r.Error(w, req, http.StatusConflict, "This run has finished, so it cannot be paused.")
	default:
		h.r.ServerError(w, req, err)
	}
}

func (h *scanHandlers) list(w http.ResponseWriter, req *http.Request) {
	defs, err := h.s.Store.Definitions(req.Context())
	if err != nil {
		h.r.ServerError(w, req, err)
		return
	}
	data := scanListData{CanConfigure: can(req, auth.PermScanConfigure)}
	for _, d := range defs {
		row := toScanRow(d)
		runs, err := h.s.Store.Runs(req.Context(), d.ID, 1)
		if err != nil {
			h.r.ServerError(w, req, err)
			return
		}
		if len(runs) > 0 {
			rr := toRunRow(runs[0])
			row.LastRun = &rr
		}
		data.Scans = append(data.Scans, row)
	}
	h.r.Render(w, req, http.StatusOK, "scans.html", View{Title: "Scans", Data: data})
}

func (h *scanHandlers) show(w http.ResponseWriter, req *http.Request) {
	id, ok := pathID(req)
	if !ok {
		h.notFound(w, req, schedule.ErrUnknownDefinition)
		return
	}
	d, err := h.s.Store.Definition(req.Context(), id)
	if err != nil {
		h.fail(w, req, err)
		return
	}
	runs, err := h.s.Store.Runs(req.Context(), id, runListLimit)
	if err != nil {
		h.r.ServerError(w, req, err)
		return
	}
	ports := make([]string, len(d.Settings.Ports))
	for i, p := range d.Settings.Ports {
		ports[i] = strconv.Itoa(p)
	}
	tz := d.Schedule.Timezone
	if tz == "" {
		tz = "UTC"
	}
	data := scanData{scanRow: toScanRow(d), Message: scanMessages[req.URL.Query().Get("msg")], Settings: d.Settings,
		Ports: strings.Join(ports, ", "), Timezone: tz, CanConfigure: can(req, auth.PermScanConfigure)}
	for _, run := range runs {
		data.Runs = append(data.Runs, toRunRow(run))
		data.Open = data.Open || run.Open()
	}
	h.r.Render(w, req, http.StatusOK, "scan.html", View{Title: d.Name, Data: data})
}

func scanFormOf(d schedule.Definition) scanForm {
	ports := make([]string, len(d.Settings.Ports))
	for i, p := range d.Settings.Ports {
		ports[i] = strconv.Itoa(p)
	}
	return scanForm{
		ID:            d.ID,
		Name:          d.Name,
		Targets:       strings.Join(d.Settings.Targets, "\n"),
		Excludes:      strings.Join(d.Settings.Excludes, "\n"),
		Ports:         strings.Join(ports, ","),
		MaxRate:       strconv.Itoa(d.Settings.MaxRate),
		Workers:       strconv.Itoa(d.Settings.Workers),
		InactiveAfter: strconv.Itoa(d.InactiveAfter),
		SignaturesDir: d.Settings.SignaturesDir,
		Timezone:      d.Schedule.Timezone,
		Windows:       schedule.FormatWindows(d.Schedule.Windows),
		Frequency:     d.Schedule.Frequency.Kind,
		Every:         d.Schedule.Frequency.Every,
	}
}

func (h *scanHandlers) newForm(w http.ResponseWriter, req *http.Request) {
	f := scanForm{Ports: "80,443", MaxRate: strconv.Itoa(scan.DefaultMaxRate), Workers: strconv.Itoa(scan.DefaultWorkers),
		InactiveAfter: strconv.Itoa(inventory.DefaultInactiveAfter), Timezone: "Europe/Warsaw",
		Windows: "mon-fri 22:00-06:00", Frequency: schedule.FrequencyDaily}
	h.r.Render(w, req, http.StatusOK, "scan_form.html", View{Title: "New scan", Data: f})
}

func (h *scanHandlers) editForm(w http.ResponseWriter, req *http.Request) {
	id, ok := pathID(req)
	if !ok {
		h.notFound(w, req, schedule.ErrUnknownDefinition)
		return
	}
	d, err := h.s.Store.Definition(req.Context(), id)
	if err != nil {
		h.fail(w, req, err)
		return
	}
	f := scanFormOf(d)
	if _, f.RunOpen, err = h.s.Store.OpenRun(req.Context(), id); err != nil {
		h.r.ServerError(w, req, err)
		return
	}
	h.r.Render(w, req, http.StatusOK, "scan_form.html", View{Title: "Edit " + d.Name, Data: f})
}

func lines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}

func parseScanForm(req *http.Request) (scanForm, schedule.Definition) {
	v := req.PostForm
	f := scanForm{
		Name: strings.TrimSpace(v.Get("name")), Targets: v.Get("targets"), Excludes: v.Get("excludes"),
		Ports: strings.TrimSpace(v.Get("ports")), MaxRate: strings.TrimSpace(v.Get("max_rate")),
		Workers: strings.TrimSpace(v.Get("workers")), InactiveAfter: strings.TrimSpace(v.Get("inactive_after")),
		SignaturesDir: strings.TrimSpace(v.Get("signatures_dir")), Timezone: strings.TrimSpace(v.Get("timezone")),
		Windows: v.Get("windows"), Frequency: v.Get("frequency"), Every: strings.TrimSpace(v.Get("every")),
		Problems: map[string]string{},
	}
	d := schedule.Definition{Name: f.Name, Settings: inventory.RunSettings{
		Targets: lines(f.Targets), Excludes: lines(f.Excludes), SignaturesDir: f.SignaturesDir,
	}}
	if d.Settings.Excludes == nil {
		d.Settings.Excludes = []string{}
	}
	ports, err := scan.ParsePorts(f.Ports)
	if err != nil {
		f.Problems["ports"] = fmt.Sprintf("%s. Enter ports separated by commas, for example 80,443.", err)
	}
	d.Settings.Ports = ports
	number := func(key, label, value string) int {
		n, err := strconv.Atoi(value)
		if err != nil {
			f.Problems[key] = fmt.Sprintf("%q is not a number. Enter the %s as a whole number.", value, label)
		}
		return n
	}
	d.Settings.MaxRate = number("max rate", "max rate", f.MaxRate)
	d.Settings.Workers = number("workers", "number of workers", f.Workers)
	d.InactiveAfter = number("inactive after", "number of runs", f.InactiveAfter)
	windows, err := schedule.ParseWindows(f.Windows)
	if err != nil {
		f.Problems["windows"] = err.Error()
	}
	every := ""
	if f.Frequency == schedule.FrequencyInterval {
		every = f.Every
	}
	d.Schedule = schedule.Schedule{Timezone: f.Timezone, Windows: windows, Frequency: schedule.Frequency{Kind: f.Frequency, Every: every}}
	return f, d
}

func problemsOf(err error, into map[string]string) bool {
	known := false
	for _, line := range strings.Split(err.Error(), "\n") {
		key, msg, ok := strings.Cut(line, ": ")
		switch key {
		case "name", "targets", "excludes", "ports", "max rate", "workers", "inactive after", "signatures", "timezone", "windows", "frequency":
		default:
			ok = false
		}
		if !ok {
			continue
		}
		known = true
		if _, set := into[key]; !set {
			into[key] = msg
		}
	}
	return known
}

func (h *scanHandlers) save(w http.ResponseWriter, req *http.Request, id int64) {
	req.Body = http.MaxBytesReader(w, req.Body, maxScanFormBytes)
	if err := req.ParseForm(); err != nil {
		h.r.Error(w, req, http.StatusBadRequest, "The form could not be read. Target lists over 1 MB are not accepted.")
		return
	}
	f, d := parseScanForm(req)
	f.ID, d.ID = id, id
	title := "New scan"
	if id != 0 {
		title = "Edit " + f.Name
	}
	if len(f.Problems) > 0 {
		if err := d.Validate(); err != nil {
			problemsOf(err, f.Problems)
		}
	} else {
		var (
			saved schedule.Definition
			err   error
			msg   = "saved"
		)
		if id == 0 {
			saved, err = h.s.Store.CreateDefinition(req.Context(), scanActor(req), d)
			msg = "created"
		} else {
			saved, err = h.s.Store.UpdateDefinition(req.Context(), scanActor(req), d)
		}
		switch {
		case err == nil:
			http.Redirect(w, req, fmt.Sprintf("/scans/%d?msg=%s", saved.ID, msg), http.StatusSeeOther)
			return
		case errors.Is(err, schedule.ErrDefinitionExists):
			f.Problems["name"] = fmt.Sprintf("A scan named %q already exists. Choose another name.", f.Name)
		case h.notFound(w, req, err):
			return
		case !problemsOf(err, f.Problems):
			h.r.ServerError(w, req, err)
			return
		}
	}
	if id != 0 {
		var err error
		if _, f.RunOpen, err = h.s.Store.OpenRun(req.Context(), id); err != nil {
			h.r.ServerError(w, req, err)
			return
		}
	}
	h.r.Render(w, req, http.StatusUnprocessableEntity, "scan_form.html", View{Title: title, Data: f})
}

func (h *scanHandlers) create(w http.ResponseWriter, req *http.Request) { h.save(w, req, 0) }

func (h *scanHandlers) update(w http.ResponseWriter, req *http.Request) {
	id, ok := pathID(req)
	if !ok {
		h.notFound(w, req, schedule.ErrUnknownDefinition)
		return
	}
	h.save(w, req, id)
}

func (h *scanHandlers) setEnabled(enabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		id, ok := pathID(req)
		if !ok {
			h.notFound(w, req, schedule.ErrUnknownDefinition)
			return
		}
		if err := h.s.Store.SetEnabled(req.Context(), scanActor(req), id, enabled); err != nil {
			h.fail(w, req, err)
			return
		}
		msg := "disabled"
		if enabled {
			msg = "enabled"
		}
		http.Redirect(w, req, fmt.Sprintf("/scans/%d?msg=%s", id, msg), http.StatusSeeOther)
	}
}

func (h *scanHandlers) start(w http.ResponseWriter, req *http.Request) {
	id, ok := pathID(req)
	if !ok {
		h.notFound(w, req, schedule.ErrUnknownDefinition)
		return
	}
	run, err := h.s.StartNow(req.Context(), scanActor(req), id)
	if err != nil {
		h.fail(w, req, err)
		return
	}
	http.Redirect(w, req, fmt.Sprintf("/runs/%d?msg=started", run.ID), http.StatusSeeOther)
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	if d < time.Minute {
		return fmt.Sprintf("%d s", int(d.Seconds()))
	}
	h, m := int(d.Hours()), int(d.Minutes())%60
	if h == 0 {
		return fmt.Sprintf("%d min %d s", m, int(d.Seconds())%60)
	}
	return fmt.Sprintf("%d h %d min", h, m)
}

func (h *scanHandlers) runPage(w http.ResponseWriter, req *http.Request) {
	id, ok := pathID(req)
	if !ok {
		h.notFound(w, req, schedule.ErrUnknownRun)
		return
	}
	run, err := h.s.Store.Run(req.Context(), id)
	if err != nil {
		h.fail(w, req, err)
		return
	}
	groups, err := h.s.Scanner.Store.RunGroups(req.Context(), id)
	if err != nil {
		h.r.ServerError(w, req, err)
		return
	}
	data := runData{Run: toRunRow(run), Message: scanMessages[req.URL.Query().Get("msg")],
		Progress: schedule.ProgressOf(run.AddressTotal, run.Settings.Workers, groups),
		CanPause: run.Open() && !run.Held, CanResume: run.Status == inventory.RunPaused && run.DefinitionID != 0,
		Running: run.Status == inventory.RunRunning}
	if run.DefinitionID != 0 {
		if data.Definition, err = h.s.Store.Definition(req.Context(), run.DefinitionID); err != nil {
			h.r.ServerError(w, req, err)
			return
		}
	}
	data.Busy = formatDuration(data.Progress.Busy)
	if data.Progress.HasLeft {
		data.Left = formatDuration(data.Progress.Left)
	}
	if run.Status == inventory.RunPaused && !run.Held {
		if next, ok := run.Schedule.NextStart(time.Now()); ok {
			data.NextWindow = formatTime(&next)
		}
	}
	for _, g := range groups {
		c := g.CompletedAt
		data.Groups = append(data.Groups, groupRow{Index: g.Index, Addresses: g.AddressCount, Hosts: g.HostsFound,
			Duration: formatDuration(g.Duration), Completed: formatTime(&c)})
	}
	h.r.Render(w, req, http.StatusOK, "scan_run.html", View{Title: "Run " + run.Name, Data: data})
}

func (h *scanHandlers) pause(w http.ResponseWriter, req *http.Request) {
	id, ok := pathID(req)
	if !ok {
		h.notFound(w, req, schedule.ErrUnknownRun)
		return
	}
	if err := h.s.Pause(req.Context(), scanActor(req), id); err != nil {
		h.fail(w, req, err)
		return
	}
	http.Redirect(w, req, fmt.Sprintf("/runs/%d?msg=paused", id), http.StatusSeeOther)
}

func (h *scanHandlers) resume(w http.ResponseWriter, req *http.Request) {
	id, ok := pathID(req)
	if !ok {
		h.notFound(w, req, schedule.ErrUnknownRun)
		return
	}
	if err := h.s.Resume(req.Context(), scanActor(req), id); err != nil {
		h.fail(w, req, err)
		return
	}
	http.Redirect(w, req, fmt.Sprintf("/runs/%d?msg=resumed", id), http.StatusSeeOther)
}
