package web

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net/http"
	"net/url"
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
	savingLookback   = 1000
)

var scanMessages = map[string]string{
	"created":   "Scan created. Enable it to run on its schedule.",
	"scheduled": "Scan created. It runs on its schedule.",
	"saved":     "Changes saved. They apply from the next run.",
	"enabled":   "Scan enabled. It runs in its windows.",
	"disabled":  "Scan disabled. The scheduler starts no new runs of it.",
	"started":   "Scan started.",
	"paused":    "Run paused. It stays paused until you resume it.",
	"resumed":   "Run resumed.",
	"deleted":   "Scan deleted. Its past runs and their observations stay.",
}

type scanRow struct {
	Definition schedule.Definition
	Windows    string
	Frequency  string
	LastRun    *runRow
	Duration   string
	NextStart  string
}

type runRow struct {
	ID       int64
	Name     string
	Status   string
	Held     bool
	Stalled  bool
	Started  string
	Finished string
	Recheck  bool
	Packets  int
	Saving   string

	DefinitionDeleted bool
}

type scanListData struct {
	Scans        []scanRow
	CanConfigure bool
	CanQuick     bool
	Quick        quickForm
	Message      string
}

type scanData struct {
	scanRow
	Message      string
	Problem      string
	Settings     inventory.RunSettings
	Ports        string
	Timezone     string
	Runs         []runRow
	CanConfigure bool
	Open         bool
}

type scanForm struct {
	ID               int64
	Name             string
	Targets          string
	Excludes         string
	PortPreset       string
	Ports            string
	Pace             string
	MaxRate          string
	Workers          string
	InactiveAfter    string
	SignaturesDir    string
	VolatileHeaders  string
	ServiceDetection string
	Mode             string
	Scheduled        bool
	Days             []string
	WindowStart      string
	WindowEnd        string
	Timezone         string
	Windows          string
	Frequency        string
	Every            string
	RecheckEvery     string
	NoAdaptive       bool
	Problems         map[string]string
	RunOpen          bool
	Template         string
	Plan             planView
	Summary          summaryView
}

type planView struct {
	Prompt   string
	Problem  string
	Sentence string
	Warnings []string
}

type summaryView struct {
	Text    string
	Problem string
}

type choice struct {
	Value    string
	Label    string
	Note     string
	Selected bool
}

type quickForm struct {
	Targets string
	Preset  string
	Problem string
}

type upload struct {
	name string
	data []byte
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
	Scale      scan.Progress
	Failed     []inventory.FailedGroup
	Busy       string
	Left       string
	NextWindow string
	Groups     []groupRow
	CanPause   bool
	CanResume  bool
	Running    bool
	Live       bool
	LeftRange  string
	LeftFrom   string
	Rate       rateView
}

type rateView struct {
	scan.RateSummary
	MaxRate  int
	Adaptive bool
	MinRate  int
	Slots    int
	Chart    rateChart
}

type rateBar struct {
	X, Y, Height int
	Title        string
}

type rateChart struct {
	Bars          []rateBar
	Limit         string
	Width, Height int
	TopY, AxisY   int
}

const (
	rateChartPlot = 120
	rateChartTop  = 4
	rateBarW      = 8
	rateBarGap    = 2
	rateColumns   = 60
)

func newRateChart(samples []inventory.RateSample, maxRate int, loc *time.Location) rateChart {
	c := rateChart{TopY: rateChartTop, AxisY: rateChartTop + rateChartPlot, Height: rateChartTop + rateChartPlot + 1}
	if len(samples) == 0 || maxRate < 1 {
		return c
	}
	per := (len(samples) + rateColumns - 1) / rateColumns
	var points []string
	for i := 0; i*per < len(samples); i++ {
		col := samples[i*per : min((i+1)*per, len(samples))]
		sent, requests, packets, eff := 0.0, 0.0, 0.0, 0
		for _, s := range col {
			if s.PerSecond()+s.PacketsPerSecond() > sent {
				sent, requests, packets = s.PerSecond()+s.PacketsPerSecond(), s.PerSecond(), s.PacketsPerSecond()
			}
			eff = max(eff, s.Effective)
		}
		x := i * (rateBarW + rateBarGap)
		h := min(int(sent*rateChartPlot/float64(maxRate)), rateChartPlot)
		if sent > 0 && h == 0 {
			h = 1
		}
		ey := c.AxisY - min(eff*rateChartPlot/maxRate, rateChartPlot)
		points = append(points, fmt.Sprintf("%d,%d %d,%d", x, ey, x+rateBarW+rateBarGap, ey))
		c.Bars = append(c.Bars, rateBar{X: x, Y: c.AxisY - h, Height: h,
			Title: fmt.Sprintf("%s: %.1f per second sent, %.1f HTTP requests measured and %.1f nmap packets estimated, limit %d per second",
				zonedTime(col[0].Minute, loc), sent, requests, packets, eff)})
	}
	c.Width = len(c.Bars) * (rateBarW + rateBarGap)
	c.Limit = strings.Join(points, " ")
	return c
}

type previewData struct {
	Definition schedule.Definition
	Plan       scan.Plan
	Ports      string
	Addresses  string
	Packets    string
	Requests   string
	AtMaxRate  string
	AtMeasured string
	Estimate   string
	LiveShare  string
	Earlier    *runRow
}

func digits(n int64) string {
	s := strconv.FormatInt(n, 10)
	if n < 1000 {
		return s
	}
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteString("\u2009")
		}
		b.WriteRune(c)
	}
	return b.String()
}

func RegisterScans(r *Router, d Deps) {
	configure, run := Require(auth.PermScanConfigure), Require(auth.PermScanRun)
	h := &scanHandlers{r: r, s: d.Scans, inv: inventory.New(d.Store, d.Keyring)}
	r.NavIn(NavScanning, "Scans", "/scans", run, "/runs")
	r.Handle(http.MethodGet, "/scans", run, h.list)
	r.Handle(http.MethodGet, "/scans/new", configure, h.newForm)
	r.Handle(http.MethodPost, "/scans", configure, h.create)
	r.Handle(http.MethodPost, "/scans/quick", configure, h.quick)
	r.Handle(http.MethodPost, "/scans/plan", configure, h.plan)
	r.Handle(http.MethodPost, "/scans/schedule-summary", configure, h.summary)
	r.Handle(http.MethodPost, "/scans/custom-ports", configure, h.customPorts)
	r.Handle(http.MethodGet, "/scans/{id}", run, h.show)
	r.Handle(http.MethodGet, "/scans/{id}/edit", configure, h.editForm)
	r.Handle(http.MethodGet, "/scans/{id}/preview", run, h.preview)
	r.Handle(http.MethodPost, "/scans/{id}", configure, h.update)
	r.Handle(http.MethodGet, "/scans/{id}/delete", configure, h.confirmDelete)
	r.Handle(http.MethodPost, "/scans/{id}/delete", configure, h.delete)
	r.Handle(http.MethodPost, "/scans/{id}/enable", configure, h.setEnabled(true))
	r.Handle(http.MethodPost, "/scans/{id}/disable", configure, h.setEnabled(false))
	r.Handle(http.MethodPost, "/scans/{id}/start", run, h.start)
	r.Handle(http.MethodGet, "/runs", run, h.runByName)
	r.Handle(http.MethodGet, "/runs/{id}", Require(auth.PermInventoryRead), h.runPage)
	r.Handle(http.MethodPost, "/runs/{id}/pause", run, h.pause)
	r.Handle(http.MethodPost, "/runs/{id}/resume", run, h.resume)
}

type scanHandlers struct {
	r   *Router
	s   *schedule.Scheduler
	inv *inventory.Inventory
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
	return formatTimeIn(t, nil)
}

func formatTimeIn(t *time.Time, loc *time.Location) string {
	if t == nil {
		return ""
	}
	return zonedTime(*t, loc)
}

func toRunRow(run schedule.Run) runRow {
	started := run.StartedAt
	loc := zoneOf(run.Schedule.Timezone)
	return runRow{ID: run.ID, Name: run.Name, Status: string(run.Status), Held: run.Held, Stalled: run.Stalled,
		Started: formatTimeIn(&started, loc), Finished: formatTimeIn(run.FinishedAt, loc), Recheck: run.Settings.Recheck(), Packets: run.Packets,
		DefinitionDeleted: run.DefinitionDeleted}
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
	h.renderList(w, req, http.StatusOK, quickForm{Preset: presetWeb})
}

func (h *scanHandlers) renderList(w http.ResponseWriter, req *http.Request, status int, quick quickForm) {
	defs, err := h.s.Store.Definitions(req.Context())
	if err != nil {
		h.r.ServerError(w, req, err)
		return
	}
	data := scanListData{CanConfigure: can(req, auth.PermScanConfigure), Quick: quick, Message: scanMessages[req.URL.Query().Get("msg")]}
	data.CanQuick = data.CanConfigure && can(req, auth.PermScanRun)
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
			if f := runs[0].FinishedAt; f != nil {
				row.Duration = formatDuration(f.Sub(runs[0].StartedAt))
			}
		}
		if d.Enabled {
			if next, ok := d.Schedule.NextPlanned(d.LastRunAt, time.Now()); ok {
				row.NextStart = formatTimeIn(&next, zoneOf(d.Schedule.Timezone))
			}
		}
		data.Scans = append(data.Scans, row)
	}
	h.r.Render(w, req, status, "scans.html", View{Title: "Scans", Data: data})
}

func (h *scanHandlers) show(w http.ResponseWriter, req *http.Request) {
	id, ok := pathID(req)
	if !ok {
		h.notFound(w, req, schedule.ErrUnknownDefinition)
		return
	}
	h.renderScan(w, req, id, http.StatusOK, "")
}

func (h *scanHandlers) renderScan(w http.ResponseWriter, req *http.Request, id int64, status int, problem string) {
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
	tz := d.Schedule.Timezone
	if tz == "" {
		tz = "UTC"
	}
	data := scanData{scanRow: toScanRow(d), Message: scanMessages[req.URL.Query().Get("msg")], Problem: problem, Settings: d.Settings,
		Ports: strings.ReplaceAll(scan.FormatPorts(d.Settings.Ports), ",", ", "), Timezone: tz, CanConfigure: can(req, auth.PermScanConfigure)}
	if problem != "" {
		data.Message = ""
	}
	for _, run := range runs {
		data.Runs = append(data.Runs, toRunRow(run))
		data.Open = data.Open || run.Open()
	}
	if err := h.addSavings(req, id, runs, data.Runs); err != nil {
		h.r.ServerError(w, req, err)
		return
	}
	h.r.Render(w, req, status, "scan.html", View{Title: d.Name, Data: data})
}

func (h *scanHandlers) addSavings(req *http.Request, id int64, runs []schedule.Run, rows []runRow) error {
	fullBefore := func(runs []schedule.Run, recheck schedule.Run) (schedule.Run, bool) {
		for _, r := range runs {
			if r.ID < recheck.ID && r.Status == inventory.RunCompleted && !r.Settings.Recheck() {
				return r, true
			}
		}
		return schedule.Run{}, false
	}
	var older []schedule.Run
	for i := range rows {
		rows[i].Saving = "—"
		if !rows[i].Recheck {
			continue
		}
		full, ok := fullBefore(runs, runs[i])
		if !ok && len(runs) == runListLimit {
			if older == nil {
				var err error
				if older, err = h.s.Store.Runs(req.Context(), id, savingLookback); err != nil {
					return err
				}
			}
			full, ok = fullBefore(older, runs[i])
		}
		if ok && full.Packets > 0 {
			rows[i].Saving = fmt.Sprintf("%d%%", int(math.Round(100*(1-float64(runs[i].Packets)/float64(full.Packets)))))
		}
	}
	return nil
}

func (h *scanHandlers) preview(w http.ResponseWriter, req *http.Request) {
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
	settings := d.Settings
	switch mode := req.URL.Query().Get("mode"); mode {
	case "":
	case inventory.ModeRecheck, inventory.ModeFull:
		settings.Mode = mode
	default:
		h.r.Error(w, req, http.StatusBadRequest, fmt.Sprintf("Unknown preview mode %q. Use full or recheck.", mode))
		return
	}
	plan, err := h.s.Scanner.PlanRun(req.Context(), inventory.Run{Settings: settings, DefinitionID: d.ID})
	if errors.Is(err, inventory.ErrNoRecheckBase) {
		h.r.Error(w, req, http.StatusUnprocessableEntity, fmt.Sprintf("The recheck preview could not be made: %s. Run a full scan of this definition first.", err))
		return
	}
	if err != nil {
		h.r.Error(w, req, http.StatusUnprocessableEntity, fmt.Sprintf("The preview could not be made: %s. Edit the scan and correct its settings.", err))
		return
	}
	data := previewData{Definition: d, Plan: plan, Addresses: digits(int64(plan.Addresses)), Packets: digits(plan.Packets),
		Requests: digits(plan.Requests), AtMaxRate: formatDuration(plan.AtMaxRate)}
	if data.Earlier, err = h.useHistory(req.Context(), id, 0, &data.Plan); err != nil {
		h.r.ServerError(w, req, err)
		return
	}
	if data.Plan.MeasuredKnown() {
		data.AtMeasured = formatDuration(data.Plan.AtMeasured)
	}
	data.Estimate = formatRange(data.Plan.EstimateLow, data.Plan.EstimateHigh)
	data.LiveShare = "under 1%"
	if data.Plan.LiveShare >= 0.01 {
		data.LiveShare = strconv.Itoa(int(math.Round(data.Plan.LiveShare*100))) + "%"
	}
	ports := make([]string, len(plan.Ports))
	for i, p := range plan.Ports {
		ports[i] = strconv.Itoa(p)
	}
	data.Ports = strings.Join(ports, ", ")
	h.r.Render(w, req, http.StatusOK, "scan_preview.html", View{Title: "Preview of " + d.Name, Data: data})
}

const (
	templateSingleHost   = "single-host"
	templateLargeNetwork = "large-network"
)

func presetSpec(value string) string {
	for _, p := range portPresets {
		if p.Value == value {
			return p.Spec
		}
	}
	return ""
}

func defaultScanForm() scanForm {
	return scanForm{PortPreset: presetWeb, Ports: presetSpec(presetWeb), Pace: paceNormal,
		Workers: strconv.Itoa(scan.DefaultWorkers), InactiveAfter: strconv.Itoa(inventory.DefaultInactiveAfter),
		ServiceDetection: scan.ServiceDetectionStandard, Mode: inventory.ModeFull, WindowStart: "22:00", WindowEnd: "06:00",
		Timezone: serverTimezone(), Frequency: schedule.FrequencyDaily}
}

func templateScanForm(name string) scanForm {
	f := defaultScanForm()
	switch name {
	case templateSingleHost:
		f.Template, f.PortPreset, f.Ports = name, presetAll, presetSpec(presetAll)
	case templateLargeNetwork:
		f.Template, f.PortPreset, f.Ports = name, presetTop1000, presetSpec(presetTop1000)
		f.Scheduled, f.Days = true, []string{"sat"}
		f.Frequency, f.RecheckEvery = schedule.FrequencyWeekly, "1h"
	}
	return f
}

func (f scanForm) values() url.Values {
	scheduled := "off"
	if f.Scheduled {
		scheduled = "on"
	}
	return url.Values{"name": {f.Name}, "targets": {f.Targets}, "excludes": {f.Excludes}, "port_preset": {f.PortPreset},
		"ports": {f.Ports}, "pace": {f.Pace}, "max_rate": {f.MaxRate}, "workers": {f.Workers}, "inactive_after": {f.InactiveAfter},
		"signatures_dir": {f.SignaturesDir}, "volatile_headers": {f.VolatileHeaders}, "service_detection": {f.ServiceDetection}, "mode": {f.Mode}, "scheduled": {scheduled},
		"days": f.Days, "window_start": {f.WindowStart}, "window_end": {f.WindowEnd}, "timezone": {f.Timezone},
		"windows": {f.Windows}, "frequency": {f.Frequency}, "every": {f.Every}, "recheck_every": {f.RecheckEvery}}
}

func scanFormOf(d schedule.Definition) scanForm {
	f := defaultScanForm()
	preset, custom := presetOf(d.Settings.Ports)
	if preset != presetCustom {
		custom = presetSpec(preset)
	}
	days, start, end, text := windowControls(d.Schedule.Windows)
	f.ID, f.Name = d.ID, d.Name
	f.Targets, f.Excludes = strings.Join(d.Settings.Targets, "\n"), strings.Join(d.Settings.Excludes, "\n")
	f.PortPreset, f.Ports = preset, custom
	f.Pace, f.MaxRate = paceOf(d.Settings.MaxRate)
	f.Workers, f.InactiveAfter = strconv.Itoa(d.Settings.Workers), strconv.Itoa(d.InactiveAfter)
	f.SignaturesDir, f.Mode, f.NoAdaptive = d.Settings.SignaturesDir, d.Settings.RunMode(), d.Settings.NoAdaptive
	f.VolatileHeaders = strings.Join(d.Settings.VolatileHeaders, ", ")
	if d.Settings.ServiceDetection != "" {
		f.ServiceDetection = d.Settings.ServiceDetection
	}
	f.Scheduled, f.Days, f.Windows = d.Enabled, days, text
	if start != "" {
		f.WindowStart, f.WindowEnd = start, end
	}
	f.Timezone = d.Schedule.Timezone
	if f.Timezone == "" {
		f.Timezone = "UTC"
	}
	f.Frequency, f.Every, f.RecheckEvery = d.Schedule.Frequency.Kind, d.Schedule.Frequency.Every, d.Schedule.RecheckEvery
	return f
}

func (f scanForm) PresetChoices() []choice {
	out := make([]choice, len(portPresets))
	for i, p := range portPresets {
		out[i] = choice{Value: p.Value, Label: p.Label, Note: p.Shows, Selected: p.Value == f.PortPreset}
	}
	return out
}

func (q quickForm) PresetChoices() []choice {
	var out []choice
	for _, p := range portPresets {
		if p.Value != presetCustom {
			out = append(out, choice{Value: p.Value, Label: p.Label, Note: p.Shows, Selected: p.Value == q.Preset})
		}
	}
	return out
}

func (f scanForm) PaceChoices() []choice {
	out := make([]choice, len(paceChoices))
	for i, p := range paceChoices {
		out[i] = choice{Value: p.Value, Label: p.Label, Note: p.Sentence, Selected: p.Value == f.Pace}
	}
	return out
}

func (f scanForm) DayChoices() []choice {
	out := make([]choice, len(weekdayValues))
	for i, v := range weekdayValues {
		out[i] = choice{Value: v, Label: weekOrder[i].String(), Selected: slices.Contains(f.Days, v)}
	}
	return out
}

func (f scanForm) TimezoneChoices() []choice {
	var out []choice
	for _, tz := range timezoneOptions(f.Timezone) {
		out = append(out, choice{Value: tz, Label: tz, Selected: tz == f.Timezone})
	}
	return out
}

func (f scanForm) problemIn(keys ...string) bool {
	for _, k := range keys {
		if f.Problems[k] != "" {
			return true
		}
	}
	return false
}

func (f scanForm) ScheduleOpen() bool {
	return f.Scheduled || f.problemIn("days", "window", "timezone", "frequency", "recheck")
}

func (f scanForm) AdvancedOpen() bool {
	return f.Windows != "" || f.problemIn("max rate", "workers", "inactive after", "signatures", "service detection", "mode", "windows")
}

func (f scanForm) AdaptiveSentence() string {
	if f.NoAdaptive {
		return "Adaptive back-off is off for this scan: it keeps the pace even when hosts stop answering in time. It was turned off outside this form and stays off."
	}
	return adaptiveSentence
}

func (h *scanHandlers) newForm(w http.ResponseWriter, req *http.Request) {
	f := templateScanForm(req.URL.Query().Get("template"))
	_, d := parseScanForm(f.values(), nil, schedule.Definition{})
	h.renderForm(w, req, http.StatusOK, "New scan", f, d)
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
	h.renderForm(w, req, http.StatusOK, "Edit "+d.Name, f, d)
}

func (h *scanHandlers) renderForm(w http.ResponseWriter, req *http.Request, status int, title string, f scanForm, d schedule.Definition) {
	f.Plan = h.planOf(req.Context(), f, d)
	f.Summary = summaryOf(f, d)
	h.r.Render(w, req, status, "scan_form.html", View{Title: title, Data: f})
}

func (h *scanHandlers) scanner() *scan.Scanner {
	if h.s == nil || h.s.Scanner == nil {
		return &scan.Scanner{}
	}
	return h.s.Scanner
}

func (h *scanHandlers) planOf(ctx context.Context, f scanForm, d schedule.Definition) planView {
	if p := f.Problems["targets"]; p != "" {
		return planView{Problem: p}
	}
	if len(d.Settings.Targets) == 0 {
		return planView{Prompt: "Enter targets to see how many addresses, packets and requests one run sends and how long it takes."}
	}
	for _, k := range []string{"excludes", "ports", "pace", "max rate"} {
		if p := f.Problems[k]; p != "" {
			return planView{Problem: p}
		}
	}
	p, err := h.scanner().Plan(ctx, d.Settings)
	if err != nil {
		return planView{Problem: fmt.Sprintf("No estimate: %s.", err)}
	}
	return planView{Sentence: planSentence(p), Warnings: planWarnings(p, f.PortPreset)}
}

func summaryOf(f scanForm, d schedule.Definition) summaryView {
	if f.Scheduled {
		for _, k := range []string{"days", "window", "windows", "timezone", "frequency", "recheck"} {
			if p := f.Problems[k]; p != "" {
				return summaryView{Problem: p}
			}
		}
	}
	return summaryView{Text: scheduleSummary(f.Scheduled, d.Schedule)}
}

func (h *scanHandlers) fragment(w http.ResponseWriter, req *http.Request, name string, data any) {
	t, ok := h.r.pages["scan_form.html"]
	if !ok {
		h.r.ServerError(w, req, errors.New("render: scan_form.html is missing"))
		return
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, name, data); err != nil {
		h.r.ServerError(w, req, fmt.Errorf("render %s: %w", name, err))
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = buf.WriteTo(w)
}

func readScanForm(w http.ResponseWriter, req *http.Request) (url.Values, map[string]upload, error) {
	req.Body = http.MaxBytesReader(w, req.Body, maxScanFormBytes)
	if mt, _, _ := mime.ParseMediaType(req.Header.Get("Content-Type")); mt != "multipart/form-data" {
		if err := req.ParseForm(); err != nil {
			return nil, nil, fmt.Errorf("read scan form: %w", err)
		}
		return req.PostForm, nil, nil
	}
	mr, err := req.MultipartReader()
	if err != nil {
		return nil, nil, fmt.Errorf("read scan form: %w", err)
	}
	v, files := url.Values{}, map[string]upload{}
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			return v, files, nil
		}
		if err != nil {
			return nil, nil, fmt.Errorf("read scan form: %w", err)
		}
		data, err := io.ReadAll(part)
		part.Close()
		if err != nil {
			return nil, nil, fmt.Errorf("read scan form: %w", err)
		}
		switch name := part.FormName(); {
		case name == "targets_file" || name == "excludes_file" || part.FileName() != "":
			if len(data) > 0 {
				files[name] = upload{name: part.FileName(), data: data}
			}
		case name != "":
			v.Add(name, string(data))
		}
	}
}

func listOf(typed string, file upload, hasFile bool) ([]string, string) {
	out, problems := targetLines(typed)
	if hasFile {
		more, p := targetFile(file.name, file.data)
		out, problems = append(out, more...), append(problems, p...)
	}
	return out, lineProblemsText(problems)
}

func parseScanForm(v url.Values, files map[string]upload, base schedule.Definition) (scanForm, schedule.Definition) {
	f := scanForm{
		Name: strings.TrimSpace(v.Get("name")), Targets: v.Get("targets"), Excludes: v.Get("excludes"),
		PortPreset: v.Get("port_preset"), Ports: strings.TrimSpace(v.Get("ports")), Pace: v.Get("pace"),
		MaxRate: strings.TrimSpace(v.Get("max_rate")), Workers: strings.TrimSpace(v.Get("workers")),
		InactiveAfter: strings.TrimSpace(v.Get("inactive_after")), SignaturesDir: strings.TrimSpace(v.Get("signatures_dir")),
		VolatileHeaders:  strings.TrimSpace(v.Get("volatile_headers")),
		ServiceDetection: v.Get("service_detection"), Mode: v.Get("mode"), Scheduled: v.Get("scheduled") == "on", Days: v["days"],
		WindowStart: strings.TrimSpace(v.Get("window_start")), WindowEnd: strings.TrimSpace(v.Get("window_end")),
		Timezone: strings.TrimSpace(v.Get("timezone")), Windows: v.Get("windows"), Frequency: v.Get("frequency"),
		Every: strings.TrimSpace(v.Get("every")), RecheckEvery: strings.TrimSpace(v.Get("recheck_every")),
		NoAdaptive: base.Settings.NoAdaptive, Problems: map[string]string{},
	}
	d := base
	d.Name = f.Name
	st := base.Settings
	st.SignaturesDir = f.SignaturesDir
	st.VolatileHeaders = inventory.ParseHeaderNames(f.VolatileHeaders)
	tf, ok := files["targets_file"]
	if st.Targets, f.Problems["targets"] = listOf(f.Targets, tf, ok); f.Problems["targets"] == "" {
		delete(f.Problems, "targets")
	}
	ef, ok := files["excludes_file"]
	if st.Excludes, f.Problems["excludes"] = listOf(f.Excludes, ef, ok); f.Problems["excludes"] == "" {
		delete(f.Problems, "excludes")
	}
	if st.Excludes == nil {
		st.Excludes = []string{}
	}
	ports, err := portsOf(f.PortPreset, f.Ports)
	switch {
	case err != nil && f.PortPreset != "" && f.PortPreset != presetCustom:
		f.Problems["ports"] = fmt.Sprintf("%s. Choose one of the listed port sets.", err)
	case err != nil:
		f.Problems["ports"] = fmt.Sprintf("%s. Enter ports, ranges or a preset separated by commas, for example 80,443,8000-8100 or top100.", err)
	}
	st.Ports = ports
	if f.Pace != "" && !slices.ContainsFunc(paceChoices, func(p paceChoice) bool { return p.Value == f.Pace }) {
		f.Problems["pace"] = fmt.Sprintf("%q is not a pace. Choose Careful, Normal or Fast.", f.Pace)
	}
	if st.MaxRate, err = rateOf(f.Pace, f.MaxRate); err != nil {
		f.Problems["max rate"] = err.Error() + "."
	}
	number := func(key, label, value string) int {
		n, err := strconv.Atoi(value)
		if err != nil {
			f.Problems[key] = fmt.Sprintf("%q is not a number. Enter the %s as a whole number.", value, label)
		}
		return n
	}
	st.Workers = number("workers", "number of workers", f.Workers)
	d.InactiveAfter = number("inactive after", "number of runs", f.InactiveAfter)
	if v.Has("service_detection") {
		switch f.ServiceDetection {
		case scan.ServiceDetectionLight, scan.ServiceDetectionStandard:
			if f.ServiceDetection != scan.ServiceDetectionStandard || st.ServiceDetection != "" {
				st.ServiceDetection = f.ServiceDetection
			}
		default:
			f.Problems["service detection"] = fmt.Sprintf("%q is not a service detection level. Choose light or standard.", f.ServiceDetection)
		}
	}
	if v.Has("mode") {
		switch f.Mode {
		case inventory.ModeFull, inventory.ModeRecheck:
			if st.RunMode() != f.Mode {
				st.Mode = f.Mode
			}
		default:
			f.Problems["mode"] = fmt.Sprintf("%q is not a scan mode. Choose full or recheck.", f.Mode)
		}
	}
	d.Settings = st

	var windows []schedule.Window
	if v.Has("scheduled") {
		anyTime := f.Scheduled && base.ID != 0 && len(base.Schedule.Windows) == 0 && len(f.Days) == 0 && strings.TrimSpace(f.Windows) == ""
		if !anyTime && (f.Scheduled || strings.TrimSpace(f.Windows) != "" || len(f.Days) > 0) {
			ws, err := scheduleWindows(f.Days, f.WindowStart, f.WindowEnd, f.Windows)
			var fp *formProblem
			if errors.As(err, &fp) {
				f.Problems[fp.Field] = fp.Msg
			}
			windows = ws
		}
		d.Enabled = f.Scheduled
	} else {
		if windows, err = schedule.ParseWindows(f.Windows); err != nil {
			f.Problems["windows"] = err.Error()
		}
		f.Scheduled = d.Enabled
	}
	every := ""
	if f.Frequency == schedule.FrequencyInterval {
		every = f.Every
	}
	tz := f.Timezone
	if tz == "UTC" && base.ID != 0 && base.Schedule.Timezone == "" {
		tz = ""
	}
	d.Schedule = schedule.Schedule{Timezone: tz, Windows: windows, Frequency: schedule.Frequency{Kind: f.Frequency, Every: every},
		RecheckEvery: f.RecheckEvery}

	if f.PortPreset == "" {
		f.PortPreset = presetCustom
	}
	if f.Pace == "" {
		f.Pace = paceNormal
	}
	if f.ServiceDetection == "" {
		f.ServiceDetection = scan.ServiceDetectionStandard
	}
	if f.Mode == "" {
		f.Mode = inventory.ModeFull
	}
	return f, d
}

func problemsOf(err error, into map[string]string) bool {
	known := false
	for _, line := range strings.Split(err.Error(), "\n") {
		key, msg, ok := strings.Cut(line, ": ")
		switch key {
		case "name", "targets", "excludes", "ports", "max rate", "workers", "inactive after", "signatures", "timezone", "windows", "frequency", "recheck":
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

func seeOther(w http.ResponseWriter, req *http.Request, loc string) {
	if req.Header.Get("HX-Request") != "" {
		w.Header().Set("HX-Redirect", loc)
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, req, loc, http.StatusSeeOther)
}

const formTooLarge = "The form could not be read. Target lists over 1 MB are not accepted."

func (h *scanHandlers) save(w http.ResponseWriter, req *http.Request, id int64) {
	v, files, err := readScanForm(w, req)
	if err != nil {
		h.r.Error(w, req, htmxStatus(req, http.StatusBadRequest), formTooLarge)
		return
	}
	var base schedule.Definition
	if id != 0 {
		if base, err = h.s.Store.Definition(req.Context(), id); err != nil {
			h.fail(w, req, err)
			return
		}
	}
	f, d := parseScanForm(v, files, base)
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
			if d.Enabled {
				msg = "scheduled"
			}
		} else if saved, err = h.s.Store.UpdateDefinition(req.Context(), scanActor(req), d); err == nil && d.Enabled != base.Enabled {
			err = h.s.Store.SetEnabled(req.Context(), scanActor(req), id, d.Enabled)
		}
		switch {
		case err == nil:
			seeOther(w, req, fmt.Sprintf("/scans/%d?msg=%s", saved.ID, msg))
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
		if _, f.RunOpen, err = h.s.Store.OpenRun(req.Context(), id); err != nil {
			h.r.ServerError(w, req, err)
			return
		}
	}
	h.renderForm(w, req, htmxStatus(req, http.StatusUnprocessableEntity), title, f, d)
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

const quickNameTries = 100

func quickName(targets []string, at time.Time, try int) string {
	what := targets[0]
	if len(targets) > 1 {
		what = fmt.Sprintf("%s and %d more", what, len(targets)-1)
	}
	name := fmt.Sprintf("Quick scan of %s, %s", what, zonedTime(at, nil))
	if try > 1 {
		name = fmt.Sprintf("%s (%d)", name, try)
	}
	return name
}

func (h *scanHandlers) quick(w http.ResponseWriter, req *http.Request) {
	if !can(req, auth.PermScanRun) {
		h.r.Error(w, req, http.StatusForbidden, "Your role does not allow starting scans.")
		return
	}
	v, _, err := readScanForm(w, req)
	if err != nil {
		h.r.Error(w, req, http.StatusBadRequest, formTooLarge)
		return
	}
	q := quickForm{Targets: strings.TrimSpace(v.Get("targets")), Preset: v.Get("port_preset")}
	if q.Preset == "" {
		q.Preset = presetWeb
	}
	in := defaultScanForm()
	in.Name, in.Targets, in.PortPreset, in.Ports = "Quick scan", strings.ReplaceAll(q.Targets, ",", "\n"), q.Preset, ""
	f, d := parseScanForm(in.values(), nil, schedule.Definition{})
	if q.Preset == presetCustom {
		f.Problems["ports"] = "Choose one of the listed port sets. Use New scan for your own ports."
	}
	if len(f.Problems) == 0 && len(d.Settings.Targets) == 0 {
		f.Problems["targets"] = "Enter at least one target, for example 10.0.0.0/24."
	}
	now := time.Now()
	for try := 1; len(f.Problems) == 0; try++ {
		d.Name = quickName(d.Settings.Targets, now, try)
		saved, err := h.s.Store.CreateDefinition(req.Context(), scanActor(req), d)
		if errors.Is(err, schedule.ErrDefinitionExists) && try < quickNameTries {
			continue
		}
		if err != nil {
			if !problemsOf(err, f.Problems) {
				h.r.ServerError(w, req, err)
				return
			}
			break
		}
		run, err := h.s.StartNow(req.Context(), scanActor(req), saved.ID, inventory.ModeFull)
		if err != nil {
			h.fail(w, req, err)
			return
		}
		http.Redirect(w, req, fmt.Sprintf("/runs/%d?msg=started", run.ID), http.StatusSeeOther)
		return
	}
	var parts []string
	for _, k := range []string{"targets", "ports", "name", "max rate", "workers", "inactive after"} {
		if p := f.Problems[k]; p != "" {
			parts = append(parts, p)
		}
	}
	q.Problem = "The scan was not started. " + strings.Join(parts, " ")
	h.renderList(w, req, http.StatusUnprocessableEntity, q)
}

func (h *scanHandlers) plan(w http.ResponseWriter, req *http.Request) {
	v, files, err := readScanForm(w, req)
	if err != nil {
		h.fragment(w, req, "scan-plan", planView{Problem: formTooLarge})
		return
	}
	f, d := parseScanForm(v, files, h.formBase(req))
	h.fragment(w, req, "scan-plan", h.planOf(req.Context(), f, d))
}

func (h *scanHandlers) formBase(req *http.Request) schedule.Definition {
	if id, err := strconv.ParseInt(req.URL.Query().Get("scan"), 10, 64); err == nil && id > 0 && h.s != nil {
		if d, err := h.s.Store.Definition(req.Context(), id); err == nil {
			return d
		}
	}
	return schedule.Definition{}
}

func (h *scanHandlers) customPorts(w http.ResponseWriter, req *http.Request) {
	v, _, err := readScanForm(w, req)
	if err != nil {
		v = url.Values{}
	}
	base := h.formBase(req)
	f, _ := parseScanForm(v, nil, base)
	f.ID = base.ID
	h.fragment(w, req, "custom-ports", f)
}

func (h *scanHandlers) summary(w http.ResponseWriter, req *http.Request) {
	v, _, err := readScanForm(w, req)
	if err != nil {
		h.fragment(w, req, "schedule-summary", summaryView{Problem: formTooLarge})
		return
	}
	f, d := parseScanForm(v, nil, h.formBase(req))
	if err := d.Validate(); err != nil {
		problemsOf(err, f.Problems)
	}
	h.fragment(w, req, "schedule-summary", summaryOf(f, d))
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

func (h *scanHandlers) confirmDelete(w http.ResponseWriter, req *http.Request) {
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
	h.r.Render(w, req, http.StatusOK, "scan_delete.html", View{Title: "Delete scan " + d.Name, Data: d})
}

func (h *scanHandlers) delete(w http.ResponseWriter, req *http.Request) {
	id, ok := pathID(req)
	if !ok {
		h.notFound(w, req, schedule.ErrUnknownDefinition)
		return
	}
	err := h.s.Store.DeleteDefinition(req.Context(), scanActor(req), id)
	if errors.Is(err, schedule.ErrRunOpen) {
		h.renderScan(w, req, id, http.StatusConflict,
			"The scan was not deleted: it has a run in progress or paused. Wait for the run to finish, then delete the scan.")
		return
	}
	if err != nil {
		h.fail(w, req, err)
		return
	}
	http.Redirect(w, req, "/scans?msg=deleted", http.StatusSeeOther)
}

func (h *scanHandlers) start(w http.ResponseWriter, req *http.Request) {
	id, ok := pathID(req)
	if !ok {
		h.notFound(w, req, schedule.ErrUnknownDefinition)
		return
	}
	mode := req.PostFormValue("mode")
	if mode == "" {
		mode = inventory.ModeFull
	}
	if mode != inventory.ModeFull && mode != inventory.ModeRecheck {
		h.r.Error(w, req, http.StatusBadRequest, fmt.Sprintf("%q is not a scan mode. Start a full scan or a recheck.", mode))
		return
	}
	run, err := h.s.StartNow(req.Context(), scanActor(req), id, mode)
	if errors.Is(err, inventory.ErrNoRecheckBase) {
		h.renderScan(w, req, id, http.StatusUnprocessableEntity,
			"The recheck was not started: there is no earlier run to recheck. Start a full scan first.")
		return
	}
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
	return fmt.Sprintf("%s h %d min", digits(int64(h)), m)
}

func (h *scanHandlers) useHistory(ctx context.Context, defID, before int64, plan *scan.Plan) (*runRow, error) {
	runs, err := h.s.Store.Runs(ctx, defID, runListLimit)
	if err != nil {
		return nil, err
	}
	for _, run := range runs {
		if run.Status != inventory.RunCompleted || run.Settings.Recheck() || (before > 0 && run.ID >= before) {
			continue
		}
		groups, err := h.s.Scanner.Store.RunGroups(ctx, run.ID)
		if err != nil {
			return nil, err
		}
		failed, err := h.s.Scanner.Store.FailedGroups(ctx, run.ID)
		if err != nil {
			return nil, err
		}
		scale := run.Run
		scale.AddressTotal = run.AddressTotal
		aps := scan.RunProgress(scale, groups, failed).AddressesPerSecond
		if aps <= 0 {
			continue
		}
		var seen, hosts int
		for _, g := range groups {
			seen += g.AddressCount
			hosts += g.HostsFound
		}
		if seen > 0 {
			plan.UseLiveShare(float64(hosts) / float64(seen))
		}
		plan.Measured(aps)
		rr := toRunRow(run)
		return &rr, nil
	}
	return nil, nil
}

func formatRange(low, high time.Duration) string {
	switch {
	case high <= 0:
		return "-"
	case high < time.Minute:
		return "about 1 min or less"
	case high <= 90*time.Minute:
		lo, hi := max(int(low/time.Minute), 1), int((high+time.Minute-1)/time.Minute)
		if lo >= hi {
			return fmt.Sprintf("about %d min", hi)
		}
		return fmt.Sprintf("about %d-%d min", lo, hi)
	}
	lo, hi := max(int(low/time.Hour), 1), int((high+time.Hour-1)/time.Hour)
	if lo >= hi {
		return fmt.Sprintf("about %d h", hi)
	}
	return fmt.Sprintf("about %d-%d h", lo, hi)
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
	failed, err := h.s.Scanner.Store.FailedGroups(req.Context(), id)
	if err != nil {
		h.r.ServerError(w, req, err)
		return
	}
	scale := run.Run
	scale.AddressTotal = run.AddressTotal
	data := runData{Scale: scan.RunProgress(scale, groups, failed), Failed: failed, Run: toRunRow(run), Message: scanMessages[req.URL.Query().Get("msg")],
		Progress: schedule.ProgressOf(run.AddressTotal, run.Settings.Workers, groups),
		CanPause: run.Open() && !run.Held && can(req, auth.PermScanRun), CanResume: run.Status == inventory.RunPaused && run.DefinitionID != 0 && can(req, auth.PermScanRun),
		Running: run.Status == inventory.RunRunning && !run.Stalled, Live: run.Open()}
	if run.Status == inventory.RunRunning {
		data.Progress = data.Progress.WithInFlight(run.InFlight)
	}
	if run.DefinitionID != 0 {
		if data.Definition, err = h.s.Store.Definition(req.Context(), run.DefinitionID); err != nil {
			h.r.ServerError(w, req, err)
			return
		}
	}
	samples, err := h.inv.RateSamples(req.Context(), id)
	if err != nil {
		h.r.ServerError(w, req, err)
		return
	}
	loc := zoneOf(run.Schedule.Timezone)
	maxRate := run.Settings.MaxRate
	if maxRate < 1 {
		maxRate = scan.DefaultMaxRate
	}
	slots := scan.NmapSlots(run.Settings.Workers, maxRate, run.AddressTotal)
	data.Rate = rateView{RateSummary: scan.SummarizeRate(samples), MaxRate: maxRate, Adaptive: !run.Settings.NoAdaptive,
		MinRate: scan.MinimumRate(maxRate, slots), Slots: slots, Chart: newRateChart(samples, maxRate, loc)}
	data.Busy = formatDuration(data.Progress.Busy)
	if data.Scale.RemainingKnown {
		data.Left = formatDuration(data.Scale.Remaining)
		if run.Open() {
			data.LeftRange = formatRange(time.Duration(float64(data.Scale.Remaining)*scan.MeasuredLow), time.Duration(float64(data.Scale.Remaining)*scan.MeasuredHigh))
			data.LeftFrom = "from the speed of the finished groups"
		}
	} else if run.Open() && !run.Settings.Recheck() {
		if plan, err := h.s.Scanner.Plan(req.Context(), run.Settings); err == nil && plan.Addresses > 0 {
			if run.DefinitionID != 0 {
				earlier, err := h.useHistory(req.Context(), run.DefinitionID, run.ID, &plan)
				if err != nil {
					h.r.ServerError(w, req, err)
					return
				}
				if earlier != nil {
					data.LeftFrom = "from the speed of run " + earlier.Name
				}
			}
			if data.LeftFrom == "" {
				data.LeftFrom = "from the plan, assuming " + strconv.Itoa(int(math.Round(plan.LiveShare*100))) + "% of addresses are live"
			}
			share := float64(max(plan.Addresses-data.Scale.AddressesDone, 0)) / float64(plan.Addresses)
			data.LeftRange = formatRange(time.Duration(float64(plan.EstimateLow)*share), time.Duration(float64(plan.EstimateHigh)*share))
		}
	}
	if run.Status == inventory.RunPaused && !run.Held {
		if next, ok := run.Schedule.NextStart(time.Now()); ok {
			data.NextWindow = formatTimeIn(&next, loc)
		}
	}
	for _, g := range groups {
		c := g.CompletedAt
		data.Groups = append(data.Groups, groupRow{Index: g.Index, Addresses: g.AddressCount, Hosts: g.HostsFound,
			Duration: formatDuration(g.Duration), Completed: formatTimeIn(&c, loc)})
	}
	h.r.Render(w, req, http.StatusOK, "scan_run.html", View{Title: "Run " + run.Name, Data: data})
}

func (h *scanHandlers) runByName(w http.ResponseWriter, req *http.Request) {
	name := req.URL.Query().Get("name")
	if name == "" {
		h.notFound(w, req, schedule.ErrUnknownRun)
		return
	}
	run, err := h.inv.RunByName(req.Context(), name)
	if errors.Is(err, inventory.ErrUnknownRun) {
		h.r.Error(w, req, http.StatusNotFound, fmt.Sprintf("There is no run named %q.", name))
		return
	}
	if err != nil {
		h.r.ServerError(w, req, err)
		return
	}
	http.Redirect(w, req, fmt.Sprintf("/runs/%d", run.ID), http.StatusSeeOther)
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
