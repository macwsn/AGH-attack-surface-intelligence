package web

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"asi/internal/auth"
	"asi/internal/diff"
	"asi/internal/inventory"
)

const (
	chartPlot   = 120
	chartTop    = 8
	chartBarW   = 8
	chartGroup  = 36
	chartLeft   = 4
	chartLabels = 64
)

type chartBar struct {
	Class  string
	X      int
	Y      int
	Height int
}

type chartRun struct {
	diff.RunCounts
	Title  string
	Bars   []chartBar
	LabelX int
	LabelY int
}

type changeChart struct {
	Runs   []chartRun
	Width  int
	Height int
	AxisY  int
	Max    int
}

func RegisterDashboard(r *Router, d Deps) {
	var inv *inventory.Inventory
	if d.Store != nil {
		inv = d.store()
	}
	chartInv := d.Inventory
	if chartInv == nil && inv != nil {
		chartInv = inv
	}
	cache := &changeCache{}
	r.NavIn(NavOverview, "Dashboard", "/", SignedIn())
	r.Handle(http.MethodGet, "/{$}", SignedIn(), func(w http.ResponseWriter, req *http.Request) {
		if p, ok := auth.PrincipalFrom(req.Context()); !ok || !slices.Contains(p.Permissions, auth.PermInventoryRead) {
			r.Render(w, req, http.StatusOK, "dashboard.html", View{Title: "Dashboard", Data: dashboardView{NoInventory: true}})
			return
		}
		v := dashboardView{}
		if inv != nil {
			now := time.Now()
			data, err := inv.Dashboard(req.Context(), now)
			if err != nil {
				r.ServerError(w, req, err)
				return
			}
			summary, err := cache.get(req.Context(), inv, data)
			if err != nil {
				r.ServerError(w, req, err)
				return
			}
			v = newDashboardView(data, summary, now)
			p, _ := auth.PrincipalFrom(req.Context())
			canRead := slices.Contains(p.Permissions, auth.PermInventoryRead)
			v.Attention = newAttention(data, summary, now, canRead)
			if canRead {
				v.AttentionURL = "/changes"
			}
			v.Steps = newSteps(data.Setup, p.Permissions)
		}
		if p, ok := auth.PrincipalFrom(req.Context()); ok && chartInv != nil && slices.Contains(p.Permissions, auth.PermInventoryRead) {
			chart, err := loadChart(req, chartInv)
			if err != nil {
				r.ServerError(w, req, err)
				return
			}
			v.ShowChart, v.Chart = true, chart
		}
		r.Render(w, req, http.StatusOK, "dashboard.html", View{Title: "Dashboard", Data: v})
	})
}

type changeSummary struct {
	Services        inventory.StatusCounts
	Changes         map[string]int
	Hosts           []string
	LatestChanges   map[string]int
	NewHosts        []diff.Change
	MissingServices []diff.Change
}

type changeCache struct {
	mu      sync.Mutex
	version string
	summary changeSummary
}

func (c *changeCache) get(ctx context.Context, inv *inventory.Inventory, d inventory.Dashboard) (changeSummary, error) {
	if d.Latest == nil {
		return changeSummary{Changes: map[string]int{}}, nil
	}
	version := d.Latest.ChangesVersion
	for _, r := range []*inventory.Run{d.ChangesTo, d.ChangesFrom} {
		if r != nil {
			version += fmt.Sprintf("/%d", r.ID)
		} else {
			version += "/-"
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.version == version {
		return c.summary, nil
	}
	latest, err := inv.Export(ctx, d.Latest.Run.Name)
	if err != nil {
		return changeSummary{}, fmt.Errorf("dashboard changes: %w", err)
	}
	s := changeSummary{Changes: map[string]int{}, LatestChanges: map[string]int{}}
	for _, h := range latest.Hosts {
		for _, svc := range h.Services {
			s.Services.Add(svc.Status)
		}
	}
	if d.ChangesTo != nil && d.ChangesFrom != nil {
		to, err := inv.Export(ctx, d.ChangesTo.Name)
		if err != nil {
			return changeSummary{}, fmt.Errorf("dashboard changes: %w", err)
		}
		from, err := inv.Export(ctx, d.ChangesFrom.Name)
		if err != nil {
			return changeSummary{}, fmt.Errorf("dashboard changes: %w", err)
		}
		for _, ch := range diff.Compute(from, to, diff.Options{}).Changes {
			s.Changes[ch.Type]++
			if !slices.Contains(s.Hosts, ch.Address) {
				s.Hosts = append(s.Hosts, ch.Address)
			}
		}
	}
	if d.Latest.PreviousRun != "" {
		from, err := inv.Export(ctx, d.Latest.PreviousRun)
		if err != nil {
			return changeSummary{}, fmt.Errorf("dashboard changes: %w", err)
		}
		for _, ch := range diff.Compute(from, latest, diff.Options{}).Changes {
			s.LatestChanges[ch.Type]++
			switch {
			case ch.Type == diff.HostNew && len(s.NewHosts) < inventory.AttentionItems:
				s.NewHosts = append(s.NewHosts, ch)
			case ch.Type == diff.ServiceMissing && len(s.MissingServices) < inventory.AttentionItems:
				s.MissingServices = append(s.MissingServices, ch)
			}
		}
	}
	c.version, c.summary = version, s
	return s, nil
}

type figure struct {
	Label, Value string
	Alert        bool
}

type changeBar struct {
	Label, Class string
	Count, Max   int
}

type topHostView struct {
	Address, URL, DisplayName string
	Status                    inventory.Status
	StatusLabel               string
	Interest                  int
	InterestHigh              bool
	Kinds                     []mark
}

type findingRow struct {
	Address, URL, Service, Name, SignatureID, Seen, SeenExact string
	Mark                                                      mark
	Confidence                                                int
}

type certRow struct {
	Address, URL, Service, Subject, Issuer, Expiry, ExpiryExact string
	SelfSigned, Expiring                                        bool
}

type scanView struct {
	Run, Status, Started, StartedExact, LastGroup, LastGroupExact string
	Running, Live                                                 bool
	Groups, Addresses, HostsFound                                 string
}

type runLink struct {
	Name, URL string
}

type laterLine struct {
	Label string
	Run   runLink
}

type changedHost struct {
	Address, URL string
}

type dashboardView struct {
	HostFigures    []figure
	ServiceFigures []figure
	Changes        []changeBar
	ChangesTotal   int
	Top            []topHostView
	Findings       []findingRow
	Certs          []certRow
	Scan           *scanView
	ChangesTo      *runLink
	ChangesFrom    *runLink
	ChangesURL     string
	ChangedHosts   []changedHost
	MoreHosts      int
	Later          []laterLine
	ShowChart      bool
	Chart          changeChart
	NoInventory    bool
	Attention      []attentionGroup
	AttentionURL   string
	Steps          []setupStep
}

type attentionItem struct {
	Address, URL, Detail string
}

type attentionGroup struct {
	Label   string
	Class   string
	Items   []attentionItem
	More    string
	MoreURL string
}

type stepLink struct {
	Label, URL string
}

type setupStep struct {
	Number int
	Title  string
	Text   string
	Links  []stepLink
}

func newAttention(d inventory.Dashboard, s changeSummary, now time.Time, canRead bool) []attentionGroup {
	link := func(address string) string {
		if canRead {
			return hostURL(address)
		}
		return ""
	}
	more := func(url string) string {
		if canRead {
			return url
		}
		return ""
	}
	service := func(port *int, protocol string) string {
		if port == nil {
			return ""
		}
		return fmt.Sprintf("%d/%s", *port, protocol)
	}
	var out []attentionGroup
	add := func(g attentionGroup, total int) {
		if len(g.Items) == 0 {
			return
		}
		switch {
		case total < 0 && len(g.Items) > inventory.AttentionItems:
			g.More = "More"
		case total > inventory.AttentionItems:
			g.More = fmt.Sprintf("%s more", count(total-inventory.AttentionItems))
		}
		if len(g.Items) > inventory.AttentionItems {
			g.Items = g.Items[:inventory.AttentionItems]
		}
		out = append(out, g)
	}
	panels := attentionGroup{Label: "New admin panels", Class: "new", MoreURL: more("/hosts/?finding=admin-panel")}
	for _, f := range d.NewPanels {
		panels.Items = append(panels.Items, attentionItem{Address: f.Address, URL: link(f.Address), Detail: fmt.Sprintf("%d/%s %s", f.Port, f.Protocol, f.Name)})
	}
	add(panels, -1)
	hosts := attentionGroup{Label: "New hosts", Class: "new", MoreURL: more("/changes")}
	for _, c := range s.NewHosts {
		hosts.Items = append(hosts.Items, attentionItem{Address: c.Address, URL: link(c.Address)})
	}
	add(hosts, s.LatestChanges[diff.HostNew])
	missing := attentionGroup{Label: "Services that went missing", Class: "missing", MoreURL: more("/changes")}
	for _, c := range s.MissingServices {
		missing.Items = append(missing.Items, attentionItem{Address: c.Address, URL: link(c.Address), Detail: service(c.Port, c.Protocol)})
	}
	add(missing, s.LatestChanges[diff.ServiceMissing])
	certs := attentionGroup{Label: "Certificates expiring within 30 days", Class: "changed"}
	for _, c := range d.Certs {
		if c.NotAfter.IsZero() || c.NotAfter.Sub(now) >= inventory.CertExpiringWindow {
			continue
		}
		certs.Items = append(certs.Items, attentionItem{Address: c.Address, URL: link(c.Address),
			Detail: fmt.Sprintf("%d/%s %s, %s", c.Port, c.Protocol, c.Subject, certExpiry(c.NotAfter.UTC().Format(time.RFC3339), now))})
	}
	add(certs, len(certs.Items))
	slow := attentionGroup{Label: "Hosts slower than usual", Class: "changed"}
	for _, sl := range d.Slow {
		slow.Items = append(slow.Items, attentionItem{Address: sl.Address, URL: link(sl.Address),
			Detail: fmt.Sprintf("%d/%s %d ms, usually %d ms", sl.Port, sl.Protocol, sl.LatestMS, sl.MedianMS)})
	}
	add(slow, -1)
	return out
}

func newSteps(st inventory.Setup, perms []auth.Permission) []setupStep {
	if st.Done() {
		return nil
	}
	can := func(p auth.Permission, l stepLink) []stepLink {
		if slices.Contains(perms, p) {
			return []stepLink{l}
		}
		return nil
	}
	var out []setupStep
	if !st.HasScan {
		out = append(out, setupStep{Number: 1, Title: "Create a scan",
			Text:  "Name the networks and ports to scan and when the scans may run.",
			Links: can(auth.PermScanConfigure, stepLink{"Create a scan", "/scans/new"})})
	}
	if !st.HasCompletedRun {
		out = append(out, setupStep{Number: 2, Title: "Look at hosts and changes",
			Text:  "After the first run completes, the hosts it found and what changed since the run before appear here.",
			Links: append(can(auth.PermInventoryRead, stepLink{"Hosts", "/hosts/"}), can(auth.PermInventoryRead, stepLink{"Changes", "/changes"})...)})
	}
	if !st.HasTeam {
		out = append(out, setupStep{Number: 3, Title: "Add users and roles",
			Text:  "Give colleagues their own accounts, with a built-in role or one that grants exactly what they need.",
			Links: append(can(auth.PermUserManage, stepLink{"Add users", "/users/"}), can(auth.PermRoleManage, stepLink{"Roles", "/roles"})...)})
	}
	return out
}

var changeLabels = []struct{ typ, label, class string }{
	{diff.HostNew, "New hosts", "new"},
	{diff.HostReturned, "Returned hosts", "new"},
	{diff.HostMissing, "Missing hosts", "missing"},
	{diff.HostInactive, "Hosts now inactive", "missing"},
	{diff.ServiceNew, "New services", "new"},
	{diff.ServiceReturned, "Returned services", "new"},
	{diff.ServiceChanged, "Changed services", "changed"},
	{diff.ServiceMissing, "Missing services", "missing"},
	{diff.ServiceInactive, "Services now inactive", "missing"},
}

var runStatusLabels = map[inventory.RunStatus]string{
	inventory.RunRunning: "Running", inventory.RunPaused: "Paused", inventory.RunCompleted: "Completed", inventory.RunFailed: "Failed",
}

const dashboardChangedHosts = 10

var laterLabels = map[string]string{
	inventory.LaterImport: "Latest import", inventory.LaterManual: "Latest manual entry",
	inventory.LaterRecheck: "Latest recheck", inventory.LaterRunning: "Running now",
}

func newRunLink(r inventory.Run) *runLink {
	return &runLink{Name: r.Name, URL: fmt.Sprintf("/runs/%d", r.ID)}
}

func hostURL(address string) string { return "/hosts/" + url.PathEscape(address) }

func newDashboardView(d inventory.Dashboard, s changeSummary, now time.Time) dashboardView {
	v := dashboardView{
		HostFigures: []figure{{"Active hosts", count(d.Hosts.Active), false}, {"Unstable hosts", count(d.Hosts.Unstable), false},
			{"Inactive hosts", count(d.Hosts.Inactive), false}},
		ServiceFigures: []figure{{"Active services", count(s.Services.Active), false}, {"Unstable services", count(s.Services.Unstable), false},
			{"Inactive services", count(s.Services.Inactive), false}},
	}
	maxCount := 0
	for _, n := range s.Changes {
		maxCount = max(maxCount, n)
		v.ChangesTotal += n
	}
	for _, c := range changeLabels {
		if n := s.Changes[c.typ]; n > 0 {
			v.Changes = append(v.Changes, changeBar{Label: c.label, Class: c.class, Count: n, Max: maxCount})
		}
	}
	for _, h := range d.TopHosts {
		t := topHostView{Address: h.Address, URL: hostURL(h.Address), DisplayName: h.DisplayName, Status: h.Status,
			StatusLabel: statusLabels[h.Status], Interest: h.InterestScore, InterestHigh: h.InterestScore >= 70}
		for _, k := range h.FindingKinds {
			t.Kinds = append(t.Kinds, kindMark(k))
		}
		v.Top = append(v.Top, t)
	}
	for _, f := range d.Findings {
		v.Findings = append(v.Findings, findingRow{Address: f.Address, URL: hostURL(f.Address),
			Service: fmt.Sprintf("%d/%s", f.Port, f.Protocol), Name: f.Name, SignatureID: f.SignatureID,
			Seen: ago(f.FirstSeen, now), SeenExact: isoTime(f.FirstSeen), Mark: kindMark(f.Kind), Confidence: f.Confidence})
	}
	for _, c := range d.Certs {
		row := certRow{Address: c.Address, URL: hostURL(c.Address), Service: fmt.Sprintf("%d/%s", c.Port, c.Protocol),
			Subject: c.Subject, Issuer: c.Issuer, SelfSigned: c.SelfSigned}
		if !c.NotAfter.IsZero() {
			row.Expiry, row.ExpiryExact = zonedFormat(c.NotAfter, nil, dateLayout), certExpiry(c.NotAfter.UTC().Format(time.RFC3339), now)
			row.Expiring = c.NotAfter.Sub(now) < inventory.CertExpiringWindow
		}
		v.Certs = append(v.Certs, row)
	}
	if p := d.Latest; p != nil {
		sv := &scanView{Run: p.Run.Name, Status: runStatusLabels[p.Run.Status], Running: p.Run.Status == inventory.RunRunning,
			Live:    p.Run.Status == inventory.RunRunning || p.Run.Status == inventory.RunPaused,
			Started: ago(p.Run.StartedAt, now), StartedExact: isoTime(p.Run.StartedAt), Groups: count(p.Groups),
			Addresses: count(p.Addresses), HostsFound: count(p.HostsFound)}
		if sv.Status == "" {
			sv.Status = strings.ToUpper(string(p.Run.Status[:1])) + string(p.Run.Status[1:])
		}
		if p.LastGroupAt != nil {
			sv.LastGroup, sv.LastGroupExact = ago(*p.LastGroupAt, now), isoTime(*p.LastGroupAt)
		}
		v.Scan = sv
	}
	if d.ChangesTo != nil {
		v.ChangesTo = newRunLink(*d.ChangesTo)
	}
	if d.ChangesFrom != nil {
		v.ChangesFrom = newRunLink(*d.ChangesFrom)
		v.ChangesURL = "/changes?" + url.Values{"from": {d.ChangesFrom.Name}, "to": {d.ChangesTo.Name}}.Encode()
	}
	for i, a := range s.Hosts {
		if i == dashboardChangedHosts {
			v.MoreHosts = len(s.Hosts) - i
			break
		}
		v.ChangedHosts = append(v.ChangedHosts, changedHost{Address: a, URL: hostURL(a)})
	}
	for _, l := range d.Later {
		label := laterLabels[l.Kind]
		if l.Run.Status == inventory.RunPaused {
			label = "Paused now"
		}
		v.Later = append(v.Later, laterLine{Label: label, Run: *newRunLink(l.Run)})
	}
	return v
}

func loadChart(req *http.Request, inv Inventory) (changeChart, error) {
	runs, err := inv.ListRuns(req.Context())
	if err != nil {
		return changeChart{}, err
	}
	var names []string
	for _, run := range runs {
		if run.Status == inventory.RunCompleted {
			names = append(names, run.Name)
		}
	}
	slices.Reverse(names)
	series, err := diff.Series(req.Context(), inv, names, diff.ChartRuns, diff.Options{})
	if err != nil {
		return changeChart{}, fmt.Errorf("dashboard chart: %w", err)
	}
	return newChangeChart(series), nil
}

func newChangeChart(series []diff.RunCounts) changeChart {
	c := changeChart{Width: chartLeft + len(series)*chartGroup + chartLabels, Height: chartTop + chartPlot + chartLabels, AxisY: chartTop + chartPlot, Max: 1}
	for _, s := range series {
		c.Max = max(c.Max, s.New, s.Missing, s.Changed)
	}
	for i, s := range series {
		x := chartLeft + i*chartGroup
		run := chartRun{RunCounts: s, LabelX: x + 2, LabelY: c.AxisY + 12,
			Title: fmt.Sprintf("%s: %d new, %d missing, %d changed (against %s)", s.To, s.New, s.Missing, s.Changed, s.From)}
		for j, v := range []struct {
			class string
			n     int
		}{{"new", s.New}, {"missing", s.Missing}, {"changed", s.Changed}} {
			h := v.n * chartPlot / c.Max
			if v.n > 0 && h == 0 {
				h = 1
			}
			run.Bars = append(run.Bars, chartBar{Class: v.class, X: x + j*(chartBarW+2), Y: c.AxisY - h, Height: h})
		}
		c.Runs = append(c.Runs, run)
	}
	return c
}
