package web

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"asi/internal/scan"
	"asi/internal/schedule"
	"asi/internal/targets"
)

const (
	planAddressBound = 65536
	allPortsCount    = 65535
	maxLineProblems  = 10
	adaptiveSentence = "Adaptive back-off is on: when hosts stop answering in time, the scan slows down below this pace and speeds up again once the network recovers."
	manualSchedule   = "Run only when started by hand"
)

const (
	presetWeb     = "web"
	presetTop100  = "top100"
	presetTop1000 = "top1000"
	presetAll     = "all"
	presetCustom  = "custom"
)

type portPreset struct {
	Value string
	Label string
	Spec  string
	Shows string
}

var portPresets = []portPreset{
	{Value: presetWeb, Label: "Web", Spec: "80,443,8000,8080,8443", Shows: "80, 443, 8000, 8080, 8443"},
	{Value: presetTop100, Label: "Top 100", Spec: "top100", Shows: "the 100 most common ports"},
	{Value: presetTop1000, Label: "Top 1000", Spec: "top1000", Shows: "the " + digits(1000) + " most common ports"},
	{Value: presetAll, Label: "All", Spec: "all", Shows: "all " + digits(allPortsCount) + " ports"},
	{Value: presetCustom, Label: "Custom", Shows: "the ports you enter, for example 80,443,8000-8100"},
}

func portsOf(preset, custom string) ([]int, error) {
	if preset == "" || preset == presetCustom {
		return scan.ParsePorts(custom)
	}
	for _, p := range portPresets {
		if p.Value == preset {
			return scan.ParsePorts(p.Spec)
		}
	}
	return nil, fmt.Errorf("%q is not a port set", preset)
}

func presetOf(ports []int) (preset, custom string) {
	for _, p := range portPresets {
		if p.Spec == "" {
			continue
		}
		if want, err := scan.ParsePorts(p.Spec); err == nil && slices.Equal(want, ports) {
			return p.Value, ""
		}
	}
	return presetCustom, scan.FormatPorts(ports)
}

const (
	paceCareful = "careful"
	paceNormal  = "normal"
	paceFast    = "fast"
)

type paceChoice struct {
	Value    string
	Label    string
	Rate     int
	Sentence string
}

var paceChoices = []paceChoice{
	{Value: paceCareful, Label: "Careful", Rate: 20,
		Sentence: "At most 20 packets and requests per second: the lightest load, for fragile devices, slow links or networks you do not know."},
	{Value: paceNormal, Label: "Normal", Rate: scan.DefaultMaxRate,
		Sentence: "At most 100 packets and requests per second: safe for most campus and office networks."},
	{Value: paceFast, Label: "Fast", Rate: 500,
		Sentence: "At most 500 packets and requests per second: finishes sooner but loads firewalls and hosts noticeably, only for networks you know can take it."},
}

func paceRate(pace string) int {
	for _, p := range paceChoices {
		if p.Value == pace {
			return p.Rate
		}
	}
	return scan.DefaultMaxRate
}

func rateOf(pace, maxRate string) (int, error) {
	maxRate = strings.TrimSpace(maxRate)
	if maxRate == "" {
		return paceRate(pace), nil
	}
	n, err := strconv.Atoi(maxRate)
	if err != nil {
		return 0, fmt.Errorf("%q is not a number. Enter the max rate as a whole number", maxRate)
	}
	return n, nil
}

func paceOf(rate int) (pace, exact string) {
	for _, p := range paceChoices {
		if p.Rate == rate {
			return p.Value, ""
		}
	}
	return paceNormal, strconv.Itoa(rate)
}

type lineProblem struct {
	File string
	Line int
	Text string
	Err  error
}

func (p lineProblem) String() string {
	where := fmt.Sprintf("line %d", p.Line)
	if p.File != "" {
		where = fmt.Sprintf("file %s, line %d", p.File, p.Line)
	}
	return fmt.Sprintf("%s: invalid target %q: %v", where, p.Text, p.Err)
}

func checkTarget(text string) error {
	_, err := targets.ParseHosts(strings.NewReader(text))
	if pe, ok := err.(*targets.ParseError); ok {
		return pe.Err
	}
	return err
}

func targetLines(text string) ([]string, []lineProblem) {
	var out []string
	var problems []lineProblem
	for i, line := range strings.Split(text, "\n") {
		if j := strings.IndexByte(line, '#'); j >= 0 {
			line = line[:j]
		}
		if line = strings.TrimSpace(line); line == "" {
			continue
		}
		if err := checkTarget(line); err != nil {
			problems = append(problems, lineProblem{Line: i + 1, Text: line, Err: err})
			continue
		}
		out = append(out, line)
	}
	return out, problems
}

func targetFile(name string, data []byte) ([]string, []lineProblem) {
	if name == "" {
		name = "upload"
	}
	text := strings.TrimPrefix(string(data), "\ufeff")
	var out []string
	var problems []lineProblem
	header := true
	for i, line := range strings.Split(text, "\n") {
		if j := strings.IndexByte(line, '#'); j >= 0 {
			line = line[:j]
		}
		if j := strings.IndexAny(line, ",;\t"); j >= 0 {
			line = line[:j]
		}
		if line = strings.Trim(strings.TrimSpace(line), `"'`); line == "" {
			continue
		}
		if header {
			header = false
			switch strings.ToLower(line) {
			case "target", "targets", "address", "addresses":
				continue
			}
		}
		if err := checkTarget(line); err != nil {
			problems = append(problems, lineProblem{File: name, Line: i + 1, Text: line, Err: err})
			continue
		}
		out = append(out, line)
	}
	return out, problems
}

func lineProblemsText(problems []lineProblem) string {
	if len(problems) == 0 {
		return ""
	}
	parts := make([]string, 0, min(len(problems), maxLineProblems)+1)
	for _, p := range problems[:min(len(problems), maxLineProblems)] {
		parts = append(parts, p.String())
	}
	if n := len(problems) - maxLineProblems; n > 0 {
		parts = append(parts, fmt.Sprintf("and %d more invalid lines", n))
	}
	return strings.Join(parts, "; ") + ". Enter one target per line: an address, a CIDR, a range such as 10.0.0.1-20 or a host name."
}

type formProblem struct {
	Field string
	Msg   string
}

func (p *formProblem) Error() string { return p.Msg }

var weekdayValues = []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"}

func scheduleWindows(days []string, start, end, text string) ([]schedule.Window, error) {
	if strings.TrimSpace(text) != "" {
		ws, err := schedule.ParseWindows(text)
		if err != nil {
			return nil, &formProblem{Field: "windows", Msg: err.Error()}
		}
		return ws, nil
	}
	var picked []string
	for _, d := range weekdayValues {
		if slices.Contains(days, d) {
			picked = append(picked, d)
		}
	}
	if len(picked) == 0 {
		return nil, &formProblem{Field: "days", Msg: "Choose at least one weekday on which the scan may run."}
	}
	start, end = strings.TrimSpace(start), strings.TrimSpace(end)
	if start == "" || end == "" {
		return nil, &formProblem{Field: "window", Msg: "Enter the start and end time of the window, for example 22:00 and 06:00."}
	}
	w, err := schedule.ParseWindow(strings.Join(picked, ",") + " " + start + "-" + end)
	if err != nil {
		return nil, &formProblem{Field: "window", Msg: err.Error()}
	}
	return []schedule.Window{w}, nil
}

func windowControls(ws []schedule.Window) (days []string, start, end, text string) {
	if len(ws) != 1 {
		return nil, "", "", schedule.FormatWindows(ws)
	}
	for _, d := range ws[0].Days {
		days = append(days, weekdayValues[(int(d)+6)%7])
	}
	return days, ws[0].Start, ws[0].End, ""
}

var weekOrder = []time.Weekday{time.Monday, time.Tuesday, time.Wednesday, time.Thursday, time.Friday, time.Saturday, time.Sunday}

func daysText(days []time.Weekday) string {
	if len(days) == 7 {
		return "day"
	}
	var parts []string
	for i := 0; i < len(weekOrder); {
		if !slices.Contains(days, weekOrder[i]) {
			i++
			continue
		}
		j := i
		for j+1 < len(weekOrder) && slices.Contains(days, weekOrder[j+1]) {
			j++
		}
		switch j - i {
		case 0:
			parts = append(parts, weekOrder[i].String())
		case 1:
			parts = append(parts, weekOrder[i].String(), weekOrder[j].String())
		default:
			parts = append(parts, weekOrder[i].String()+" to "+weekOrder[j].String())
		}
		i = j + 1
	}
	return strings.Join(parts, ", ")
}

func windowsText(ws []schedule.Window) string {
	parts := make([]string, len(ws))
	for i, w := range ws {
		parts[i] = daysText(w.Days) + " " + w.Start + "-" + w.End
	}
	return strings.Join(parts, " and ")
}

func everyText(s string) string {
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return s
	}
	unit := func(n int64, one string) string {
		if n == 1 {
			return one
		}
		return fmt.Sprintf("%d %ss", n, one)
	}
	switch {
	case d%time.Hour == 0:
		return unit(int64(d/time.Hour), "hour")
	case d%time.Minute == 0:
		return unit(int64(d/time.Minute), "minute")
	}
	return d.String()
}

func scheduleSummary(enabled bool, s schedule.Schedule) string {
	if !enabled {
		return manualSchedule
	}
	var full string
	single := len(s.Windows) == 1 && len(s.Windows[0].Days) == 1
	switch s.Frequency.Kind {
	case schedule.FrequencyWeekly:
		switch {
		case len(s.Windows) == 0:
			full = "Full scan once a week"
		case single:
			full = "Full scan every " + windowsText(s.Windows)
		default:
			full = "Full scan once a week during " + windowsText(s.Windows)
		}
	case schedule.FrequencyInterval:
		full = "Full scan every " + everyText(s.Frequency.Every)
		if len(s.Windows) > 0 {
			full += " during " + windowsText(s.Windows)
		}
	default:
		full = "Full scan every day"
		if len(s.Windows) > 0 {
			full = "Full scan every " + windowsText(s.Windows)
		}
	}
	if s.RecheckEvery != "" {
		full += "; recheck of known services every " + everyText(s.RecheckEvery)
	}
	return full
}

func countOf(n int64, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return digits(n) + " " + many
}

func planSentence(p scan.Plan) string {
	return fmt.Sprintf("%s after excludes, %s, %s, at most %s packets and requests, estimated %s at this rate (at most %s if every address answered)",
		countOf(int64(p.Addresses), "address", "addresses"), countOf(int64(len(p.Ports)), "port", "ports"),
		countOf(int64(p.Groups), "group", "groups"), digits(p.Packets+p.Requests), formatRange(p.EstimateLow, p.EstimateHigh), planTime(p))
}

func planTime(p scan.Plan) string {
	if p.MaxRate < 2 {
		return formatDuration(p.AtMaxRate)
	}
	secs := max(float64(p.Packets)/float64(p.MaxRate/2), float64(p.Requests)/float64(p.MaxRate-p.MaxRate/2))
	if secs < 1e6*3600 {
		return formatDuration(p.AtMaxRate)
	}
	return digits(int64(secs/3600)) + " h"
}

func planWarnings(p scan.Plan, preset string) []string {
	var out []string
	if p.Addresses > planAddressBound {
		out = append(out, fmt.Sprintf("%s addresses is above the bound of %s addresses for one scan: it runs for a long time and loads the network; split the targets into several scans.",
			digits(int64(p.Addresses)), digits(planAddressBound)))
	}
	if preset == presetAll || len(p.Ports) == allPortsCount {
		out = append(out, fmt.Sprintf("All %s ports are scanned on every address: this sends far more traffic and takes much longer than a named set.",
			digits(allPortsCount)))
	}
	return out
}

func serverTimezone() string {
	if name := time.Local.String(); name != "" && name != "Local" {
		return name
	}
	return "UTC"
}

var commonTimezones = []string{"UTC", "Europe/Warsaw", "Europe/London", "Europe/Berlin", "Europe/Paris", "America/New_York", "America/Chicago", "America/Los_Angeles", "Asia/Tokyo"}

func timezoneOptions(selected string) []string {
	out := slices.Clone(commonTimezones)
	for _, tz := range []string{serverTimezone(), selected} {
		if tz != "" && !slices.Contains(out, tz) {
			out = append(out, tz)
		}
	}
	return out
}
