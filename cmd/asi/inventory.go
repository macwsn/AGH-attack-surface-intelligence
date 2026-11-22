package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"asi/internal/config"
	"asi/internal/detect"
	"asi/internal/diff"
	"asi/internal/exchange"
	"asi/internal/exchange/defectdojo"
	"asi/internal/inventory"
	"asi/internal/probe"
	"asi/internal/scan"
	"asi/internal/scan/nmap"
	"asi/internal/store"
	"asi/internal/targets"
)

type inventoryAction func(ctx context.Context, inv *inventory.Inventory, sc *scan.Scanner, stdout io.Writer) error

type scanDeps struct {
	runner    nmap.Runner
	transport func(target string) http.RoundTripper
	dojo      defectdojo.Doer
}

type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }

func (l *stringList) Set(v string) error {
	*l = append(*l, v)
	return nil
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, errUsage
		}
		if fs.NArg() == 0 {
			return positional, nil
		}
		positional = append(positional, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

func flagSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

func parseInventoryCommand(cmd string, args []string) (inventoryAction, error) {
	switch cmd {
	case "scan":
		if len(args) == 0 {
			return nil, errUsage
		}
		switch args[0] {
		case "run", "plan":
			return parseScanRun(args[0], args[1:])
		case "resume", "show":
			name, err := parseRunName(args[0], args[1:])
			if err != nil {
				return nil, err
			}
			if args[0] == "resume" {
				return func(ctx context.Context, inv *inventory.Inventory, sc *scan.Scanner, stdout io.Writer) error {
					return scanResume(ctx, inv, sc, name, stdout)
				}, nil
			}
			return func(ctx context.Context, inv *inventory.Inventory, sc *scan.Scanner, stdout io.Writer) error {
				return scanShow(ctx, inv, name, stdout)
			}, nil
		}
		return nil, errUsage
	case "export":
		return parseExport(args)
	case "diff":
		return parseDiff(args)
	case "import":
		return parseImport(args)
	case "host":
		return parseHostEdit(args)
	case "inventory":
		if len(args) != 1 || args[0] != "rebuild-summary" {
			return nil, errUsage
		}
		return func(ctx context.Context, inv *inventory.Inventory, _ *scan.Scanner, stdout io.Writer) error {
			if err := inv.RefreshSummary(ctx); err != nil {
				return err
			}
			fmt.Fprintln(stdout, "host summary: rebuilt")
			return nil
		}, nil
	case "signature":
		return parseSignatureHunt(args)
	}
	return nil, errUsage
}

func withInventory(ctx context.Context, cfg config.Config, deps scanDeps, stdout io.Writer, action inventoryAction) error {
	keys, err := store.NewKeyring(cfg.MasterKey, cfg.PreviousKeys...)
	if err != nil {
		return err
	}
	s, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := s.CheckKeys(ctx, keys); err != nil {
		return err
	}
	inv := inventory.New(s, keys)
	inv.Interest = cfg.Interest
	inv.BodyRetention = cfg.BodyRetention
	inv.VolatileHeaders = cfg.VolatileHeaders
	return action(ctx, inv, &scan.Scanner{Store: inv, Runner: deps.runner, Transport: deps.transport, Signatures: detect.NewLibrary(s, keys, "")}, stdout)
}

func runError(err error, name string) error {
	if errors.Is(err, inventory.ErrUnknownRun) {
		return fmt.Errorf("unknown run %q", name)
	}
	return err
}

func parseRunName(sub string, args []string) (string, error) {
	pos, err := parseInterspersed(newFlagSet("scan "+sub), args)
	if err != nil || len(pos) != 1 || pos[0] == "" {
		return "", errUsage
	}
	return pos[0], nil
}

func parseScanRun(sub string, args []string) (inventoryAction, error) {
	fs := newFlagSet("scan " + sub)
	targetsFile := fs.String("targets-file", "", "")
	excludeFile := fs.String("exclude-file", "", "")
	portsFlag := fs.String("ports", "", "")
	name := fs.String("name", "", "")
	sigDir := fs.String("signatures-dir", "", "")
	inactiveAfter := fs.Int("inactive-after", inventory.DefaultInactiveAfter, "")
	maxRate := fs.Int("max-rate", scan.DefaultMaxRate, "")
	workers := fs.Int("workers", scan.DefaultWorkers, "")
	httpTimeout := fs.Duration("http-timeout", probe.DefaultTimeout, "")
	maxAddresses := fs.Uint64("max-addresses", scan.DefaultMaxAddresses, "")
	maxWork := fs.Uint64("max-work", scan.DefaultMaxWork, "")
	serviceDetection := fs.String("service-detection", scan.ServiceDetectionStandard, "")
	wait := fs.Bool("wait", false, "")
	noAdaptive := fs.Bool("no-adaptive", false, "")
	mode := fs.String("mode", inventory.ModeFull, "")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		return nil, errUsage
	}
	if *mode != inventory.ModeFull && *mode != inventory.ModeRecheck {
		return nil, fmt.Errorf("--mode must be full|recheck, got %q", *mode)
	}
	if *mode == inventory.ModeFull {
		*mode = ""
	}
	if *targetsFile == "" || !flagSet(fs, "ports") || (sub == "run" && (*name == "" || !*wait)) {
		return nil, errUsage
	}
	ports, err := scan.ParsePorts(*portsFlag)
	if err != nil {
		return nil, fmt.Errorf("--ports: %w", err)
	}
	if *workers < 1 {
		return nil, errors.New("--workers must be at least 1")
	}
	if *maxRate < 2 {
		return nil, errors.New("--max-rate must be at least 2")
	}
	if *inactiveAfter < 1 {
		return nil, errors.New("--inactive-after must be at least 1")
	}
	if *httpTimeout < time.Millisecond {
		return nil, errors.New("--http-timeout must be at least 1ms")
	}
	if *serviceDetection != scan.ServiceDetectionLight && *serviceDetection != scan.ServiceDetectionStandard {
		return nil, errors.New("--service-detection must be light or standard")
	}
	include, err := readTargets(*targetsFile)
	if err != nil {
		return nil, fmt.Errorf("--targets-file: %w", err)
	}
	if len(include) == 0 {
		return nil, fmt.Errorf("--targets-file: no targets in %s", *targetsFile)
	}
	var exclude []string
	if *excludeFile != "" {
		if exclude, err = readTargets(*excludeFile); err != nil {
			return nil, fmt.Errorf("--exclude-file: %w", err)
		}
	}
	if n := countTargets(include, exclude); n > *maxAddresses {
		return nil, fmt.Errorf("--max-addresses: the targets expand to %d addresses, more than the bound of %d; raise --max-addresses or split the targets", n, *maxAddresses)
	}
	dir := *sigDir
	if dir != "" {
		if dir, err = filepath.Abs(dir); err != nil {
			return nil, fmt.Errorf("--signatures-dir: %w", err)
		}
		if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
			return nil, fmt.Errorf("--signatures-dir: %s is not a directory", dir)
		}
		if _, err := detect.LoadDir(dir); err != nil {
			return nil, fmt.Errorf("--signatures-dir: %w", err)
		}
	}
	spec := inventory.RunSpec{
		Name:          *name,
		InactiveAfter: *inactiveAfter,
		Settings: inventory.RunSettings{
			Targets:       include,
			Excludes:      exclude,
			Ports:         ports,
			SignaturesDir: dir,
			MaxRate:       *maxRate,
			Workers:       *workers,
			NoAdaptive:    *noAdaptive,
			Mode:          *mode,
		},
	}
	if flagSet(fs, "max-work") {
		spec.Settings.MaxWork = *maxWork
	}
	if err := scan.CheckWork(spec.Settings); err != nil {
		return nil, fmt.Errorf("--max-work: %w, or raise --max-work", err)
	}
	if flagSet(fs, "http-timeout") {
		spec.Settings.HTTPTimeoutMS = int(httpTimeout.Milliseconds())
	}
	if flagSet(fs, "service-detection") {
		spec.Settings.ServiceDetection = *serviceDetection
	}
	if sub == "plan" {
		return func(ctx context.Context, inv *inventory.Inventory, sc *scan.Scanner, stdout io.Writer) error {
			return scanPlan(ctx, inv, sc, spec.Settings, stdout)
		}, nil
	}
	return func(ctx context.Context, inv *inventory.Inventory, sc *scan.Scanner, stdout io.Writer) error {
		if err := sc.Validate(ctx, spec.Settings); err != nil {
			return fmt.Errorf("run %q: %w", spec.Name, err)
		}
		if spec.Settings.Recheck() {
			if _, err := sc.PlanRecheck(ctx, inventory.Run{Name: spec.Name, Settings: spec.Settings}); err != nil {
				return err
			}
		}
		run, err := inv.CreateRun(ctx, spec)
		if err != nil {
			return err
		}
		return execute(ctx, inv, sc, run, stdout)
	}, nil
}

func countTargets(include, exclude []string) uint64 {
	in, _ := targets.ParseHosts(strings.NewReader(strings.Join(include, "\n")))
	ex, _ := targets.ParseHosts(strings.NewReader(strings.Join(exclude, "\n")))
	return targets.Count(in, ex)
}

func readTargets(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if _, err := targets.ParseHosts(bytes.NewReader(data)); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	return lines, nil
}

func execute(ctx context.Context, inv *inventory.Inventory, sc *scan.Scanner, run inventory.Run, stdout io.Writer) error {
	if err := sc.Run(ctx, run); err != nil {
		return err
	}
	groups, err := inv.RunGroups(ctx, run.ID)
	if err != nil {
		return err
	}
	addrs, hosts := groupTotals(groups)
	fmt.Fprintf(stdout, "run %s status=%s groups=%d addresses=%d hosts=%d\n", run.Name, inventory.RunCompleted, len(groups), addrs, hosts)
	return nil
}

func scanPlan(ctx context.Context, inv *inventory.Inventory, sc *scan.Scanner, st inventory.RunSettings, stdout io.Writer) error {
	p, err := sc.Plan(ctx, st)
	if err != nil {
		return err
	}
	runs, err := inv.ListRuns(ctx)
	if err != nil {
		return err
	}
	earlier := "-"
	for _, run := range runs {
		if run.Status != inventory.RunCompleted || run.Settings.Recheck() || !sameTargets(run.Settings, st) {
			continue
		}
		groups, err := inv.RunGroups(ctx, run.ID)
		if err != nil {
			return err
		}
		failed, err := inv.FailedGroups(ctx, run.ID)
		if err != nil {
			return err
		}
		aps := scan.RunProgress(run, groups, failed).AddressesPerSecond
		if aps <= 0 {
			continue
		}
		p.Measured(aps)
		earlier = run.Name
		break
	}
	ports := make([]string, len(p.Ports))
	for i, port := range p.Ports {
		ports[i] = strconv.Itoa(port)
	}
	measured, atMeasured := "-", "-"
	if p.MeasuredKnown() {
		measured, atMeasured = fmt.Sprintf("%.1f/s", p.MeasuredRate), p.AtMeasured.String()
	}
	fmt.Fprintf(stdout, "plan addresses=%d ports=%s groups=%d group_size=%d packets=%d requests=%d max_rate=%d adaptive=%t duration_at_max_rate=%s measured_run=%s measured_rate=%s duration_measured=%s\n",
		p.Addresses, strings.Join(ports, ","), p.Groups, p.GroupSize, p.Packets, p.Requests, p.MaxRate, p.Adaptive,
		p.AtMaxRate, earlier, measured, atMeasured)
	mode, base, services := inventory.ModeFull, "-", "-"
	if p.Recheck {
		mode, base, services = inventory.ModeRecheck, p.Base, strconv.Itoa(p.Services)
	}
	fmt.Fprintf(stdout, "plan_mode mode=%s base_run=%s services=%s nmap_slots=%d min_rate=%d\n", mode, base, services, p.Slots, p.MinRate)
	if p.Recheck {
		fmt.Fprintf(stdout, "recheck: only the %d known open services of run %s are planned, other addresses and ports are not scanned\n", p.Services, p.Base)
	}
	fmt.Fprintln(stdout, "nothing was sent: packets and requests are worst-case counts (every address up, every port open and speaking HTTP)")
	if p.Adaptive {
		fmt.Fprintf(stdout, "lowest rate when backing off: %d/s, because nmap sends at least one packet per second per slot (nmap slots: %d)\n", p.MinRate, p.Slots)
	}
	return nil
}

func sameTargets(a, b inventory.RunSettings) bool {
	return slices.Equal(a.Targets, b.Targets) && slices.Equal(a.Excludes, b.Excludes)
}

func groupTotals(groups []inventory.GroupInfo) (addrs, hosts int) {
	for _, g := range groups {
		addrs += g.AddressCount
		hosts += g.HostsFound
	}
	return addrs, hosts
}

func scanResume(ctx context.Context, inv *inventory.Inventory, sc *scan.Scanner, name string, stdout io.Writer) error {
	run, err := inv.RunByName(ctx, name)
	if err != nil {
		return runError(err, name)
	}
	if run.Status == inventory.RunRunning && !run.Stalled {
		return fmt.Errorf("run %q is still running in another process; resume it once it is paused or shown as %s", name, inventory.StalledLabel)
	}
	return execute(ctx, inv, sc, run, stdout)
}

func scanShow(ctx context.Context, inv *inventory.Inventory, name string, stdout io.Writer) error {
	run, err := inv.RunByName(ctx, name)
	if err != nil {
		return runError(err, name)
	}
	groups, err := inv.RunGroups(ctx, run.ID)
	if err != nil {
		return err
	}
	failed, err := inv.FailedGroups(ctx, run.ID)
	if err != nil {
		return err
	}
	finished := "-"
	if run.FinishedAt != nil {
		finished = run.FinishedAt.UTC().Format(time.RFC3339)
	}
	addrs, hosts := groupTotals(groups)
	p := scan.RunProgress(run, groups, failed)
	samples, err := inv.RateSamples(ctx, run.ID)
	if err != nil {
		return err
	}
	maxRate := run.Settings.MaxRate
	if maxRate < 1 {
		maxRate = scan.DefaultMaxRate
	}
	rs := scan.SummarizeRate(samples)
	actual, limit := rateCharts(samples, maxRate)
	status := string(run.Status)
	if run.Stalled {
		status = inventory.StalledLabel
	}
	fmt.Fprintf(stdout, "run %s status=%s started=%s finished=%s mode=%s packets=%d requests_measured=%d nmap_packets_estimated=%d max_rate=%d adaptive=%t actual_peak=%.1f/s actual_avg=%.1f/s actual_chart=%s limit_chart=%s groups=%d addresses=%d hosts=%d rate=%.1f/s groups_done=%d/%d failed_groups=%d eta=%s\n",
		run.Name, status, run.StartedAt.UTC().Format(time.RFC3339), finished, run.Settings.RunMode(), run.Packets,
		rs.Requests, rs.Packets, maxRate, !run.Settings.NoAdaptive, rs.Peak, rs.Average, actual, limit,
		len(groups), addrs, hosts, p.AddressesPerSecond, p.GroupsDone, p.GroupsTotal, p.GroupsFailed, p.ETA())
	for _, g := range groups {
		fmt.Fprintf(stdout, "group=%d addresses=%d hosts=%d duration=%s\n", g.Index, g.AddressCount, g.HostsFound, g.Duration.Round(time.Millisecond))
	}
	for _, g := range failed {
		fmt.Fprintf(stdout, "failed_group=%d addresses=%d reason=%q\n", g.Index, len(g.Addresses), g.Reason)
	}
	return nil
}

func rateCharts(samples []inventory.RateSample, maxRate int) (actual, limit string) {
	const columns = 60
	if len(samples) == 0 {
		return "-", "-"
	}
	levels := []rune("▁▂▃▄▅▆▇█")
	level := func(v float64) rune {
		return levels[min(max(int(v/float64(maxRate)*float64(len(levels)-1)+0.5), 0), len(levels)-1)]
	}
	per := (len(samples) + columns - 1) / columns
	var a, l []rune
	for i := 0; i < len(samples); i += per {
		sent, eff := 0.0, 0
		for _, s := range samples[i:min(i+per, len(samples))] {
			sent, eff = max(sent, s.PerSecond()), max(eff, s.Effective)
		}
		a, l = append(a, level(sent)), append(l, level(float64(eff)))
	}
	return string(a), string(l)
}

func parseExport(args []string) (inventoryAction, error) {
	fs := newFlagSet("export")
	format := fs.String("format", "", "")
	out := fs.String("out", "", "")
	runName := fs.String("run", "", "")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 || *format == "" || *out == "" {
		return nil, errUsage
	}
	if *format != "json" && *format != "csv" {
		return nil, fmt.Errorf("--format must be json or csv, got %q", *format)
	}
	if flagSet(fs, "run") && *runName == "" {
		return nil, errors.New("--run must not be empty")
	}
	return func(ctx context.Context, inv *inventory.Inventory, sc *scan.Scanner, stdout io.Writer) error {
		exp, err := inv.Report(ctx, *runName)
		if err != nil {
			return runError(err, *runName)
		}
		var buf bytes.Buffer
		if *format == "csv" {
			if err := exchange.WriteCSV(&buf, exp); err != nil {
				return err
			}
		} else if err := writeJSON(&buf, exp); err != nil {
			return err
		}
		if err := os.WriteFile(*out, buf.Bytes(), 0o644); err != nil {
			return fmt.Errorf("write export: %w", err)
		}
		fmt.Fprintf(stdout, "exported %d hosts as of run %s to %s\n", len(exp.Hosts), exp.Run, *out)
		return nil
	}, nil
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("encode json: %w", err)
	}
	return nil
}

func parseImport(args []string) (inventoryAction, error) {
	fs := newFlagSet("import")
	format := fs.String("format", "", "")
	file := fs.String("file", "", "")
	name := fs.String("name", "", "")
	dryRun := fs.Bool("dry-run", false, "")
	sigDir := fs.String("signatures-dir", "", "")
	inactiveAfter := fs.Int("inactive-after", 0, "")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 || *format == "" || *file == "" {
		return nil, errUsage
	}
	if *format != "json" && *format != "csv" {
		return nil, fmt.Errorf("--format must be json or csv, got %q", *format)
	}
	explicit := false
	fs.Visit(func(f *flag.Flag) { explicit = explicit || f.Name == "inactive-after" })
	if explicit && *inactiveAfter < 1 {
		return nil, errors.New("--inactive-after must be at least 1")
	}
	var sigs *detect.Set
	if *sigDir != "" {
		var err error
		if sigs, err = detect.LoadDir(*sigDir); err != nil {
			return nil, fmt.Errorf("--signatures-dir: %w", err)
		}
	}
	return func(ctx context.Context, inv *inventory.Inventory, sc *scan.Scanner, stdout io.Writer) error {
		f, err := os.Open(*file)
		if err != nil {
			return fmt.Errorf("--file: %w", err)
		}
		data, err := exchange.ReadAll(f)
		f.Close()
		if err != nil {
			return fmt.Errorf("--file: %w", err)
		}
		batch, err := exchange.Parse(*format, data)
		if err != nil {
			return fmt.Errorf("--file: %w", err)
		}
		stored, err := sc.Signatures.Enabled(ctx)
		if err != nil {
			return err
		}
		all, err := detect.Combine(sigs, stored)
		if err != nil {
			return fmt.Errorf("--signatures-dir: %w", err)
		}
		rep, err := exchange.Apply(ctx, inv, batch, exchange.Options{Name: *name, InactiveAfter: *inactiveAfter, DryRun: *dryRun, Signatures: all,
			Actor: inventory.Editor(cliActor)})
		for _, e := range rep.Errors {
			fmt.Fprintf(stdout, "%s\n", e)
		}
		if more := rep.Invalid - len(rep.Errors); more > 0 {
			fmt.Fprintf(stdout, "%d more invalid rows not listed\n", more)
		}
		if err != nil {
			return runError(err, *name)
		}
		verb := "imported"
		if rep.DryRun {
			verb = "dry run: would import"
		}
		fmt.Fprintf(stdout, "%s %d hosts, %d services as run %s; %d invalid rows; %d changes; %d left as stored (not active in the file)\n",
			verb, rep.Hosts, rep.Services, rep.Run, rep.Invalid, len(rep.Changes.Changes), rep.Skipped)
		for _, c := range rep.Changes.Changes {
			fmt.Fprintf(stdout, "%s\n", formatChange(c))
		}
		return nil
	}, nil
}

func formatChange(c diff.Change) string {
	s := c.Type + " " + c.Address
	if c.Port != nil {
		s += fmt.Sprintf(" %d/%s", *c.Port, c.Protocol)
	}
	for _, f := range c.Fields {
		s += fmt.Sprintf(" %s: %v -> %v", f.Field, f.Old, f.New)
	}
	return s
}

func parseDiff(args []string) (inventoryAction, error) {
	fs := newFlagSet("diff")
	from := fs.String("from", "", "")
	to := fs.String("to", "", "")
	format := fs.String("format", "json", "")
	out := fs.String("out", "", "")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 || *from == "" || *to == "" || *out == "" {
		return nil, errUsage
	}
	if *format != "json" {
		return nil, fmt.Errorf("--format must be json, got %q", *format)
	}
	return func(ctx context.Context, inv *inventory.Inventory, sc *scan.Scanner, stdout io.Writer) error {
		d, err := diff.Between(ctx, inv, *from, *to, diff.Options{})
		if err != nil {
			return err
		}
		var buf bytes.Buffer
		if err := diff.WriteJSON(&buf, d); err != nil {
			return err
		}
		if err := os.WriteFile(*out, buf.Bytes(), 0o644); err != nil {
			return fmt.Errorf("write diff: %w", err)
		}
		fmt.Fprintf(stdout, "%d changes from %s to %s written to %s\n", len(d.Changes), *from, *to, *out)
		return nil
	}, nil
}

func parseHostEdit(args []string) (inventoryAction, error) {
	if len(args) == 0 || args[0] != "edit" {
		return nil, errUsage
	}
	fs := newFlagSet("host edit")
	var add, remove stringList
	fs.Var(&add, "add-tag", "")
	fs.Var(&remove, "remove-tag", "")
	notes := fs.String("notes", "", "")
	pos, err := parseInterspersed(fs, args[1:])
	if err != nil || len(pos) != 1 {
		return nil, errUsage
	}
	ip, err := netip.ParseAddr(pos[0])
	if err != nil {
		return nil, fmt.Errorf("invalid address %q", pos[0])
	}
	addr := ip.Unmap().String()
	for _, t := range append(slices.Clone(add), remove...) {
		if strings.TrimSpace(t) == "" {
			return nil, errors.New("--add-tag and --remove-tag need a non-empty tag")
		}
	}
	setNotes := flagSet(fs, "notes")
	return func(ctx context.Context, inv *inventory.Inventory, sc *scan.Scanner, stdout io.Writer) error {
		f, err := inv.GetHostUserFields(ctx, addr)
		if errors.Is(err, inventory.ErrUnknownHost) {
			return fmt.Errorf("unknown host %s", addr)
		}
		if err != nil {
			return err
		}
		for _, t := range add {
			if !slices.Contains(f.Tags, t) {
				f.Tags = append(f.Tags, t)
			}
		}
		f.Tags = slices.DeleteFunc(f.Tags, func(t string) bool { return slices.Contains(remove, t) })
		if setNotes {
			f.Notes = *notes
		}
		if err := inv.EditHostUserFields(ctx, inventory.Editor(cliActor), addr, f); err != nil {
			return err
		}
		line := fmt.Sprintf("host %s updated: tags=%s", addr, strings.Join(f.Tags, ","))
		if setNotes {
			line += fmt.Sprintf(" notes=%q", f.Notes)
		}
		fmt.Fprintln(stdout, line)
		return nil
	}, nil
}

func parseSignatureHunt(args []string) (inventoryAction, error) {
	if len(args) == 0 || args[0] != "hunt" {
		return nil, errUsage
	}
	fs := newFlagSet("signature hunt")
	file := fs.String("file", "", "")
	sinceFlag := fs.String("since", "", "")
	format := fs.String("format", "text", "")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() > 0 || *file == "" {
		return nil, errUsage
	}
	if *format != "text" && *format != "json" {
		return nil, fmt.Errorf("--format must be text or json, got %q", *format)
	}
	var since time.Duration
	if *sinceFlag != "" {
		var err error
		if since, err = inventory.ParseSince(*sinceFlag); err != nil {
			return nil, fmt.Errorf("--since: %w", err)
		}
	}
	src, err := os.ReadFile(*file)
	if err != nil {
		return nil, fmt.Errorf("--file: %w", err)
	}
	sig, err := detect.ParseOne(src)
	if err != nil {
		return nil, fmt.Errorf("--file: %w", err)
	}
	return func(ctx context.Context, inv *inventory.Inventory, _ *scan.Scanner, stdout io.Writer) error {
		spec := inventory.HuntSpec{Signature: sig, Source: string(src), Actor: "cli", Addr: "local"}
		if since > 0 {
			spec.Since = time.Now().Add(-since)
		}
		h, err := inv.RunHunt(ctx, spec)
		if err != nil {
			return err
		}
		if *format == "json" {
			return writeHuntJSON(ctx, inv, h, stdout)
		}
		fmt.Fprintf(stdout, "hunt %d signature=%s observations=%d matched=%d not_evaluable=%d latest_run=%s duration=%s\n",
			h.ID, h.SignatureID, h.Observations, h.Matched, h.NotEvaluable, h.LatestRun, h.Duration.Round(time.Millisecond))
		return inv.HuntResults(ctx, h.ID, 0, 0, func(r inventory.HuntResult) error {
			if !r.Evaluable {
				_, err := fmt.Fprintf(stdout, "%s %d/%s not evaluable from history\n", r.Address, r.Port, r.Protocol)
				return err
			}
			_, err := fmt.Fprintf(stdout, "%s %d/%s first_run=%s last_run=%s latest=%t version=%s\n",
				r.Address, r.Port, r.Protocol, r.FirstRun, r.LastRun, r.InLatest, r.Version)
			return err
		})
	}, nil
}

func writeHuntJSON(ctx context.Context, inv *inventory.Inventory, h inventory.Hunt, w io.Writer) error {
	head, err := json.Marshal(h)
	if err != nil {
		return fmt.Errorf("encode hunt: %w", err)
	}
	if _, err := fmt.Fprintf(w, `{"schema":%q,"hunt":%s,"results":[`, inventory.HuntSchema, head); err != nil {
		return err
	}
	sep := "\n"
	if err := inv.HuntResults(ctx, h.ID, 0, 0, func(r inventory.HuntResult) error {
		b, err := json.Marshal(r)
		if err != nil {
			return fmt.Errorf("encode hunt result: %w", err)
		}
		_, err = fmt.Fprintf(w, "%s%s", sep, b)
		sep = ",\n"
		return err
	}); err != nil {
		return err
	}
	_, err = fmt.Fprint(w, "]}\n")
	return err
}
