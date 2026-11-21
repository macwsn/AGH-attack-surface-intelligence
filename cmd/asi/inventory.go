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
	"strings"
	"time"

	"asi/internal/config"
	"asi/internal/detect"
	"asi/internal/diff"
	"asi/internal/exchange"
	"asi/internal/inventory"
	"asi/internal/scan"
	"asi/internal/scan/nmap"
	"asi/internal/store"
	"asi/internal/targets"
)

type inventoryAction func(ctx context.Context, inv *inventory.Inventory, sc *scan.Scanner, stdout io.Writer) error

type scanDeps struct {
	runner    nmap.Runner
	transport func(target string) http.RoundTripper
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
		case "run":
			return parseScanRun(args[1:])
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
	case "host":
		return parseHostEdit(args)
	}
	return nil, errUsage
}

func withInventory(ctx context.Context, cfg config.Config, deps scanDeps, stdout io.Writer, action inventoryAction) error {
	keys, err := store.NewKeyring(cfg.MasterKey)
	if err != nil {
		return err
	}
	s, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer s.Close()
	inv := inventory.New(s, keys)
	return action(ctx, inv, &scan.Scanner{Store: inv, Runner: deps.runner, Transport: deps.transport, Signatures: detect.NewLibrary(s, "")}, stdout)
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

func parseScanRun(args []string) (inventoryAction, error) {
	fs := newFlagSet("scan run")
	targetsFile := fs.String("targets-file", "", "")
	excludeFile := fs.String("exclude-file", "", "")
	portsFlag := fs.String("ports", "", "")
	name := fs.String("name", "", "")
	sigDir := fs.String("signatures-dir", "", "")
	inactiveAfter := fs.Int("inactive-after", inventory.DefaultInactiveAfter, "")
	maxRate := fs.Int("max-rate", scan.DefaultMaxRate, "")
	workers := fs.Int("workers", scan.DefaultWorkers, "")
	wait := fs.Bool("wait", false, "")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		return nil, errUsage
	}
	if *targetsFile == "" || !flagSet(fs, "ports") || *name == "" || !*wait {
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
		},
	}
	return func(ctx context.Context, inv *inventory.Inventory, sc *scan.Scanner, stdout io.Writer) error {
		run, err := inv.CreateRun(ctx, spec)
		if err != nil {
			return err
		}
		return execute(ctx, inv, sc, run, stdout)
	}, nil
}

func readTargets(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if _, err := targets.Parse(bytes.NewReader(data)); err != nil {
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
	fmt.Fprintf(stdout, "run %s status=%s started=%s finished=%s groups=%d addresses=%d hosts=%d rate=%.1f/s groups_done=%d/%d failed_groups=%d eta=%s\n",
		run.Name, run.Status, run.StartedAt.UTC().Format(time.RFC3339), finished, len(groups), addrs, hosts,
		p.AddressesPerSecond, p.GroupsDone, p.GroupsTotal, p.GroupsFailed, p.ETA())
	for _, g := range groups {
		fmt.Fprintf(stdout, "group=%d addresses=%d hosts=%d duration=%s\n", g.Index, g.AddressCount, g.HostsFound, g.Duration.Round(time.Millisecond))
	}
	for _, g := range failed {
		fmt.Fprintf(stdout, "failed_group=%d addresses=%d reason=%q\n", g.Index, len(g.Addresses), g.Reason)
	}
	return nil
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
		exp, err := inv.Export(ctx, *runName)
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
		a, err := inv.Export(ctx, *from)
		if err != nil {
			return runError(err, *from)
		}
		b, err := inv.Export(ctx, *to)
		if err != nil {
			return runError(err, *to)
		}
		d := diff.Compute(a, b, diff.Options{})
		var buf bytes.Buffer
		if err := writeJSON(&buf, d); err != nil {
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
		if err := inv.UpdateHostUserFields(ctx, addr, f); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "host %s updated: tags=%s\n", addr, strings.Join(f.Tags, ","))
		return nil
	}, nil
}
