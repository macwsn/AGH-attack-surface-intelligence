package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"asi/internal/auth"
	"asi/internal/config"
	"asi/internal/exchange/defectdojo"
	"asi/internal/inventory"
	"asi/internal/store"
)

const dojoTimeout = 2 * time.Minute

var cliActor = auth.Actor{Username: "cli", Addr: "local"}

type dojoAction func(ctx context.Context, svc *defectdojo.Service, stdin io.Reader, stdout io.Writer) error

func parseDefectDojo(args []string) (dojoAction, error) {
	if len(args) == 0 {
		return nil, errUsage
	}
	switch args[0] {
	case "configure":
		return parseDojoConfigure(args[1:])
	case "test":
		if len(args) > 1 {
			return nil, errUsage
		}
		return func(ctx context.Context, svc *defectdojo.Service, _ io.Reader, stdout io.Writer) error {
			if err := svc.TestConnection(ctx); err != nil {
				return err
			}
			if err := svc.CheckStoredTests(ctx); err != nil {
				return err
			}
			fmt.Fprintln(stdout, "defectdojo: connection ok")
			return nil
		}, nil
	case "export":
		return parseDojoExport(args[1:])
	}
	return nil, errUsage
}

func parseDojoConfigure(args []string) (dojoAction, error) {
	fs := newFlagSet("defectdojo configure")
	var c defectdojo.Config
	fs.StringVar(&c.BaseURL, "url", "", "")
	fs.IntVar(&c.ProductID, "product", 0, "")
	fs.IntVar(&c.EngagementID, "engagement", 0, "")
	tokenStdin := fs.Bool("token-stdin", false, "")
	fs.BoolVar(&c.Force, "force", false, "")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 || c.BaseURL == "" || c.ProductID == 0 || c.EngagementID == 0 {
		return nil, errUsage
	}
	return func(ctx context.Context, svc *defectdojo.Service, stdin io.Reader, stdout io.Writer) error {
		if *tokenStdin {
			token, err := bufio.NewReader(stdin).ReadString('\n')
			if err != nil && !errors.Is(err, io.EOF) {
				return fmt.Errorf("read token from stdin: %w", err)
			}
			c.Token = strings.TrimSpace(token)
			if c.Token == "" {
				return errors.New("--token-stdin: no token on stdin")
			}
		}
		if err := svc.Configure(ctx, cliActor, c); err != nil {
			if errors.Is(err, defectdojo.ErrNotSaved) {
				return fmt.Errorf("%w (use --force to save it anyway)", err)
			}
			return err
		}
		fmt.Fprintf(stdout, "defectdojo: configured product %d engagement %d\n", c.ProductID, c.EngagementID)
		return nil
	}, nil
}

func parseDojoExport(args []string) (dojoAction, error) {
	fs := newFlagSet("defectdojo export")
	runName := fs.String("run", "", "")
	dryRun := fs.Bool("dry-run", false, "")
	out := fs.String("out", "", "")
	force := fs.Bool("force", false, "")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 || *runName == "" {
		return nil, errUsage
	}
	if *out != "" && !*dryRun {
		return nil, errors.New("--out is only used with --dry-run")
	}
	if *force && *dryRun {
		return nil, errors.New("--force is not used with --dry-run")
	}
	return func(ctx context.Context, svc *defectdojo.Service, _ io.Reader, stdout io.Writer) error {
		if *dryRun {
			dir := *out
			if dir == "" {
				dir = "defectdojo-" + *runName
			}
			res, err := svc.DryRun(ctx, *runName, dir)
			if err != nil {
				return runError(err, *runName)
			}
			fmt.Fprintf(stdout, "dry run of %s: %s (%d hosts, %d services) for POST %s, %s (%d findings) for POST %s, written to %s\n",
				res.Run, defectdojo.NmapFile, res.Hosts, res.Services, res.NmapPath, defectdojo.FindingsFile, res.Findings, res.FindingsPath, dir)
			return nil
		}
		export := svc.Export
		if *force {
			export = svc.ForceExport
		}
		res, err := export(ctx, cliActor, *runName)
		if errors.Is(err, defectdojo.ErrOlderRun) {
			return fmt.Errorf("%w (use --force to export it anyway)", err)
		}
		if err != nil {
			return runError(err, *runName)
		}
		for _, r := range res.Recreated {
			fmt.Fprintf(stdout, "defectdojo: %s\n", r)
		}
		fmt.Fprintf(stdout, "exported %s to defectdojo: %d hosts, %d services to test %d, %d findings to test %d\n",
			res.Run, res.Hosts, res.Services, res.NmapTestID, res.Findings, res.FindingsTestID)
		return nil
	}, nil
}

func withDefectDojo(ctx context.Context, cfg config.Config, deps scanDeps, stdin io.Reader, stdout io.Writer, action dojoAction) error {
	keys, err := store.NewKeyring(cfg.MasterKey, cfg.PreviousKeys...)
	if err != nil {
		return err
	}
	s, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer s.Close()
	doer := deps.dojo
	if doer == nil {
		doer = &http.Client{Timeout: dojoTimeout}
	}
	svc := &defectdojo.Service{Store: defectdojo.DBStore{DB: s, Keys: keys}, Inventory: inventory.New(s, keys), HTTP: doer}
	return action(ctx, svc, stdin, stdout)
}
