package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	_ "time/tzdata"

	"asi/internal/auth"
	"asi/internal/config"
	"asi/internal/detect"
	"asi/internal/exchange/defectdojo"
	"asi/internal/inventory"
	"asi/internal/scan"
	"asi/internal/scan/nmap"
	"asi/internal/schedule"
	"asi/internal/store"
	"asi/internal/version"
	"asi/internal/web"
)

const usage = `usage: asi <command> [flags]

Commands:
  migrate    apply embedded schema migrations; idempotent
  serve      web UI + JSON API + scheduler + scan workers
  user       user create --username U --role R [--password-stdin]
             user list
             user set-role --username U --role R
             user delete --username U
  role       role list
  scan       scan run --targets-file F [--exclude-file F] --ports LIST --name NAME [--signatures-dir D] [--inactive-after N] [--max-rate PPS] [--workers N] [--http-timeout D] [--max-addresses N] [--max-work N] [--service-detection light|standard] [--no-adaptive] [--mode full|recheck] --wait
             scan plan (same flags as scan run; sends nothing)
             scan resume NAME
             scan show NAME
  export     export --format json|csv --out FILE [--run NAME]
  diff       diff --from NAME --to NAME --format json --out FILE
  import     import --format json|csv --file FILE [--name NAME] [--dry-run] [--signatures-dir D] [--inactive-after N]
  host       host edit ADDRESS [--add-tag T]... [--remove-tag T]... [--notes TEXT]
  inventory  inventory rebuild-summary
  signature  signature hunt --file SIG.yaml [--since DURATION] [--format text|json]
  defectdojo defectdojo configure --url URL --product ID --engagement ID [--token-stdin] [--force]
             defectdojo test
             defectdojo export --run NAME [--dry-run [--out DIR] | --force]
  key        key status
             key rotate [--batch N]
  version    print the version

Environment:
  ASI_DATABASE_URL   Postgres URL (postgres://user:password@host:port/db)
  ASI_MASTER_KEY     base64 of 32 bytes, field encryption key
  ASI_MASTER_KEY_PREVIOUS  comma-separated base64 keys that encrypted older data (read only; key rotate rewrites it)
  ASI_LISTEN         listen address for serve (default :8080)
  ASI_INTEREST_WEIGHTS  interest score weights, e.g. admin-panel=30,staging=20 (unset keys keep defaults)
  ASI_SIGNATURES_DIR signatures directory serve matches scans, imports and entries with (optional)
  ASI_TIMEZONE       IANA zone the UI shows times in, e.g. Europe/Warsaw (default: the process local zone)
  ASI_VOLATILE_HEADERS  response headers that never count as a change, comma-separated (optional)
`

var inventoryCommands = map[string]bool{"scan": true, "export": true, "diff": true, "import": true, "host": true, "inventory": true, "signature": true}

var errUsage = errors.New("usage")

var errPasswordStdin = errors.New("password must be given on stdin: use --password-stdin")

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr, os.Getenv)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, getenv func(string) string) int {
	return runWith(ctx, scanDeps{runner: nmap.ExecRunner{}}, args, stdin, stdout, stderr, getenv)
}

func runWith(ctx context.Context, deps scanDeps, args []string, stdin io.Reader, stdout, stderr io.Writer, getenv func(string) string) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usage)
		return 0
	case "version", "--version":
		fmt.Fprintln(stdout, version.String())
		return 0
	}
	if cmd != "migrate" && cmd != "serve" && cmd != "user" && cmd != "role" && cmd != "defectdojo" && cmd != "key" && !inventoryCommands[cmd] {
		fmt.Fprintf(stderr, "asi: unknown command %q\n\n%s", cmd, usage)
		return 2
	}
	if len(rest) > 0 && (rest[0] == "-h" || rest[0] == "--help") {
		fmt.Fprint(stdout, usage)
		return 0
	}

	err := dispatch(ctx, deps, cmd, rest, stdin, stdout, stderr, getenv)
	if errors.Is(err, errUsage) {
		fmt.Fprint(stderr, usage)
		return 2
	}
	if err != nil {
		fmt.Fprintf(stderr, "asi %s: %s\n", cmd, oneLine(err.Error()))
		return 1
	}
	return 0
}

func dispatch(ctx context.Context, deps scanDeps, cmd string, args []string, stdin io.Reader, stdout, stderr io.Writer, getenv func(string) string) error {
	var (
		ua     userAction
		action inventoryAction
		dojo   dojoAction
		key    keyAction
		err    error
	)
	switch {
	case cmd == "user":
		ua, err = parseUser(args)
	case cmd == "role":
		err = parseRole(args)
	case cmd == "defectdojo":
		dojo, err = parseDefectDojo(args)
	case cmd == "key":
		key, err = parseKey(args)
	case inventoryCommands[cmd]:
		action, err = parseInventoryCommand(cmd, args)
	}
	if err != nil {
		return err
	}
	cfg, err := config.Load(getenv)
	if err != nil {
		return err
	}
	if cfg.Location != nil {
		time.Local = cfg.Location
	}
	switch cmd {
	case "migrate":
		if len(args) > 0 {
			return errUsage
		}
		return migrate(ctx, cfg, stdout)
	case "serve":
		if len(args) > 0 {
			return errUsage
		}
		return serve(ctx, cfg, deps, stdout)
	case "user":
		return runUser(ctx, cfg, ua, stdin, stdout)
	case "role":
		return roleList(ctx, cfg, stdout)
	case "defectdojo":
		return withDefectDojo(ctx, cfg, deps, stdin, stdout, dojo)
	case "key":
		return withKeys(ctx, cfg, stdout, key)
	case "export", "diff":
		return withInventory(ctx, cfg, deps, stderr, action)
	default:
		return withInventory(ctx, cfg, deps, stdout, action)
	}
}

const encryptBatch = 500

func migrate(ctx context.Context, cfg config.Config, stdout io.Writer) error {
	keys, err := store.NewKeyring(cfg.MasterKey, cfg.PreviousKeys...)
	if err != nil {
		return err
	}
	s, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer s.Close()
	applied, err := s.Migrate(ctx)
	if err != nil {
		return err
	}
	if len(applied) == 0 {
		fmt.Fprintln(stdout, "migrations: up to date")
	} else {
		fmt.Fprintf(stdout, "migrations: applied %s\n", strings.Join(applied, ", "))
	}
	sealed, err := s.EncryptPending(ctx, keys, encryptBatch)
	if err != nil {
		return err
	}
	if sealed > 0 {
		fmt.Fprintf(stdout, "field encryption: encrypted %d stored values\n", sealed)
	}
	n, err := inventory.New(s, keys).BackfillSummary(ctx)
	if err != nil {
		return err
	}
	if n > 0 {
		fmt.Fprintf(stdout, "host summary: rebuilt %d hosts\n", n)
	}
	return nil
}

type userCreateArgs struct {
	username, role string
}

func parseUserCreate(args []string) (userCreateArgs, error) {
	if len(args) == 0 || args[0] != "create" {
		return userCreateArgs{}, errUsage
	}
	fs := flag.NewFlagSet("user create", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var a userCreateArgs
	fs.StringVar(&a.username, "username", "", "")
	fs.StringVar(&a.role, "role", "", "")
	passwordStdin := fs.Bool("password-stdin", false, "")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() > 0 || a.username == "" || a.role == "" {
		return userCreateArgs{}, errUsage
	}
	if !*passwordStdin {
		return userCreateArgs{}, errPasswordStdin
	}
	return a, nil
}

func userCreate(ctx context.Context, cfg config.Config, a userCreateArgs, stdin io.Reader, stdout io.Writer) error {
	password, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read password from stdin: %w", err)
	}
	password = strings.TrimSuffix(password, "\n")
	if strings.HasSuffix(password, "\r") && !errors.Is(err, io.EOF) {
		password = strings.TrimSuffix(password, "\r")
	}
	s, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer s.Close()
	svc := auth.NewService(s, auth.Config{})
	if err := svc.CreateUser(ctx, cliActor, a.username, password, a.role); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "user %s created with role %s\n", a.username, a.role)
	return nil
}

func serve(ctx context.Context, cfg config.Config, deps scanDeps, stdout io.Writer) error {
	keyring, err := store.NewKeyring(cfg.MasterKey, cfg.PreviousKeys...)
	if err != nil {
		return err
	}
	s, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer s.Close()
	if _, err := s.EncryptPending(ctx, keyring, encryptBatch); err != nil {
		fmt.Fprintf(stdout, "asi serve: %s\n", oneLine(err.Error()))
	}
	if err := s.CheckKeys(ctx, keyring); errors.Is(err, store.ErrKeyMismatch) {
		return err
	} else if err != nil {
		fmt.Fprintf(stdout, "asi serve: %s\n", oneLine(err.Error()))
	}
	if cfg.SignaturesDir != "" {
		if _, err := detect.LoadDir(cfg.SignaturesDir); err != nil {
			return fmt.Errorf("ASI_SIGNATURES_DIR: %w", err)
		}
	}

	inv := inventory.New(s, keyring)
	inv.Interest = cfg.Interest
	inv.BodyRetention = cfg.BodyRetention
	inv.VolatileHeaders = cfg.VolatileHeaders
	if n, err := inv.BackfillSummary(ctx); err != nil {
		fmt.Fprintf(stdout, "asi serve: %s\n", oneLine(err.Error()))
	} else if n > 0 {
		fmt.Fprintf(stdout, "asi serve: host summary rebuilt for %d hosts\n", n)
	}
	lib := detect.NewLibrary(s, keyring, cfg.SignaturesDir)
	sched := &schedule.Scheduler{
		Store:   schedule.NewStore(s, keyring),
		Scanner: &scan.Scanner{Store: inv, Runner: deps.runner, Transport: deps.transport, Signatures: lib},
	}
	dojo := &defectdojo.Service{Store: defectdojo.DBStore{DB: s, Keys: keyring}, Inventory: inv,
		HTTP: &http.Client{Timeout: dojoTimeout}}
	authSvc := auth.NewService(s, auth.Config{})
	handler, err := web.New(web.Deps{Store: s, Keyring: keyring, Auth: authSvc, Users: authSvc, Roles: authSvc, Audit: authSvc, Scans: sched,
		DefectDojo: dojo, SignaturesDir: cfg.SignaturesDir, Inventory: inv, Library: lib})
	if err != nil {
		return err
	}
	schedCtx, stopScheduler := context.WithCancel(ctx)
	defer sched.Wait()
	defer stopScheduler()
	sched.Start(schedCtx)
	go sched.Loop()

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.Listen, err)
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	fmt.Fprintf(stdout, "asi serve: listening on %s\n", ln.Addr())

	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		return fmt.Errorf("http server: %w", err)
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	return nil
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
