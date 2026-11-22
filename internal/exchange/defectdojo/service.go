package defectdojo

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"asi/internal/auth"
	"asi/internal/inventory"
)

const (
	NmapFile     = "nmap.xml"
	FindingsFile = "findings.json"

	auditConfigure = "defectdojo.configure"
	auditExport    = "defectdojo.export"
)

var (
	ErrNotConfigured = errors.New("defectdojo is not configured: set the base URL, API token, product and engagement first")
	ErrInvalidConfig = errors.New("invalid defectdojo configuration")
	ErrNotSaved      = errors.New("not saved: the connection test failed")
	ErrOlderRun      = errors.New("run is older than the last exported run")
	ErrTestsMissing  = errors.New("stored defectdojo tests no longer exist")
)

type SettingsStore interface {
	Load(ctx context.Context) (Settings, error)
	Save(ctx context.Context, s Settings) error
	Audit(ctx context.Context, actor auth.Actor, action, target string) error
}

type Exporter interface {
	Export(ctx context.Context, asOfRun string) (inventory.Export, error)
}

type Service struct {
	Store     SettingsStore
	Inventory Exporter
	HTTP      Doer
}

type Config struct {
	BaseURL      string
	Token        string
	ProductID    int
	EngagementID int
	Force        bool
}

type View struct {
	BaseURL        string
	TokenSet       bool
	ProductID      int
	EngagementID   int
	NmapTestID     int
	FindingsTestID int
}

type Result struct {
	Run            string
	Hosts          int
	Services       int
	Findings       int
	NmapPath       string
	FindingsPath   string
	NmapTestID     int
	FindingsTestID int
	Recreated      []string
}

type payloads struct {
	Result
	nmap, findings []byte
	startedAt      time.Time
}

func (s *Service) View(ctx context.Context) (View, error) {
	st, err := s.Store.Load(ctx)
	if err != nil {
		return View{}, err
	}
	return View{BaseURL: st.BaseURL, TokenSet: st.Token != "", ProductID: st.ProductID, EngagementID: st.EngagementID,
		NmapTestID: st.NmapTestID, FindingsTestID: st.FindingsTestID}, nil
}

func (s *Service) Configure(ctx context.Context, actor auth.Actor, c Config) error {
	base, err := NormalizeBaseURL(c.BaseURL)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	if c.ProductID < 1 || c.EngagementID < 1 {
		return fmt.Errorf("%w: product and engagement ids must be positive numbers", ErrInvalidConfig)
	}
	old, err := s.Store.Load(ctx)
	if err != nil {
		return err
	}
	next := Settings{BaseURL: base, Token: strings.TrimSpace(c.Token), ProductID: c.ProductID, EngagementID: c.EngagementID}
	if next.Token == "" && old.BaseURL == next.BaseURL {
		next.Token = old.Token
	}
	if next.Token == "" && old.Token != "" {
		return fmt.Errorf("%w: the API token is required when the base URL changes", ErrInvalidConfig)
	}
	if next.Token == "" {
		return fmt.Errorf("%w: the API token is required", ErrInvalidConfig)
	}
	if !c.Force && (old.target() != next.target() || old.Token != next.Token) {
		client := &Client{BaseURL: next.BaseURL, Token: next.Token, HTTP: s.HTTP}
		if err := client.CheckEngagement(ctx, next.ProductID, next.EngagementID); err != nil {
			return fmt.Errorf("%w: %w", ErrNotSaved, err)
		}
	}
	next.switchFrom(old)
	if err := s.Store.Save(ctx, next); err != nil {
		return err
	}
	return s.Store.Audit(ctx, actor, auditConfigure, base)
}

func (s *Service) configured(ctx context.Context) (Settings, *Client, error) {
	st, err := s.Store.Load(ctx)
	if err != nil {
		return Settings{}, nil, err
	}
	if !st.Configured() {
		return Settings{}, nil, ErrNotConfigured
	}
	return st, &Client{BaseURL: st.BaseURL, Token: st.Token, HTTP: s.HTTP}, nil
}

func (s *Service) TestConnection(ctx context.Context) error {
	st, c, err := s.configured(ctx)
	if err != nil {
		return err
	}
	return c.CheckEngagement(ctx, st.ProductID, st.EngagementID)
}

type Choices struct {
	Products    []Choice
	Engagements []Choice
}

func (s *Service) Choices(ctx context.Context, productID int) (Choices, error) {
	st, err := s.Store.Load(ctx)
	if err != nil {
		return Choices{}, err
	}
	if st.BaseURL == "" || st.Token == "" {
		return Choices{}, ErrNotConfigured
	}
	c := &Client{BaseURL: st.BaseURL, Token: st.Token, HTTP: s.HTTP}
	var ch Choices
	if ch.Products, err = c.Products(ctx); err != nil {
		return Choices{}, err
	}
	if productID < 1 {
		productID = st.ProductID
	}
	if productID > 0 {
		if ch.Engagements, err = c.Engagements(ctx, productID); err != nil {
			return Choices{}, err
		}
	}
	return ch, nil
}

func (s *Service) CheckStoredTests(ctx context.Context) error {
	st, c, err := s.configured(ctx)
	if err != nil {
		return err
	}
	var missing []string
	for _, t := range []struct {
		name string
		id   int
	}{{"nmap", st.NmapTestID}, {"findings", st.FindingsTestID}} {
		if t.id == 0 {
			continue
		}
		ok, err := c.TestExists(ctx, t.id)
		if err != nil {
			return err
		}
		if !ok {
			missing = append(missing, fmt.Sprintf("the stored %s test %d", t.name, t.id))
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: the connection works, but %s no longer exist in DefectDojo; the next export recreates them",
			ErrTestsMissing, strings.Join(missing, " and "))
	}
	return nil
}

func (s *Service) build(ctx context.Context, run string, st Settings) (payloads, error) {
	exp, err := s.Inventory.Export(ctx, run)
	if err != nil {
		return payloads{}, err
	}
	exp.GeneratedAt = exp.RunStartedAt
	exp.Hosts = coveredBy(exp)
	var p payloads
	if p.nmap, p.Services, err = NmapXML(exp); err != nil {
		return payloads{}, err
	}
	if p.findings, p.Findings, err = GenericFindings(exp); err != nil {
		return payloads{}, err
	}
	p.Run, p.startedAt = exp.Run, exp.RunStartedAt
	for _, h := range exp.Hosts {
		if h.Status == inventory.StatusActive {
			p.Hosts++
		}
	}
	p.NmapTestID, p.FindingsTestID = st.NmapTestID, st.FindingsTestID
	p.NmapPath, p.FindingsPath = endpoint(st.NmapTestID), endpoint(st.FindingsTestID)
	return p, nil
}

func coveredBy(exp inventory.Export) []inventory.ExportHost {
	var hosts []inventory.ExportHost
	for _, h := range exp.Hosts {
		if h.NotInRun {
			continue
		}
		var services []inventory.ExportService
		for _, sv := range h.Services {
			if !sv.NotInRun {
				services = append(services, sv)
			}
		}
		h.Services = services
		hosts = append(hosts, h)
	}
	return hosts
}

func endpoint(testID int) string {
	if testID == 0 {
		return ImportPath
	}
	return ReimportPath
}

func (s *Service) Export(ctx context.Context, actor auth.Actor, run string) (Result, error) {
	return s.export(ctx, actor, run, false)
}

func (s *Service) ForceExport(ctx context.Context, actor auth.Actor, run string) (Result, error) {
	return s.export(ctx, actor, run, true)
}

func (s *Service) export(ctx context.Context, actor auth.Actor, run string, force bool) (Result, error) {
	st, c, err := s.configured(ctx)
	if err != nil {
		return Result{}, err
	}
	p, err := s.build(ctx, run, st)
	if err != nil {
		return Result{}, err
	}
	if !force && st.LastRun != "" && st.LastRun != p.Run && p.startedAt.Before(st.LastRunStartedAt) {
		return Result{}, fmt.Errorf("%w: run %s is older than run %s, the last one exported to this engagement; exporting it would reopen in DefectDojo what was closed since",
			ErrOlderRun, p.Run, st.LastRun)
	}
	var recreated bool
	if st.NmapTestID, recreated, err = send(ctx, c, st.EngagementID, st.NmapTestID, Upload{ScanType: ScanTypeNmap, FileName: NmapFile, File: p.nmap}); err != nil {
		return Result{}, err
	}
	if recreated {
		p.Recreated = append(p.Recreated, fmt.Sprintf("the nmap test %d no longer existed in DefectDojo and was recreated as test %d", p.NmapTestID, st.NmapTestID))
	}
	if err := s.keepTestIDs(ctx, st); err != nil {
		return Result{}, err
	}
	if st.FindingsTestID, recreated, err = send(ctx, c, st.EngagementID, st.FindingsTestID, Upload{ScanType: ScanTypeGeneric, FileName: FindingsFile, File: p.findings}); err != nil {
		return Result{}, err
	}
	if recreated {
		p.Recreated = append(p.Recreated, fmt.Sprintf("the findings test %d no longer existed in DefectDojo and was recreated as test %d", p.FindingsTestID, st.FindingsTestID))
	}
	st.LastRun, st.LastRunStartedAt = p.Run, p.startedAt
	if err := s.keepTestIDs(ctx, st); err != nil {
		return Result{}, err
	}
	p.NmapTestID, p.FindingsTestID = st.NmapTestID, st.FindingsTestID
	if err := s.Store.Audit(ctx, actor, auditExport, p.Run); err != nil {
		return Result{}, err
	}
	return p.Result, nil
}

func (s *Service) keepTestIDs(ctx context.Context, used Settings) error {
	cur, err := s.Store.Load(ctx)
	if err != nil {
		return err
	}
	if cur.target() != used.target() {
		return nil
	}
	cur.setExported(used.exported())
	return s.Store.Save(ctx, cur)
}

func send(ctx context.Context, c *Client, engagementID, testID int, up Upload) (int, bool, error) {
	if testID != 0 {
		id, err := c.Reimport(ctx, testID, up)
		var apiErr *APIError
		if !errors.As(err, &apiErr) || !apiErr.testMissing() {
			return id, false, err
		}
	}
	id, err := c.Import(ctx, engagementID, up)
	return id, testID != 0, err
}

func (s *Service) Preview(ctx context.Context, run string) (Result, error) {
	p, err := s.preview(ctx, run)
	return p.Result, err
}

func (s *Service) preview(ctx context.Context, run string) (payloads, error) {
	st, err := s.Store.Load(ctx)
	if err != nil {
		return payloads{}, err
	}
	return s.build(ctx, run, st)
}

func (s *Service) DryRun(ctx context.Context, run, dir string) (Result, error) {
	p, err := s.preview(ctx, run)
	if err != nil {
		return Result{}, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Result{}, fmt.Errorf("dry run: %w", err)
	}
	for name, body := range map[string][]byte{NmapFile: p.nmap, FindingsFile: p.findings} {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			return Result{}, fmt.Errorf("dry run: %w", err)
		}
	}
	return p.Result, nil
}
