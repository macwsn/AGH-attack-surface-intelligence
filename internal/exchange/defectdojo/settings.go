package defectdojo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"asi/internal/auth"
	"asi/internal/store"
)

const settingsKey = "defectdojo"

type Settings struct {
	BaseURL        string `json:"base_url"`
	Token          string `json:"token"`
	ProductID      int    `json:"product_id"`
	EngagementID   int    `json:"engagement_id"`
	NmapTestID     int    `json:"nmap_test_id"`
	FindingsTestID int    `json:"findings_test_id"`

	LastRun          string               `json:"last_run,omitempty"`
	LastRunStartedAt time.Time            `json:"last_run_started_at,omitzero"`
	Targets          *map[string]Exported `json:"targets,omitempty"`
}

type Exported struct {
	NmapTestID       int       `json:"nmap_test_id"`
	FindingsTestID   int       `json:"findings_test_id"`
	LastRun          string    `json:"last_run,omitempty"`
	LastRunStartedAt time.Time `json:"last_run_started_at,omitzero"`
}

func (s Settings) Configured() bool {
	return s.BaseURL != "" && s.Token != "" && s.ProductID > 0 && s.EngagementID > 0
}

func (s Settings) target() string {
	return s.BaseURL + " product " + strconv.Itoa(s.ProductID) + " engagement " + strconv.Itoa(s.EngagementID)
}

func (s Settings) exported() Exported {
	return Exported{NmapTestID: s.NmapTestID, FindingsTestID: s.FindingsTestID, LastRun: s.LastRun, LastRunStartedAt: s.LastRunStartedAt}
}

func (s *Settings) setExported(e Exported) {
	s.NmapTestID, s.FindingsTestID, s.LastRun, s.LastRunStartedAt = e.NmapTestID, e.FindingsTestID, e.LastRun, e.LastRunStartedAt
}

func (s *Settings) switchFrom(old Settings) {
	targets := map[string]Exported{}
	if old.Targets != nil {
		targets = maps.Clone(*old.Targets)
	}
	if old.BaseURL != "" {
		targets[old.target()] = old.exported()
	}
	s.setExported(targets[s.target()])
	delete(targets, s.target())
	if len(targets) > 0 {
		s.Targets = &targets
	}
}

type DBStore struct {
	DB   *store.Store
	Keys *store.Keyring
}

func (d DBStore) Load(ctx context.Context) (Settings, error) {
	var sealed []byte
	err := d.DB.Pool.QueryRow(ctx, `SELECT value FROM settings WHERE key = $1`, settingsKey).Scan(&sealed)
	if errors.Is(err, pgx.ErrNoRows) {
		return Settings{}, nil
	}
	if err != nil {
		return Settings{}, fmt.Errorf("load defectdojo settings: %w", err)
	}
	plain, err := d.Keys.Decrypt(sealed)
	if err != nil {
		return Settings{}, fmt.Errorf("load defectdojo settings: %w", err)
	}
	var s Settings
	if err := json.Unmarshal(plain, &s); err != nil {
		return Settings{}, fmt.Errorf("load defectdojo settings: %w", err)
	}
	return s, nil
}

func (d DBStore) Save(ctx context.Context, s Settings) error {
	plain, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("save defectdojo settings: %w", err)
	}
	sealed, err := d.Keys.Encrypt(plain)
	if err != nil {
		return fmt.Errorf("save defectdojo settings: %w", err)
	}
	if _, err := d.DB.Pool.Exec(ctx, `INSERT INTO settings (key, value) VALUES ($1, $2)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`, settingsKey, sealed); err != nil {
		return fmt.Errorf("save defectdojo settings: %w", err)
	}
	return nil
}

func (d DBStore) Audit(ctx context.Context, actor auth.Actor, action, target string) error {
	if _, err := d.DB.Pool.Exec(ctx, `INSERT INTO audit_log (actor, action, target, address) VALUES ($1, $2, $3, $4)`,
		actor.Username, action, target, actor.Addr); err != nil {
		return fmt.Errorf("write audit %s: %w", action, err)
	}
	return nil
}
