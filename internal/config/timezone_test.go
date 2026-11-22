package config

import (
	"strings"
	"testing"
)

// REQ-WEB-009: AC4 of T-803xb7cwjk
func TestLoadTimezone(t *testing.T) {
	cfg, err := Load(env(map[string]string{"ASI_DATABASE_URL": validURL, "ASI_MASTER_KEY": validKey}))
	if err != nil || cfg.Location != nil {
		t.Fatalf("no ASI_TIMEZONE: Location = %v, err = %v, want nil (process local zone)", cfg.Location, err)
	}
	cfg, err = Load(env(map[string]string{"ASI_DATABASE_URL": validURL, "ASI_MASTER_KEY": validKey, "ASI_TIMEZONE": "Europe/Warsaw"}))
	if err != nil || cfg.Location == nil || cfg.Location.String() != "Europe/Warsaw" {
		t.Fatalf("Location = %v, err = %v, want Europe/Warsaw", cfg.Location, err)
	}
	_, err = Load(env(map[string]string{"ASI_DATABASE_URL": validURL, "ASI_MASTER_KEY": validKey, "ASI_TIMEZONE": "Mars/Olympus"}))
	if err == nil || !strings.HasPrefix(err.Error(), "ASI_TIMEZONE is malformed") {
		t.Fatalf("invalid zone: err = %v, want ASI_TIMEZONE is malformed", err)
	}
}
