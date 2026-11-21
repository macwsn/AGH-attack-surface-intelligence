package config

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

const validURL = "postgres://asi:secret@127.0.0.1:5432/asi?sslmode=disable"

var validKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadValid(t *testing.T) {
	cfg, err := Load(env(map[string]string{"ASI_DATABASE_URL": validURL, "ASI_MASTER_KEY": validKey}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DatabaseURL != validURL || len(cfg.MasterKey) != 32 || cfg.Listen != DefaultListen {
		t.Fatalf("unexpected config: %+v", cfg)
	}

	cfg, err = Load(env(map[string]string{"ASI_DATABASE_URL": validURL, "ASI_MASTER_KEY": validKey, "ASI_LISTEN": "127.0.0.1:9000"}))
	if err != nil || cfg.Listen != "127.0.0.1:9000" {
		t.Fatalf("Listen = %q, err = %v", cfg.Listen, err)
	}
}

func TestLoadErrors(t *testing.T) {
	short := base64.StdEncoding.EncodeToString(make([]byte, 16))
	cases := []struct {
		name, dbURL, key, wantPrefix string
	}{
		{"missing url", "", validKey, "ASI_DATABASE_URL is not set"},
		{"url not postgres", "mysql://x@y/z", validKey, "ASI_DATABASE_URL is malformed"},
		{"url unparsable", "postgres://asi:pw@host:notaport/db", validKey, "ASI_DATABASE_URL is malformed"},
		{"missing key", validURL, "", "ASI_MASTER_KEY is not set"},
		{"key not base64", validURL, "not base64!!", "ASI_MASTER_KEY is malformed"},
		{"key too short", validURL, short, "ASI_MASTER_KEY is malformed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(env(map[string]string{"ASI_DATABASE_URL": tc.dbURL, "ASI_MASTER_KEY": tc.key}))
			if err == nil {
				t.Fatal("Load succeeded, want error")
			}
			msg := err.Error()
			if !strings.HasPrefix(msg, tc.wantPrefix) {
				t.Fatalf("error = %q, want prefix %q", msg, tc.wantPrefix)
			}
			if strings.Contains(msg, "\n") || strings.Contains(msg, "pw") {
				t.Fatalf("error must be one line without secrets: %q", msg)
			}
		})
	}
}

func TestLoadSignaturesDir(t *testing.T) {
	cfg, err := Load(env(map[string]string{"ASI_DATABASE_URL": validURL, "ASI_MASTER_KEY": validKey, "ASI_SIGNATURES_DIR": " /etc/asi/signatures "}))
	if err != nil || cfg.SignaturesDir != "/etc/asi/signatures" {
		t.Fatalf("SignaturesDir = %q, err = %v", cfg.SignaturesDir, err)
	}
}
