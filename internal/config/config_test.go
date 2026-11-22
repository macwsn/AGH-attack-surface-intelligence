package config

import (
	"bytes"
	"encoding/base64"
	"reflect"
	"strings"
	"testing"

	"asi/internal/inventory"
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

// REQ-INVENTORY-011
func TestLoadInterestWeights(t *testing.T) {
	base := map[string]string{"ASI_DATABASE_URL": validURL, "ASI_MASTER_KEY": validKey}
	cfg, err := Load(env(base))
	if err != nil || !reflect.DeepEqual(cfg.Interest, inventory.DefaultInterestWeights) {
		t.Fatalf("unset ASI_INTEREST_WEIGHTS = %v, %v; want defaults", cfg.Interest, err)
	}
	base["ASI_INTEREST_WEIGHTS"] = "admin-panel=45,new=0"
	cfg, err = Load(env(base))
	if err != nil || cfg.Interest["admin-panel"] != 45 || cfg.Interest["new"] != 0 || cfg.Interest["staging"] != inventory.DefaultInterestWeights["staging"] {
		t.Fatalf("ASI_INTEREST_WEIGHTS = %v, %v", cfg.Interest, err)
	}
	for spec, want := range map[string]string{
		"bogus=5":         `ASI_INTEREST_WEIGHTS is malformed: unknown key "bogus"`,
		"admin-panel=lot": `ASI_INTEREST_WEIGHTS is malformed: admin-panel: "lot" is not a number from 0 to 100`,
		"admin-panel":     `ASI_INTEREST_WEIGHTS is malformed: "admin-panel" is not key=points`,
	} {
		base["ASI_INTEREST_WEIGHTS"] = spec
		if _, err := Load(env(base)); err == nil || !strings.HasPrefix(err.Error(), want) || strings.Contains(err.Error(), "\n") {
			t.Errorf("ASI_INTEREST_WEIGHTS=%q error = %v, want prefix %q", spec, err, want)
		}
	}
}

func TestLoadSignaturesDir(t *testing.T) {
	cfg, err := Load(env(map[string]string{"ASI_DATABASE_URL": validURL, "ASI_MASTER_KEY": validKey, "ASI_SIGNATURES_DIR": " /etc/asi/signatures "}))
	if err != nil || cfg.SignaturesDir != "/etc/asi/signatures" {
		t.Fatalf("SignaturesDir = %q, err = %v", cfg.SignaturesDir, err)
	}
}

func TestLoadBodyRetention(t *testing.T) {
	base := map[string]string{"ASI_DATABASE_URL": validURL, "ASI_MASTER_KEY": validKey}
	cfg, err := Load(env(base))
	if err != nil || cfg.BodyRetention != inventory.DefaultBodyRetention || inventory.DefaultBodyRetention != 10 {
		t.Fatalf("unset ASI_BODY_RETENTION_RUNS = %d, %v; want 10", cfg.BodyRetention, err)
	}
	base["ASI_BODY_RETENTION_RUNS"] = " 3 "
	if cfg, err = Load(env(base)); err != nil || cfg.BodyRetention != 3 {
		t.Fatalf("ASI_BODY_RETENTION_RUNS=3 = %d, %v", cfg.BodyRetention, err)
	}
	for _, bad := range []string{"0", "-1", "ten"} {
		base["ASI_BODY_RETENTION_RUNS"] = bad
		if _, err := Load(env(base)); err == nil || !strings.HasPrefix(err.Error(), "ASI_BODY_RETENTION_RUNS is malformed") {
			t.Errorf("ASI_BODY_RETENTION_RUNS=%q error = %v", bad, err)
		}
	}
}

func TestLoadVolatileHeaders(t *testing.T) {
	cfg, err := Load(env(map[string]string{"ASI_DATABASE_URL": validURL, "ASI_MASTER_KEY": validKey, "ASI_VOLATILE_HEADERS": " X-Trace-Id, x-backend-node,,x-trace-id "}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if want := []string{"x-trace-id", "x-backend-node"}; !reflect.DeepEqual(cfg.VolatileHeaders, want) {
		t.Errorf("VolatileHeaders = %q, want %q", cfg.VolatileHeaders, want)
	}
}

// REQ-INVENTORY-021
func TestLoadPreviousKeys(t *testing.T) {
	other := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	base := map[string]string{"ASI_DATABASE_URL": validURL, "ASI_MASTER_KEY": validKey}
	cfg, err := Load(env(base))
	if err != nil || cfg.PreviousKeys != nil {
		t.Fatalf("unset ASI_MASTER_KEY_PREVIOUS = %v, %v; want none", cfg.PreviousKeys, err)
	}
	base["ASI_MASTER_KEY_PREVIOUS"] = " " + other + " , " + validKey + " "
	cfg, err = Load(env(base))
	if err != nil || len(cfg.PreviousKeys) != 2 || !bytes.Equal(cfg.PreviousKeys[0], bytes.Repeat([]byte{9}, 32)) || !bytes.Equal(cfg.PreviousKeys[1], bytes.Repeat([]byte{7}, 32)) {
		t.Fatalf("ASI_MASTER_KEY_PREVIOUS = %v, %v", cfg.PreviousKeys, err)
	}
	short := base64.StdEncoding.EncodeToString(make([]byte, 16))
	for spec, entry := range map[string]string{
		"not base64!!":        "entry 1",
		other + ",":           "entry 2",
		other + "," + short:   "entry 2",
		other + ",,," + other: "entry 2",
	} {
		base["ASI_MASTER_KEY_PREVIOUS"] = spec
		_, err := Load(env(base))
		if err == nil || !strings.HasPrefix(err.Error(), "ASI_MASTER_KEY_PREVIOUS is malformed: "+entry+" ") ||
			strings.Contains(err.Error(), "\n") || strings.Contains(err.Error(), other) {
			t.Errorf("ASI_MASTER_KEY_PREVIOUS=%q error = %v, want one line naming %s", spec, err, entry)
		}
	}
}
