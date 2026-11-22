//go:build integration

package defectdojo

import (
	"bytes"
	"context"
	"testing"

	"asi/internal/auth"
	"asi/internal/store"
	"asi/internal/store/storetest"
)

// REQ-DEFECTDOJO-001
func TestDBStoreEncryptsSettings(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, storetest.DatabaseURL(t))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(st.Close)
	if _, err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	keys, err := store.NewKeyring(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	db := DBStore{DB: st, Keys: keys}
	empty, err := db.Load(ctx)
	if err != nil || empty != (Settings{}) {
		t.Fatalf("Load before save = %+v, %v", empty, err)
	}
	want := Settings{BaseURL: "https://dojo.example", Token: testToken, ProductID: 2, EngagementID: 3, NmapTestID: 41}
	if err := db.Save(ctx, want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	want.FindingsTestID = 42
	if err := db.Save(ctx, want); err != nil {
		t.Fatalf("Save again: %v", err)
	}
	got, err := db.Load(ctx)
	if err != nil || got != want {
		t.Fatalf("Load = %+v, %v; want %+v", got, err, want)
	}
	var raw []byte
	if err := st.Pool.QueryRow(ctx, `SELECT value FROM settings WHERE key = 'defectdojo'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(testToken)) || bytes.Contains(raw, []byte("dojo.example")) {
		t.Fatal("settings are stored in plain text")
	}
	if err := db.Audit(ctx, auth.Actor{Username: "olga", Addr: "10.0.0.1"}, auditExport, "r2"); err != nil {
		t.Fatalf("Audit: %v", err)
	}
	var actor, target string
	if err := st.Pool.QueryRow(ctx, `SELECT actor, target FROM audit_log WHERE action = 'defectdojo.export'`).Scan(&actor, &target); err != nil || actor != "olga" || target != "r2" {
		t.Fatalf("audit row = %q %q %v", actor, target, err)
	}
}
