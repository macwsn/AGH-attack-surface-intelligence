//go:build integration

package detect_test

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"asi/internal/detect"
	"asi/internal/store"
	"asi/internal/store/storetest"
)

func setIDs(t *testing.T, lib *detect.Library) []string {
	t.Helper()
	set, err := lib.Set(context.Background())
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	pack, err := detect.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	var ids []string
	for _, s := range set.Signatures {
		if !slices.ContainsFunc(pack, func(p detect.Signature) bool { return p.ID == s.ID }) {
			ids = append(ids, s.ID)
		}
	}
	return ids
}

// R11 AC2: the Library loads the directory and enabled database signatures once, hands the same set to every caller,
// and loads it again only after a change made through it.
func TestLibrarySetLoadedOnceAndRefreshedOnChange(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, storetest.DatabaseURL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if _, err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "s.yaml")
	if err := os.WriteFile(file, []byte("- id: dir-a\n  name: A\n  kind: custom\n  confidence: 50\n  match: { all: [ { type: title_regex, value: 'A' } ] }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	lib := detect.NewLibrary(st, mustKeys(t), dir)
	actor := detect.Actor{Username: "test", Addr: "local"}
	if _, err := lib.Create(ctx, actor, "id: db-b\nname: B\nkind: custom\nconfidence: 50\nmatch: { all: [ { type: title_regex, value: 'B' } ] }\n", true); err != nil {
		t.Fatal(err)
	}
	if got := setIDs(t, lib); !slices.Equal(got, []string{"dir-a", "db-b"}) {
		t.Fatalf("Set = %v, want dir-a and db-b", got)
	}
	first, _ := lib.Set(ctx)
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE signatures SET enabled = false`); err != nil {
		t.Fatal(err)
	}
	if again, _ := lib.Set(ctx); again != first {
		t.Fatal("Set loaded the signatures again instead of sharing the loaded set")
	}
	if err := lib.SetEnabled(ctx, actor, "db-b", true); err != nil {
		t.Fatal(err)
	}
	if got := setIDs(t, lib); !slices.Equal(got, []string{"db-b"}) {
		t.Fatalf("Set after a change = %v, want the reloaded set [db-b]", got)
	}
}

func mustKeys(t *testing.T) *store.Keyring {
	t.Helper()
	k, err := store.NewKeyring(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// AC1: a stored signature source is encrypted at rest and read back in plain text.
func TestStoredSignatureSourceEncrypted(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, storetest.DatabaseURL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if _, err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	lib := detect.NewLibrary(st, mustKeys(t), "")
	src := "id: db-secret\nname: Secret\nkind: custom\nconfidence: 50\nmatch: { all: [ { type: title_regex, value: 'MARKER-SRC-1' } ] }\n"
	if _, err := lib.Create(ctx, detect.Actor{Username: "test", Addr: "local"}, src, true); err != nil {
		t.Fatal(err)
	}
	var raw string
	if err := st.Pool.QueryRow(ctx, `SELECT t::text FROM signatures t`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, "MARKER-SRC-1") || strings.Contains(raw, hex.EncodeToString([]byte("MARKER-SRC-1"))) {
		t.Fatalf("signatures row holds the source in plain text: %s", raw)
	}
	if got, err := lib.Get(ctx, "db-secret"); err != nil || got.Source != src {
		t.Fatalf("Get = %+v, %v", got, err)
	}
	if on, err := lib.Enabled(ctx); err != nil || !slices.ContainsFunc(on, func(s detect.Signature) bool { return s.ID == "db-secret" }) {
		t.Fatalf("Enabled = %v, %v; want db-secret", len(on), err)
	}
}
