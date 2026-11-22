//go:build integration

package detect

import (
	"context"
	"errors"
	"strings"
	"testing"

	"asi/internal/store"
	"asi/internal/store/storetest"
)

func openPackLibrary(t *testing.T) (*store.Store, *Library) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, storetest.DatabaseURL(t))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(st.Close)
	if _, err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return st, NewLibrary(st, testKeys(t), "")
}

func enabledSet(t *testing.T, l *Library) map[string]bool {
	t.Helper()
	sigs, err := l.Enabled(context.Background())
	if err != nil {
		t.Fatalf("Enabled: %v", err)
	}
	out := map[string]bool{}
	for _, s := range sigs {
		if out[s.ID] {
			t.Fatalf("Enabled returned %s twice", s.ID)
		}
		out[s.ID] = true
	}
	return out
}

func TestPackEnabledByDefaultWithDatabaseSignatures(t *testing.T) {
	ctx := context.Background()
	_, lib := openPackLibrary(t)
	pack := mustPack(t)
	if len(pack) == 0 {
		t.Fatal("the built-in pack is empty")
	}
	a := Actor{Username: "eddie", Addr: "local"}

	on := enabledSet(t, lib)
	if len(on) != len(pack) {
		t.Fatalf("fresh database: Enabled returned %d signatures, want the %d pack signatures", len(on), len(pack))
	}
	for _, s := range pack {
		if !on[s.ID] {
			t.Fatalf("fresh database: pack signature %s is not enabled", s.ID)
		}
	}

	if _, err := lib.Create(ctx, a, "id: user-on\nname: U\nkind: custom\nconfidence: 1\nmatch: {all: [{type: status, value: 200}]}\n", true); err != nil {
		t.Fatalf("Create enabled: %v", err)
	}
	if _, err := lib.Create(ctx, a, "id: user-off\nname: U\nkind: custom\nconfidence: 1\nmatch: {all: [{type: status, value: 200}]}\n", false); err != nil {
		t.Fatalf("Create disabled: %v", err)
	}
	on = enabledSet(t, lib)
	if len(on) != len(pack)+1 || !on["user-on"] || on["user-off"] {
		t.Fatalf("Enabled = %d signatures (user-on %v, user-off %v), want pack + user-on", len(on), on["user-on"], on["user-off"])
	}

	list, err := lib.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("List = %d stored signatures, want 2 (no pack signatures)", len(list))
	}
	exp, err := lib.Export(ctx)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if strings.Contains(string(exp), PackIDPrefix) {
		t.Fatalf("export contains pack signatures:\n%s", exp)
	}
}

func TestPackIDsRejectedForDatabaseSignatures(t *testing.T) {
	ctx := context.Background()
	st, lib := openPackLibrary(t)
	id := mustPack(t)[0].ID
	a := Actor{Username: "eddie", Addr: "local"}
	src := "id: " + id + "\nname: Mine\nkind: custom\nconfidence: 1\nmatch: {all: [{type: status, value: 200}]}\n"

	wantRule := func(what string, err error, rule string) {
		t.Helper()
		var re *RuleError
		if !errors.As(err, &re) || re.Rule != rule {
			t.Fatalf("%s: err = %v, want rule %q", what, err, rule)
		}
	}
	_, err := lib.Create(ctx, a, src, true)
	wantRule("create", err, RuleDuplicateID)
	_, err = lib.Create(ctx, a, src, false)
	wantRule("create disabled", err, RuleDuplicateID)
	_, err = lib.Import(ctx, a, []byte("- "+strings.ReplaceAll(strings.TrimSuffix(src, "\n"), "\n", "\n  ")+"\n"))
	wantRule("import", err, RuleDuplicateID)
	_, err = lib.Update(ctx, a, id, src, true)
	wantRule("update", err, RuleDuplicateID)
	wantRule("delete", lib.Delete(ctx, a, id), RuleDuplicateID)

	var stored, audits int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM signatures`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE target = $1`, id).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if stored != 0 || audits != 0 {
		t.Fatalf("after rejected writes: %d stored signatures, %d audit rows, want none", stored, audits)
	}
}

func TestPackDisableEnablePersists(t *testing.T) {
	ctx := context.Background()
	st, lib := openPackLibrary(t)
	id := mustPack(t)[0].ID
	a := Actor{Username: "eddie", Addr: "10.0.0.9"}

	if err := lib.SetEnabled(ctx, a, id, false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if enabledSet(t, NewLibrary(st, testKeys(t), ""))[id] {
		t.Fatalf("%s still enabled after disable", id)
	}
	got, err := lib.Get(ctx, id)
	if err != nil || !got.Builtin || got.Enabled || got.UpdatedBy != "eddie" || !strings.Contains(got.Source, id) {
		t.Fatalf("Get after disable = %+v, %v", got, err)
	}
	if err := lib.SetEnabled(ctx, a, id, true); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if !enabledSet(t, lib)[id] {
		t.Fatalf("%s not enabled after enable", id)
	}
	rows, err := st.Pool.Query(ctx, `SELECT action || ' ' || target || ' ' || address FROM audit_log ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var audit []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		audit = append(audit, s)
	}
	want := AuditDisable + " " + id + " 10.0.0.9\n" + AuditEnable + " " + id + " 10.0.0.9"
	if strings.Join(audit, "\n") != want {
		t.Fatalf("audit = %q, want %q", audit, want)
	}
}

func TestPackDisabledSignatureDropsOutOfEnabledAndReturns(t *testing.T) {
	ctx := context.Background()
	_, lib := openPackLibrary(t)
	pack := mustPack(t)
	if len(pack) < 2 {
		t.Fatalf("pack has %d signatures, want at least 2", len(pack))
	}
	id := pack[len(pack)-1].ID
	a := Actor{Username: "eddie", Addr: "local"}

	before := enabledSet(t, lib)
	if !before[id] || len(before) != len(pack) {
		t.Fatalf("before: %s enabled %v, %d enabled, want all %d", id, before[id], len(before), len(pack))
	}
	if err := lib.SetEnabled(ctx, a, id, false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	off := enabledSet(t, lib)
	if off[id] || len(off) != len(pack)-1 {
		t.Fatalf("after disable: %s enabled %v, %d enabled, want %d without it", id, off[id], len(off), len(pack)-1)
	}
	for _, s := range pack {
		if s.ID != id && !off[s.ID] {
			t.Fatalf("disabling %s also dropped %s", id, s.ID)
		}
	}
	if err := lib.SetEnabled(ctx, a, id, true); err != nil {
		t.Fatalf("enable: %v", err)
	}
	on := enabledSet(t, lib)
	if !on[id] || len(on) != len(pack) {
		t.Fatalf("after enable: %s enabled %v, %d enabled, want all %d", id, on[id], len(on), len(pack))
	}
}

func testKeys(t *testing.T) *store.Keyring {
	t.Helper()
	k, err := store.NewKeyring(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return k
}
