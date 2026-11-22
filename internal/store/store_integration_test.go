//go:build integration

package store

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"asi/internal/store/storetest"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), storetest.DatabaseURL(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

func TestMigrateIdempotent(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)

	all, err := Migrations()
	if err != nil || len(all) == 0 {
		t.Fatalf("Migrations() = %v, %v", all, err)
	}
	first, err := s.Migrate(ctx)
	if err != nil {
		t.Fatalf("first Migrate: %v", err)
	}
	if len(first) != len(all) {
		t.Fatalf("first Migrate applied %v, want all %d", first, len(all))
	}
	second, err := s.Migrate(ctx)
	if err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	if len(second) != 0 {
		t.Fatalf("second Migrate applied %v, want none", second)
	}

	var n int
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatalf("count schema_migrations: %v", err)
	}
	if n != len(all) {
		t.Fatalf("schema_migrations has %d rows, want %d", n, len(all))
	}
	var schema string
	if err := s.Pool.QueryRow(ctx, `SELECT table_schema FROM information_schema.tables WHERE table_name = 'settings' AND table_schema = current_schema()`).Scan(&schema); err != nil {
		t.Fatalf("settings table not in the test schema: %v", err)
	}
}

func TestMigrateFailureRollsBack(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	bad := []Migration{
		{Version: "0001_ok", SQL: `CREATE TABLE ok_table (id int)`},
		{Version: "0002_bad", SQL: `CREATE TABLE broken (`},
	}
	if _, err := s.migrate(ctx, bad); err == nil {
		t.Fatal("migrate with a broken migration succeeded")
	}
	var exists bool
	if err := s.Pool.QueryRow(ctx, `SELECT to_regclass('ok_table') IS NOT NULL`).Scan(&exists); err != nil {
		t.Fatalf("check ok_table: %v", err)
	}
	if exists {
		t.Fatal("ok_table survived a failed migration run")
	}
}

func TestTx(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	if err := s.Tx(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO settings (key, value) VALUES ('committed', '\x01')`)
		return err
	}); err != nil {
		t.Fatalf("Tx commit: %v", err)
	}

	boom := errors.New("boom")
	err := s.Tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO settings (key, value) VALUES ('rolled-back', '\x01')`); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("Tx error = %v, want boom", err)
	}

	rows, err := s.Pool.Query(ctx, `SELECT key FROM settings ORDER BY key`)
	if err != nil {
		t.Fatalf("query settings: %v", err)
	}
	keys, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatalf("collect settings: %v", err)
	}
	if len(keys) != 1 || keys[0] != "committed" {
		t.Fatalf("settings keys = %v, want [committed]", keys)
	}
}

func TestEncryptedValueStoredAndRead(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	k := mustKeyring(t, key(3))
	ct, err := k.Encrypt([]byte("defectdojo-token"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := s.Pool.Exec(ctx, `INSERT INTO settings (key, value) VALUES ('dojo', $1)`, ct); err != nil {
		t.Fatalf("insert: %v", err)
	}
	var stored []byte
	if err := s.Pool.QueryRow(ctx, `SELECT value FROM settings WHERE key = 'dojo'`).Scan(&stored); err != nil {
		t.Fatalf("select: %v", err)
	}
	plain, err := k.Decrypt(stored)
	if err != nil || string(plain) != "defectdojo-token" {
		t.Fatalf("Decrypt stored value = %q, %v", plain, err)
	}
}

// REQ-INVENTORY-022 REQ-INVENTORY-023
func TestRotateKeysResumable(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	oldKey, newKey := make([]byte, 32), make([]byte, 32)
	newKey[0] = 1
	old, err := NewKeyring(oldKey)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 5 {
		notes, err := old.Encrypt([]byte{byte('a' + i)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Pool.Exec(ctx, `INSERT INTO hosts (address, notes) VALUES ($1, $2)`, "192.0.2."+string(rune('1'+i)), notes); err != nil {
			t.Fatal(err)
		}
	}
	only, _ := NewKeyring(newKey)
	if err := s.CheckKeys(ctx, only); !errors.Is(err, ErrKeyMismatch) || !strings.Contains(err.Error(), "hosts.notes") {
		t.Fatalf("CheckKeys without the old key = %v, want ErrKeyMismatch naming hosts.notes", err)
	}
	if _, err := s.RotateKeys(ctx, only, 2, nil); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("RotateKeys without the old key = %v, want ErrKeyMismatch", err)
	}
	both, _ := NewKeyring(newKey, oldKey)
	stop, cancel := context.WithCancel(ctx)
	if _, err := s.RotateKeys(stop, both, 2, func(string, int) { cancel() }); !errors.Is(err, context.Canceled) {
		t.Fatalf("interrupted RotateKeys = %v, want context.Canceled", err)
	}
	status, err := s.KeyStatus(ctx, both)
	if err != nil || status[1].Table != "hosts" || status[1].Current != 2 || len(status[1].Old) != 1 {
		t.Fatalf("status after one batch = %+v, %v", status, err)
	}
	res, err := s.RotateKeys(ctx, both, 2, nil)
	if err != nil || res[1].Table != "hosts" || res[1].Rewritten != 3 {
		t.Fatalf("resumed RotateKeys = %+v, %v; want 3 hosts rewritten", res, err)
	}
	if res, err = s.RotateKeys(ctx, both, 2, nil); err != nil || res[1].Rewritten != 0 {
		t.Fatalf("repeated RotateKeys = %+v, %v; want nothing rewritten", res, err)
	}
	if err := s.CheckKeys(ctx, only); err != nil {
		t.Fatalf("CheckKeys after rotate: %v", err)
	}
	rows, err := s.Pool.Query(ctx, `SELECT notes FROM hosts ORDER BY address`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got string
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			t.Fatal(err)
		}
		plain, err := only.Decrypt(b)
		if err != nil {
			t.Fatalf("decrypt with only the new key: %v", err)
		}
		got += string(plain)
	}
	if got != "abcde" {
		t.Fatalf("notes after rotate = %q, want abcde", got)
	}
}

func TestEveryEncryptedColumnIsRotated(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	notEncrypted := map[string]bool{"sessions.token_hash": true, "sessions.csrf_hash": true}
	rotated := map[string]bool{}
	for _, tb := range encryptedTables {
		for _, c := range tb.columns {
			rotated[tb.name+"."+c] = true
		}
	}
	rows, err := s.Pool.Query(ctx, `SELECT table_name || '.' || column_name FROM information_schema.columns
		WHERE table_schema = current_schema() AND data_type = 'bytea'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var col string
		if err := rows.Scan(&col); err != nil {
			t.Fatal(err)
		}
		if !rotated[col] && !notEncrypted[col] {
			t.Errorf("bytea column %s is not in encryptedTables (internal/store/rotate.go): add it so asi key rotate/status and the startup key check cover it, or list it as not encrypted here", col)
		}
		delete(rotated, col)
	}
	for col := range rotated {
		t.Errorf("encryptedTables lists %s, which is not a bytea column of the migrated schema", col)
	}
}

func TestEveryEncryptedColumnTracksItsKeys(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	rows, err := s.Pool.Query(ctx, `SELECT c.relname, t.tgname, t.tgargs FROM pg_trigger t
		JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_proc p ON p.oid = t.tgfoid
		WHERE c.relnamespace = current_schema()::regnamespace AND p.proname = 'track_encryption_keys'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	tracked := map[string]int{}
	for rows.Next() {
		var table, name string
		var args []byte
		if err := rows.Scan(&table, &name, &args); err != nil {
			t.Fatal(err)
		}
		for _, c := range strings.Split(strings.TrimSuffix(string(args), "\x00"), "\x00") {
			tracked[table+"."+c]++
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, tb := range encryptedTables {
		for _, c := range tb.columns {
			col := tb.name + "." + c
			if tracked[col] != 2 {
				t.Errorf("%s has %d track_encryption_keys triggers, want an insert and an update trigger so the startup key check sees its key ids", col, tracked[col])
			}
			delete(tracked, col)
		}
	}
	for col := range tracked {
		t.Errorf("track_encryption_keys tracks %s, which is not in encryptedTables (internal/store/rotate.go)", col)
	}
}

// REQ-INVENTORY-023
func TestKeysInUseFollowWritesAndRotation(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	oldKey, newKey := make([]byte, 32), make([]byte, 32)
	newKey[0] = 1
	both, _ := NewKeyring(newKey, oldKey)
	old, _ := NewKeyring(oldKey)
	only, _ := NewKeyring(newKey)
	notes, err := old.Encrypt([]byte("n"))
	if err != nil {
		t.Fatal(err)
	}
	headers := func() []string {
		rows, err := s.Pool.Query(ctx, `SELECT table_name || '.' || column_name || ':' || key_header
			FROM encryption_keys_in_use ORDER BY 1`)
		if err != nil {
			t.Fatal(err)
		}
		got, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	oldID, newID := old.KeyID(), only.KeyID()
	oldEntry := "hosts.notes:01" + hex.EncodeToString(oldID[:])
	newEntry := "hosts.notes:01" + hex.EncodeToString(newID[:])

	if _, err := s.Pool.Exec(ctx, `INSERT INTO hosts (address) VALUES ('192.0.2.1'), ('192.0.2.2')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `UPDATE hosts SET notes = $1 WHERE address = '192.0.2.1'`, notes); err != nil {
		t.Fatal(err)
	}
	if got := headers(); len(got) != 1 || got[0] != oldEntry {
		t.Fatalf("keys in use after an update = %v, want [%s]", got, oldEntry)
	}
	if err := s.CheckKeys(ctx, only); !errors.Is(err, ErrKeyMismatch) || !strings.Contains(err.Error(), "hosts.notes") {
		t.Fatalf("CheckKeys without the old key = %v, want ErrKeyMismatch naming hosts.notes", err)
	}
	if _, err := s.RotateKeys(ctx, both, 10, nil); err != nil {
		t.Fatal(err)
	}
	if got := headers(); len(got) != 1 || got[0] != newEntry {
		t.Fatalf("keys in use after rotate = %v, want [%s]", got, newEntry)
	}

	if _, err := s.Pool.Exec(ctx, `UPDATE hosts SET notes = $1 WHERE address = '192.0.2.2'`, notes); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `DELETE FROM hosts WHERE address = '192.0.2.2'`); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckKeys(ctx, only); err != nil {
		t.Fatalf("CheckKeys after the only old-key row was deleted: %v", err)
	}
	if got := headers(); len(got) != 1 || got[0] != newEntry {
		t.Fatalf("keys in use after the check forgot the unused key = %v, want [%s]", got, newEntry)
	}
}

// REQ-INVENTORY-035 AC1: migration 0020 marks the plain owner, display name, scan targets and excludes and signature sources of an
// existing database, EncryptPending encrypts them, and the session CSRF token is no longer stored in plain text.
func TestMigrationEncryptsExistingSensitiveRows(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	all, err := Migrations()
	if err != nil {
		t.Fatal(err)
	}
	var before []Migration
	for _, m := range all {
		if m.Version < "0019" {
			before = append(before, m)
		}
	}
	if _, err := s.migrate(ctx, before); err != nil {
		t.Fatal(err)
	}
	secrets := []string{"Plain Owner Team", "Plain Display Name", "198.51.100.0/24", "198.51.100.7", "Plain Signature Title", "plain-csrf-secret"}
	for _, q := range []string{
		`INSERT INTO hosts (address, owner, display_name) VALUES ('192.0.2.1', 'Plain Owner Team', 'Plain Display Name'), ('192.0.2.2', '', '')`,
		`INSERT INTO scan_definitions (name, inactive_after, settings, schedule)
			VALUES ('campus', 3, '{"targets": ["198.51.100.0/24"], "excludes": ["198.51.100.7"], "ports": [80], "max_rate": 10, "workers": 1}', '{}')`,
		`INSERT INTO runs (name, inactive_after, settings, definition_id)
			VALUES ('r1', 3, '{"targets": ["198.51.100.0/24"], "excludes": ["198.51.100.7"], "ports": [80]}', (SELECT id FROM scan_definitions))`,
		`INSERT INTO signatures (id, name, kind, source) VALUES ('plain-sig', 'Plain', 'custom', E'id: plain-sig\nname: Plain Signature Title\n')`,
		`INSERT INTO hunts (signature_id, source, actor) VALUES ('plain-sig', E'id: plain-sig\nname: Plain Signature Title\n', 'alice')`,
		`INSERT INTO users (username, password_hash, role) VALUES ('alice', 'x', 'admin')`,
		`INSERT INTO sessions (token_hash, user_id, csrf_token, created_at, last_used_at)
			SELECT '\x01', id, 'plain-csrf-secret', now(), now() FROM users`,
	} {
		if _, err := s.Pool.Exec(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	k, err := NewKeyring(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	n, err := s.EncryptPending(ctx, k, 1)
	if err != nil || n != 6 {
		t.Fatalf("EncryptPending = %d, %v; want 6 values (owner, display name, 2 scopes, 2 signature sources)", n, err)
	}
	if n, err := s.EncryptPending(ctx, k, 1); err != nil || n != 0 {
		t.Fatalf("second EncryptPending = %d, %v; want 0", n, err)
	}
	dump := func() string {
		var out strings.Builder
		for _, table := range []string{"hosts", "scan_definitions", "runs", "signatures", "hunts", "sessions"} {
			rows, err := s.Pool.Query(ctx, `SELECT row_to_json(t)::text FROM `+table+` t`)
			if err != nil {
				t.Fatal(err)
			}
			got, err := pgx.CollectRows(rows, pgx.RowTo[string])
			if err != nil {
				t.Fatal(err)
			}
			out.WriteString(strings.Join(got, "\n"))
		}
		return out.String()
	}
	raw := dump()
	for _, secret := range secrets {
		if strings.Contains(raw, secret) || strings.Contains(raw, hex.EncodeToString([]byte(secret))) {
			t.Errorf("raw rows still hold %q in plain text", secret)
		}
	}
	open := func(q string) string {
		var b []byte
		if err := s.Pool.QueryRow(ctx, q).Scan(&b); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		plain, err := k.Decrypt(b)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return string(plain)
	}
	if got := open(`SELECT owner FROM hosts WHERE address = '192.0.2.1'`); got != "Plain Owner Team" {
		t.Errorf("owner = %q", got)
	}
	if got := open(`SELECT display_name FROM hosts WHERE address = '192.0.2.1'`); got != "Plain Display Name" {
		t.Errorf("display name = %q", got)
	}
	for _, table := range []string{"scan_definitions", "runs"} {
		if got := open(`SELECT scope FROM ` + table); got != `{"targets": ["198.51.100.0/24"], "excludes": ["198.51.100.7"]}` {
			t.Errorf("%s scope = %q", table, got)
		}
	}
	for _, table := range []string{"signatures", "hunts"} {
		if got := open(`SELECT source FROM ` + table); got != "id: plain-sig\nname: Plain Signature Title\n" {
			t.Errorf("%s source = %q", table, got)
		}
	}
	var empty bool
	if err := s.Pool.QueryRow(ctx, `SELECT owner IS NULL AND display_name IS NULL FROM hosts WHERE address = '192.0.2.2'`).Scan(&empty); err != nil || !empty {
		t.Errorf("empty owner and display name = %v, %v; want NULL", empty, err)
	}
	if err := s.CheckKeys(ctx, k); err != nil {
		t.Fatalf("CheckKeys after encrypting: %v", err)
	}
	var sessions int
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM sessions`).Scan(&sessions); err != nil || sessions != 0 {
		t.Fatalf("sessions = %d, %v; want 0 (sessions with a plain CSRF token are ended)", sessions, err)
	}
}

var hashedColumns = map[string]bool{"sessions.token_hash": true, "sessions.csrf_hash": true, "users.password_hash": true}

// REQ-INVENTORY-036 AC2: docs/technical.md lists every column of the migrated schema as encrypted, hashed or plain; encrypted ones are
// exactly the rotated columns and every plain one gives its reason.
func TestColumnProtectionTableMatchesSchema(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	doc, err := os.ReadFile("../../docs/technical.md")
	if err != nil {
		t.Fatal(err)
	}
	_, section, ok := strings.Cut(string(doc), "\n### Protection of every column\n")
	if !ok {
		t.Fatal("docs/technical.md has no section 'Protection of every column'")
	}
	if i := strings.Index(section, "\n#"); i >= 0 {
		section = section[:i]
	}
	row := regexp.MustCompile("^\\| `([a-z_]+\\.[a-z_]+)` \\| (encrypted|hashed|plain) \\| (.*) \\|$")
	documented := map[string]string{}
	for _, line := range strings.Split(section, "\n") {
		m := row.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if _, dup := documented[m[1]]; dup {
			t.Errorf("docs/technical.md lists %s twice", m[1])
		}
		documented[m[1]] = m[2]
		if strings.TrimSpace(m[3]) == "" {
			t.Errorf("docs/technical.md gives no reason or content for %s", m[1])
		}
	}
	rotated := map[string]bool{}
	for _, tb := range encryptedTables {
		for _, c := range tb.columns {
			rotated[tb.name+"."+c] = true
		}
	}
	rows, err := s.Pool.Query(ctx, `SELECT table_name || '.' || column_name FROM information_schema.columns
		WHERE table_schema = current_schema() ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	cols, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	for _, col := range cols {
		want := "plain"
		if rotated[col] {
			want = "encrypted"
		} else if hashedColumns[col] {
			want = "hashed"
		}
		got, ok := documented[col]
		switch {
		case !ok:
			t.Errorf("column %s is missing from the table in docs/technical.md (%s)", col, want)
		case got != want:
			t.Errorf("docs/technical.md says %s is %s, the code makes it %s", col, got, want)
		}
		delete(documented, col)
	}
	for col := range documented {
		t.Errorf("docs/technical.md lists %s, which is not a column of the migrated schema", col)
	}
}

// REQ-INVENTORY-035: EncryptPending first checks ASI_MASTER_KEY against the stored ciphertexts, so a wrong key never
// seals the pending values of an upgrade.
func TestEncryptPendingRefusesWrongKey(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	all, err := Migrations()
	if err != nil {
		t.Fatal(err)
	}
	var before []Migration
	for _, m := range all {
		if m.Version < "0019" {
			before = append(before, m)
		}
	}
	if _, err := s.migrate(ctx, before); err != nil {
		t.Fatal(err)
	}
	keyA, keyB := make([]byte, 32), make([]byte, 32)
	keyB[0] = 1
	a, _ := NewKeyring(keyA)
	b, _ := NewKeyring(keyB)
	notes, err := a.Encrypt([]byte("n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `INSERT INTO hosts (address, owner, notes) VALUES ('192.0.2.1', 'Plain Owner Team', $1)`, notes); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if n, err := s.EncryptPending(ctx, b, 10); !errors.Is(err, ErrKeyMismatch) || n != 0 {
		t.Fatalf("EncryptPending with the wrong key = %d, %v; want 0, ErrKeyMismatch", n, err)
	}
	var owner []byte
	if err := s.Pool.QueryRow(ctx, `SELECT owner FROM hosts`).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	if string(owner) != "\x00Plain Owner Team" {
		t.Fatalf("owner after the refused EncryptPending = %q, want still pending", owner)
	}
	if n, err := s.EncryptPending(ctx, a, 10); err != nil || n != 1 {
		t.Fatalf("EncryptPending with the right key = %d, %v; want 1", n, err)
	}
	if err := s.CheckKeys(ctx, a); err != nil {
		t.Fatalf("CheckKeys with the right key: %v", err)
	}
}
