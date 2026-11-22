package store

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
)

var ErrKeyMismatch = errors.New("ASI_MASTER_KEY cannot read stored data")

var errKeyInUse = errors.New("key in use")

type encryptedTable struct {
	name    string
	columns []string
}

var encryptedTables = []encryptedTable{
	{"settings", []string{"value"}},
	{"hosts", []string{"notes", "display_name", "owner"}},
	{"scan_definitions", []string{"scope"}},
	{"runs", []string{"scope"}},
	{"signatures", []string{"source"}},
	{"hunts", []string{"source"}},
	{"service_observations", []string{"http_headers", "http_cookies", "http_body", "field_state"}},
	{"findings", []string{"evidence"}},
	{"hunt_results", []string{"evidence"}},
}

type TableKeys struct {
	Table   string
	Current int64
	Old     map[string]int64
}

type TableRotation struct {
	Table     string
	Rewritten int64
}

func (k *Keyring) header() []byte {
	return append([]byte{cipherVersion}, k.current.id[:]...)
}

func (s *Store) presentEncryptedTables(ctx context.Context) ([]encryptedTable, error) {
	rows, err := s.Pool.Query(ctx, `SELECT table_name, column_name FROM information_schema.columns
		WHERE table_schema = current_schema() AND data_type = 'bytea'`)
	if err != nil {
		return nil, fmt.Errorf("list encrypted columns: %w", err)
	}
	present := map[string]bool{}
	for rows.Next() {
		var t, c string
		if err := rows.Scan(&t, &c); err != nil {
			rows.Close()
			return nil, fmt.Errorf("list encrypted columns: %w", err)
		}
		present[t+"."+c] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list encrypted columns: %w", err)
	}
	var out []encryptedTable
	for _, t := range encryptedTables {
		var cols []string
		for _, c := range t.columns {
			if present[t.name+"."+c] {
				cols = append(cols, c)
			}
		}
		if len(cols) > 0 {
			out = append(out, encryptedTable{t.name, cols})
		}
	}
	return out, nil
}

func (s *Store) CheckKeys(ctx context.Context, k *Keyring) error {
	tables, err := s.presentEncryptedTables(ctx)
	if err != nil {
		return err
	}
	var known [][]byte
	for id := range k.keys {
		known = append(known, append([]byte{cipherVersion}, id[:]...))
	}
	tracked, err := s.keysTracked(ctx)
	if err != nil {
		return err
	}
	if !tracked {
		for _, t := range tables {
			for _, c := range t.columns {
				var header []byte
				err := s.Pool.QueryRow(ctx, fmt.Sprintf(`SELECT substring(%[1]s from 1 for %[2]d) FROM %[3]s
					WHERE %[1]s IS NOT NULL AND substring(%[1]s from 1 for %[2]d) <> ALL($1) LIMIT 1`, c, headerSize, t.name), known).Scan(&header)
				if errors.Is(err, pgx.ErrNoRows) {
					continue
				}
				if err != nil {
					return fmt.Errorf("check field encryption keys in %s.%s: %w", t.name, c, err)
				}
				return keyMismatch(t.name, c, header)
			}
		}
		return nil
	}
	present := map[string]bool{}
	for _, t := range tables {
		for _, c := range t.columns {
			present[t.name+"."+c] = true
		}
	}
	rows, err := s.Pool.Query(ctx, `SELECT table_name, column_name, decode(key_header, 'hex') FROM encryption_keys_in_use
		WHERE decode(key_header, 'hex') <> ALL($1) ORDER BY 1, 2, 3`, known)
	if err != nil {
		return fmt.Errorf("check field encryption keys: %w", err)
	}
	type keyUse struct {
		table, column string
		header        []byte
	}
	uses, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (keyUse, error) {
		var u keyUse
		return u, r.Scan(&u.table, &u.column, &u.header)
	})
	if err != nil {
		return fmt.Errorf("check field encryption keys: %w", err)
	}
	for _, u := range uses {
		if !present[u.table+"."+u.column] {
			continue
		}
		inUse, err := s.forgetUnusedKey(ctx, u.table, u.column, u.header)
		if err != nil {
			return err
		}
		if inUse {
			return keyMismatch(u.table, u.column, u.header)
		}
	}
	return nil
}

func (s *Store) keysTracked(ctx context.Context) (bool, error) {
	var tracked bool
	if err := s.Pool.QueryRow(ctx, `SELECT to_regclass('encryption_keys_in_use') IS NOT NULL`).Scan(&tracked); err != nil {
		return false, fmt.Errorf("check field encryption keys: %w", err)
	}
	return tracked, nil
}

func keyMismatch(table, column string, header []byte) error {
	id := "unknown format"
	if len(header) == headerSize && header[0] == cipherVersion {
		id = "key id " + hex.EncodeToString(header[1:])
	}
	return fmt.Errorf("%w: %s.%s holds values under %s, which is neither ASI_MASTER_KEY nor in ASI_MASTER_KEY_PREVIOUS; start with the key that wrote the data, or add it to ASI_MASTER_KEY_PREVIOUS",
		ErrKeyMismatch, table, column, id)
}

func (s *Store) forgetUnusedKey(ctx context.Context, table, column string, header []byte) (bool, error) {
	var inUse bool
	err := s.Tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM encryption_keys_in_use WHERE table_name = $1 AND column_name = $2 AND key_header = encode($3, 'hex')`,
			table, column, header); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, fmt.Sprintf(`SELECT EXISTS (SELECT 1 FROM %s WHERE substring(%s from 1 for %d) = $1)`,
			table, column, headerSize), header).Scan(&inUse); err != nil {
			return err
		}
		if inUse {
			return errKeyInUse
		}
		return nil
	})
	if errors.Is(err, errKeyInUse) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("check field encryption keys in %s.%s: %w", table, column, err)
	}
	return false, nil
}

func (s *Store) KeyStatus(ctx context.Context, k *Keyring) ([]TableKeys, error) {
	tables, err := s.presentEncryptedTables(ctx)
	if err != nil {
		return nil, err
	}
	current := hex.EncodeToString(k.current.id[:])
	var out []TableKeys
	for _, t := range tables {
		values := make([]string, len(t.columns))
		for i, c := range t.columns {
			values[i] = "(" + c + ")"
		}
		rows, err := s.Pool.Query(ctx, fmt.Sprintf(`SELECT encode(substring(v from 2 for %d), 'hex'), count(DISTINCT t.ctid)
			FROM %s t CROSS JOIN LATERAL (VALUES %s) x(v) WHERE v IS NOT NULL GROUP BY 1`, keyIDSize, t.name, strings.Join(values, ", ")))
		if err != nil {
			return nil, fmt.Errorf("key status of %s: %w", t.name, err)
		}
		tk := TableKeys{Table: t.name, Old: map[string]int64{}}
		for rows.Next() {
			var (
				id string
				n  int64
			)
			if err := rows.Scan(&id, &n); err != nil {
				rows.Close()
				return nil, fmt.Errorf("key status of %s: %w", t.name, err)
			}
			if id == current {
				tk.Current = n
			} else {
				tk.Old[id] = n
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("key status of %s: %w", t.name, err)
		}
		out = append(out, tk)
	}
	return out, nil
}

func (s *Store) RotateKeys(ctx context.Context, k *Keyring, batch int, onBatch func(table string, rewritten int)) ([]TableRotation, error) {
	if batch < 1 {
		return nil, fmt.Errorf("rotate keys: batch size %d, want at least 1", batch)
	}
	if err := s.CheckKeys(ctx, k); err != nil {
		return nil, err
	}
	tables, err := s.presentEncryptedTables(ctx)
	if err != nil {
		return nil, err
	}
	var out []TableRotation
	for _, t := range tables {
		r := TableRotation{Table: t.name}
		for {
			n, err := s.rotateBatch(ctx, k, t, batch)
			if err != nil {
				return out, err
			}
			if n == 0 {
				break
			}
			r.Rewritten += int64(n)
			if onBatch != nil {
				onBatch(t.name, n)
			}
		}
		if err := s.forgetOldKeys(ctx, k, t); err != nil {
			return out, err
		}
		out = append(out, r)
	}
	return out, nil
}

func (s *Store) forgetOldKeys(ctx context.Context, k *Keyring, t encryptedTable) error {
	if tracked, err := s.keysTracked(ctx); err != nil || !tracked {
		return err
	}
	rows, err := s.Pool.Query(ctx, `SELECT column_name, decode(key_header, 'hex') FROM encryption_keys_in_use
		WHERE table_name = $1 AND key_header <> encode($2, 'hex')`, t.name, k.header())
	if err != nil {
		return fmt.Errorf("forget old keys of %s: %w", t.name, err)
	}
	type keyUse struct {
		column string
		header []byte
	}
	uses, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (keyUse, error) {
		var u keyUse
		return u, r.Scan(&u.column, &u.header)
	})
	if err != nil {
		return fmt.Errorf("forget old keys of %s: %w", t.name, err)
	}
	for _, u := range uses {
		if !slices.Contains(t.columns, u.column) {
			continue
		}
		if _, err := s.forgetUnusedKey(ctx, t.name, u.column, u.header); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) rotateBatch(ctx context.Context, k *Keyring, t encryptedTable, batch int) (int, error) {
	header := k.header()
	stale := make([]string, len(t.columns))
	sets := make([]string, len(t.columns))
	for i, c := range t.columns {
		stale[i] = fmt.Sprintf("substring(%s from 1 for %d) <> $1", c, headerSize)
		sets[i] = fmt.Sprintf("%s = $%d", c, i+1)
	}
	selectSQL := fmt.Sprintf(`SELECT ctid::text, %s FROM %s WHERE %s LIMIT $2 FOR UPDATE`,
		strings.Join(t.columns, ", "), t.name, strings.Join(stale, " OR "))
	updateSQL := fmt.Sprintf(`UPDATE %s SET %s WHERE ctid = $%d::tid`, t.name, strings.Join(sets, ", "), len(t.columns)+1)

	var n int
	err := s.Tx(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, selectSQL, header, batch)
		if err != nil {
			return err
		}
		updates := &pgx.Batch{}
		for rows.Next() {
			var ctid string
			vals := make([][]byte, len(t.columns))
			dest := []any{&ctid}
			for i := range vals {
				dest = append(dest, &vals[i])
			}
			if err := rows.Scan(dest...); err != nil {
				rows.Close()
				return err
			}
			args := make([]any, 0, len(vals)+1)
			for i, v := range vals {
				if v != nil && !bytes.HasPrefix(v, header) {
					plain, err := k.Decrypt(v)
					if err != nil {
						rows.Close()
						return fmt.Errorf("%s.%s: %w", t.name, t.columns[i], err)
					}
					if v, err = k.Encrypt(plain); err != nil {
						rows.Close()
						return err
					}
				}
				args = append(args, v)
			}
			updates.Queue(updateSQL, append(args, ctid)...)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		n = updates.Len()
		if n == 0 {
			return nil
		}
		return tx.SendBatch(ctx, updates).Close()
	})
	if err != nil {
		return 0, fmt.Errorf("rotate keys in %s: %w", t.name, err)
	}
	return n, nil
}

const pendingMarker = 0

func (s *Store) EncryptPending(ctx context.Context, k *Keyring, batch int) (int64, error) {
	if batch < 1 {
		return 0, fmt.Errorf("encrypt pending values: batch size %d, want at least 1", batch)
	}
	if err := s.CheckKeys(ctx, k); err != nil {
		return 0, err
	}
	tables, err := s.presentEncryptedTables(ctx)
	if err != nil {
		return 0, err
	}
	var total int64
	for _, t := range tables {
		for _, c := range t.columns {
			for {
				n, err := s.encryptPendingBatch(ctx, k, t.name, c, batch)
				if err != nil {
					return total, err
				}
				if n == 0 {
					break
				}
				total += int64(n)
			}
		}
	}
	return total, nil
}

func (s *Store) encryptPendingBatch(ctx context.Context, k *Keyring, table, column string, batch int) (int, error) {
	var n int
	err := s.Tx(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, fmt.Sprintf(`SELECT ctid::text, %[1]s FROM %[2]s WHERE substring(%[1]s from 1 for 1) = $1 LIMIT $2 FOR UPDATE`,
			column, table), []byte{pendingMarker}, batch)
		if err != nil {
			return err
		}
		updates := &pgx.Batch{}
		for rows.Next() {
			var (
				ctid string
				v    []byte
			)
			if err := rows.Scan(&ctid, &v); err != nil {
				rows.Close()
				return err
			}
			sealed, err := k.Encrypt(v[1:])
			if err != nil {
				rows.Close()
				return err
			}
			updates.Queue(fmt.Sprintf(`UPDATE %s SET %s = $1 WHERE ctid = $2::tid`, table, column), sealed, ctid)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		n = updates.Len()
		if n == 0 {
			return nil
		}
		return tx.SendBatch(ctx, updates).Close()
	})
	if err != nil {
		return 0, fmt.Errorf("encrypt pending values in %s.%s: %w", table, column, err)
	}
	return n, nil
}
