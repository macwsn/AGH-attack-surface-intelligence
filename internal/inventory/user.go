package inventory

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func validStatusOverride(s string) bool {
	switch Status(s) {
	case "", StatusActive, StatusUnstable, StatusInactive:
		return true
	}
	return false
}

func (inv *Inventory) UpdateHostUserFields(ctx context.Context, address string, f HostUserFields) error {
	addr, sealed, err := inv.prepareUserFields(address, f)
	if err != nil {
		return err
	}
	return updateHostUserFields(ctx, inv.db.Pool, addr, f, sealed)
}

type sealedUserFields struct {
	notes, displayName, owner []byte
}

func (inv *Inventory) prepareUserFields(address string, f HostUserFields) (string, sealedUserFields, error) {
	var sealed sealedUserFields
	addr, err := normalizeAddress(address)
	if err != nil {
		return "", sealed, err
	}
	if !validStatusOverride(f.StatusOverride) {
		return "", sealed, fmt.Errorf("inventory: invalid status override %q", f.StatusOverride)
	}
	for _, v := range []struct {
		dst   *[]byte
		plain string
	}{{&sealed.notes, f.Notes}, {&sealed.displayName, f.DisplayName}, {&sealed.owner, f.Owner}} {
		if *v.dst, err = inv.sealString(v.plain); err != nil {
			return "", sealed, err
		}
	}
	return addr, sealed, nil
}

type Editor struct {
	Username string
	Addr     string
}

func (inv *Inventory) EditHostUserFields(ctx context.Context, e Editor, address string, f HostUserFields) error {
	addr, sealed, err := inv.prepareUserFields(address, f)
	if err != nil {
		return err
	}
	return inv.db.Tx(ctx, func(tx pgx.Tx) error {
		if err := updateHostUserFields(ctx, tx, addr, f, sealed); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO audit_log (actor, action, target, address) VALUES ($1, 'host.edit', $2, $3)`,
			e.Username, addr, e.Addr); err != nil {
			return fmt.Errorf("audit edit of host %s: %w", addr, err)
		}
		return nil
	})
}

func cleanTags(tags []string) []string {
	out := []string{}
	for _, tag := range tags {
		for _, t := range strings.FieldsFunc(tag, func(r rune) bool { return r == ',' || r == ';' || r == '\n' || r == '\r' }) {
			if t = strings.TrimSpace(t); t != "" && !slices.Contains(out, t) {
				out = append(out, t)
			}
		}
	}
	return out
}

type execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

func updateHostUserFields(ctx context.Context, db execer, addr string, f HostUserFields, sealed sealedUserFields) error {
	tag, err := db.Exec(ctx, `UPDATE hosts SET tags = $2, notes = $3, display_name = $4, owner = $5,
			criticality = $6, status_override = $7, user_updated_at = now()
		WHERE address = $1`, addr, cleanTags(f.Tags), sealed.notes, sealed.displayName, sealed.owner, f.Criticality, f.StatusOverride)
	if err != nil {
		return fmt.Errorf("update user fields of host %s: %w", addr, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: %s", ErrUnknownHost, addr)
	}
	return nil
}

func (inv *Inventory) GetHostUserFields(ctx context.Context, address string) (HostUserFields, error) {
	addr, err := normalizeAddress(address)
	if err != nil {
		return HostUserFields{}, err
	}
	var (
		f                         HostUserFields
		notes, displayName, owner []byte
	)
	err = inv.db.Pool.QueryRow(ctx, `SELECT tags, notes, display_name, owner, criticality, status_override
		FROM hosts WHERE address = $1`, addr).Scan(&f.Tags, &notes, &displayName, &owner, &f.Criticality, &f.StatusOverride)
	if errors.Is(err, pgx.ErrNoRows) {
		return HostUserFields{}, fmt.Errorf("%w: %s", ErrUnknownHost, addr)
	}
	if err != nil {
		return HostUserFields{}, fmt.Errorf("read user fields of host %s: %w", addr, err)
	}
	if f.Notes, f.DisplayName, f.Owner, err = inv.openUserFields(notes, displayName, owner); err != nil {
		return HostUserFields{}, fmt.Errorf("host %s: %w", addr, err)
	}
	f.Tags = nonNil(f.Tags)
	return f, nil
}

func (inv *Inventory) openUserFields(notes, displayName, owner []byte) (string, string, string, error) {
	n, err := inv.openString(notes)
	if err != nil {
		return "", "", "", fmt.Errorf("notes: %w", err)
	}
	d, err := inv.openString(displayName)
	if err != nil {
		return "", "", "", fmt.Errorf("display name: %w", err)
	}
	o, err := inv.openString(owner)
	if err != nil {
		return "", "", "", fmt.Errorf("owner: %w", err)
	}
	return n, d, o, nil
}
