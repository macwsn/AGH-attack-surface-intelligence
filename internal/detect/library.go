package detect

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"asi/internal/store"
)

const (
	AuditCreate  = "signature.create"
	AuditUpdate  = "signature.update"
	AuditEnable  = "signature.enable"
	AuditDisable = "signature.disable"
	AuditDelete  = "signature.delete"
	AuditImport  = "signature.import"
)

var ErrUnknownSignature = errors.New("detect: unknown signature")

type Library struct {
	db  *store.Store
	dir string
}

func NewLibrary(db *store.Store, signaturesDir string) *Library {
	return &Library{db: db, dir: signaturesDir}
}

type Actor struct {
	Username string
	Addr     string
}

type Stored struct {
	ID        string
	Name      string
	Kind      string
	Source    string
	Enabled   bool
	UpdatedAt time.Time
	UpdatedBy string
}

const storedColumns = `id, name, kind, source, enabled, updated_at, updated_by`

func scanStored(row pgx.CollectableRow) (Stored, error) {
	var s Stored
	err := row.Scan(&s.ID, &s.Name, &s.Kind, &s.Source, &s.Enabled, &s.UpdatedAt, &s.UpdatedBy)
	return s, err
}

func (l *Library) List(ctx context.Context) ([]Stored, error) {
	rows, err := l.db.Pool.Query(ctx, `SELECT `+storedColumns+` FROM signatures ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list signatures: %w", err)
	}
	out, err := pgx.CollectRows(rows, scanStored)
	if err != nil {
		return nil, fmt.Errorf("list signatures: %w", err)
	}
	return out, nil
}

func (l *Library) Get(ctx context.Context, id string) (Stored, error) {
	rows, err := l.db.Pool.Query(ctx, `SELECT `+storedColumns+` FROM signatures WHERE id = $1`, id)
	if err != nil {
		return Stored{}, fmt.Errorf("get signature %q: %w", id, err)
	}
	s, err := pgx.CollectExactlyOneRow(rows, scanStored)
	if errors.Is(err, pgx.ErrNoRows) {
		return Stored{}, fmt.Errorf("%w: %q", ErrUnknownSignature, id)
	}
	if err != nil {
		return Stored{}, fmt.Errorf("get signature %q: %w", id, err)
	}
	return s, nil
}

func (l *Library) Enabled(ctx context.Context) ([]Signature, error) {
	return enabled(ctx, l.db.Pool)
}

type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

func enabled(ctx context.Context, db querier) ([]Signature, error) {
	rows, err := db.Query(ctx, `SELECT source FROM signatures WHERE enabled ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("load database signatures: %w", err)
	}
	srcs, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("load database signatures: %w", err)
	}
	out := make([]Signature, 0, len(srcs))
	for _, src := range srcs {
		s, err := ParseOne([]byte(src))
		if err != nil {
			return nil, fmt.Errorf("database signature: %w", err)
		}
		out = append(out, s)
	}
	return out, nil
}

func (l *Library) Create(ctx context.Context, a Actor, src string, on bool) (Signature, error) {
	sig, err := ParseOne([]byte(src))
	if err != nil {
		return Signature{}, err
	}
	err = l.change(ctx, a, AuditCreate, []string{sig.ID}, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO signatures (id, name, kind, source, enabled, updated_by)
			VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (id) DO NOTHING`, sig.ID, sig.Name, sig.Kind, src, on, a.Username)
		if err != nil {
			return fmt.Errorf("create signature %q: %w", sig.ID, err)
		}
		if tag.RowsAffected() == 0 {
			return &RuleError{ID: sig.ID, Rule: RuleDuplicateID, Detail: "a stored signature already has this id"}
		}
		return nil
	})
	return sig, err
}

func (l *Library) Update(ctx context.Context, a Actor, id, src string, on bool) (Signature, error) {
	sig, err := ParseOne([]byte(src))
	if err != nil {
		return Signature{}, err
	}
	if sig.ID != id {
		return Signature{}, &RuleError{ID: sig.ID, Rule: RuleSchema, Detail: fmt.Sprintf("the id of %q cannot change; create a new signature instead", id)}
	}
	err = l.change(ctx, a, AuditUpdate, []string{id}, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE signatures SET name = $2, kind = $3, source = $4, enabled = $5,
			updated_at = now(), updated_by = $6 WHERE id = $1`, id, sig.Name, sig.Kind, src, on, a.Username)
		if err != nil {
			return fmt.Errorf("update signature %q: %w", id, err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("%w: %q", ErrUnknownSignature, id)
		}
		return nil
	})
	return sig, err
}

func (l *Library) SetEnabled(ctx context.Context, a Actor, id string, on bool) error {
	action := AuditDisable
	if on {
		action = AuditEnable
	}
	return l.change(ctx, a, action, []string{id}, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE signatures SET enabled = $2, updated_at = now(), updated_by = $3 WHERE id = $1`,
			id, on, a.Username)
		if err != nil {
			return fmt.Errorf("%s %q: %w", action, id, err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("%w: %q", ErrUnknownSignature, id)
		}
		return nil
	})
}

func (l *Library) Delete(ctx context.Context, a Actor, id string) error {
	return l.change(ctx, a, AuditDelete, []string{id}, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM signatures WHERE id = $1`, id)
		if err != nil {
			return fmt.Errorf("delete signature %q: %w", id, err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("%w: %q", ErrUnknownSignature, id)
		}
		return nil
	})
}

func (l *Library) Import(ctx context.Context, a Actor, data []byte) ([]string, error) {
	sigs, srcs, err := SplitSources(data)
	if err != nil {
		return nil, err
	}
	ids := make([]string, len(sigs))
	for i, s := range sigs {
		ids[i] = s.ID
	}
	err = l.change(ctx, a, AuditImport, ids, func(tx pgx.Tx) error {
		for i, s := range sigs {
			if _, err := tx.Exec(ctx, `INSERT INTO signatures (id, name, kind, source, updated_by) VALUES ($1, $2, $3, $4, $5)
				ON CONFLICT (id) DO UPDATE SET name = $2, kind = $3, source = $4, updated_at = now(), updated_by = $5`,
				s.ID, s.Name, s.Kind, string(srcs[i]), a.Username); err != nil {
				return fmt.Errorf("import signature %q: %w", s.ID, err)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return ids, nil
}

func (l *Library) Export(ctx context.Context) ([]byte, error) {
	list, err := l.List(ctx)
	if err != nil {
		return nil, err
	}
	srcs := make([][]byte, len(list))
	for i, s := range list {
		srcs[i] = []byte(s.Source)
	}
	return JoinSources(srcs)
}

func (l *Library) change(ctx context.Context, a Actor, action string, ids []string, write func(pgx.Tx) error) error {
	var dirSet *Set
	if l.dir != "" {
		var err error
		checkIDs := action != AuditDelete && action != AuditDisable
		if dirSet, err = LoadDir(l.dir); err != nil {
			return fmt.Errorf("signatures directory: %w", err)
		}
		for _, s := range dirSet.Signatures {
			for _, id := range ids {
				if checkIDs && s.ID == id {
					return &RuleError{ID: id, Rule: RuleDuplicateID, Detail: "already defined in the signatures directory"}
				}
			}
		}
	}
	return l.db.Tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `LOCK TABLE signatures IN SHARE ROW EXCLUSIVE MODE`); err != nil {
			return fmt.Errorf("lock signatures: %w", err)
		}
		if err := write(tx); err != nil {
			return err
		}
		on, err := enabled(ctx, tx)
		if err != nil {
			return err
		}
		if _, err := Combine(dirSet, on); err != nil {
			return err
		}
		for _, id := range ids {
			if _, err := tx.Exec(ctx, `INSERT INTO audit_log (actor, action, target, address) VALUES ($1, $2, $3, $4)`,
				a.Username, action, id, a.Addr); err != nil {
				return fmt.Errorf("write audit %s: %w", action, err)
			}
		}
		return nil
	})
}
