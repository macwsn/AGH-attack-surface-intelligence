package detect

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"sync"
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
	db   *store.Store
	keys *store.Keyring
	dir  string
	mu   sync.Mutex
	set  *Set
}

func NewLibrary(db *store.Store, keys *store.Keyring, signaturesDir string) *Library {
	return &Library{db: db, keys: keys, dir: signaturesDir}
}

var errNoKeyring = errors.New("detect: no field encryption keyring")

func (l *Library) seal(src string) ([]byte, error) {
	if l.keys == nil {
		return nil, errNoKeyring
	}
	out, err := l.keys.Encrypt([]byte(src))
	if err != nil {
		return nil, fmt.Errorf("encrypt signature source: %w", err)
	}
	return out, nil
}

func (l *Library) open(sealed []byte) (string, error) {
	if l.keys == nil {
		return "", errNoKeyring
	}
	out, err := l.keys.Decrypt(sealed)
	if err != nil {
		return "", fmt.Errorf("decrypt signature source: %w", err)
	}
	return string(out), nil
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
	Builtin   bool
}

const storedColumns = `id, name, kind, source, enabled, updated_at, updated_by`

func (l *Library) scanStored(row pgx.CollectableRow) (Stored, error) {
	var (
		s      Stored
		source []byte
	)
	if err := row.Scan(&s.ID, &s.Name, &s.Kind, &source, &s.Enabled, &s.UpdatedAt, &s.UpdatedBy); err != nil {
		return s, err
	}
	var err error
	if s.Source, err = l.open(source); err != nil {
		return s, fmt.Errorf("signature %q: %w", s.ID, err)
	}
	return s, nil
}

func (l *Library) List(ctx context.Context) ([]Stored, error) {
	rows, err := l.db.Pool.Query(ctx, `SELECT `+storedColumns+` FROM signatures ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list signatures: %w", err)
	}
	out, err := pgx.CollectRows(rows, l.scanStored)
	if err != nil {
		return nil, fmt.Errorf("list signatures: %w", err)
	}
	return out, nil
}

func (l *Library) Builtin(ctx context.Context) ([]Stored, error) {
	return builtinStored(ctx, l.db.Pool, "")
}

func builtinStored(ctx context.Context, db querier, only string) ([]Stored, error) {
	sigs, srcs, err := packSources()
	if err != nil {
		return nil, err
	}
	rows, err := db.Query(ctx, `SELECT id, enabled, updated_at, updated_by FROM builtin_signatures`)
	if err != nil {
		return nil, fmt.Errorf("list built-in signatures: %w", err)
	}
	state, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Stored, error) {
		var s Stored
		err := row.Scan(&s.ID, &s.Enabled, &s.UpdatedAt, &s.UpdatedBy)
		return s, err
	})
	if err != nil {
		return nil, fmt.Errorf("list built-in signatures: %w", err)
	}
	byID := map[string]Stored{}
	for _, s := range state {
		byID[s.ID] = s
	}
	var out []Stored
	for _, sig := range sigs {
		if only != "" && sig.ID != only {
			continue
		}
		s, ok := byID[sig.ID]
		if !ok {
			s.Enabled = true
		}
		s.ID, s.Name, s.Kind, s.Source, s.Builtin = sig.ID, sig.Name, sig.Kind, srcs[sig.ID], true
		out = append(out, s)
	}
	return out, nil
}

func packSources() ([]Signature, map[string]string, error) {
	sigs, err := Pack()
	if err != nil {
		return nil, nil, err
	}
	files, err := fs.Glob(packFS, "pack/*.yaml")
	if err != nil {
		return nil, nil, fmt.Errorf("list built-in signatures: %w", err)
	}
	srcs := map[string]string{}
	for _, f := range files {
		data, err := fs.ReadFile(packFS, f)
		if err != nil {
			return nil, nil, fmt.Errorf("read built-in signatures: %w", err)
		}
		parsed, raw, err := SplitSources(data)
		if err != nil {
			return nil, nil, fmt.Errorf("built-in %s: %w", f, err)
		}
		for i, s := range parsed {
			srcs[s.ID] = string(raw[i])
		}
	}
	return sigs, srcs, nil
}

func inPack(ids ...string) (string, error) {
	sigs, err := Pack()
	if err != nil {
		return "", err
	}
	for _, s := range sigs {
		for _, id := range ids {
			if s.ID == id {
				return id, nil
			}
		}
	}
	return "", nil
}

func builtinReadOnly(id string) error {
	return &RuleError{ID: id, Rule: RuleDuplicateID, Detail: fmt.Sprintf("%s is a built-in signature; built-in signatures can only be enabled or disabled.", id)}
}

func (l *Library) Get(ctx context.Context, id string) (Stored, error) {
	if b, err := builtinStored(ctx, l.db.Pool, id); err != nil || len(b) == 1 {
		if err != nil {
			return Stored{}, fmt.Errorf("get signature %q: %w", id, err)
		}
		return b[0], nil
	}
	rows, err := l.db.Pool.Query(ctx, `SELECT `+storedColumns+` FROM signatures WHERE id = $1`, id)
	if err != nil {
		return Stored{}, fmt.Errorf("get signature %q: %w", id, err)
	}
	s, err := pgx.CollectExactlyOneRow(rows, l.scanStored)
	if errors.Is(err, pgx.ErrNoRows) {
		return Stored{}, fmt.Errorf("%w: %q", ErrUnknownSignature, id)
	}
	if err != nil {
		return Stored{}, fmt.Errorf("get signature %q: %w", id, err)
	}
	return s, nil
}

func (l *Library) Enabled(ctx context.Context) ([]Signature, error) {
	return l.enabled(ctx, l.db.Pool)
}

func (l *Library) Dir() string {
	return l.dir
}

func (l *Library) Set(ctx context.Context) (*Set, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.set != nil {
		return l.set, nil
	}
	var dirSet *Set
	if l.dir != "" {
		var err error
		if dirSet, err = LoadDir(l.dir); err != nil {
			return nil, fmt.Errorf("signatures directory: %w", err)
		}
	}
	on, err := l.Enabled(ctx)
	if err != nil {
		return nil, err
	}
	set, err := Combine(dirSet, on)
	if err != nil {
		return nil, err
	}
	l.set = set
	return set, nil
}

type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

func (l *Library) enabled(ctx context.Context, db querier) ([]Signature, error) {
	pack, err := Pack()
	if err != nil {
		return nil, err
	}
	rows, err := db.Query(ctx, `SELECT id FROM builtin_signatures WHERE NOT enabled`)
	if err != nil {
		return nil, fmt.Errorf("load built-in signature state: %w", err)
	}
	off, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("load built-in signature state: %w", err)
	}
	out := make([]Signature, 0, len(pack))
	for _, s := range pack {
		if !slices.Contains(off, s.ID) {
			out = append(out, s)
		}
	}
	rows, err = db.Query(ctx, `SELECT source FROM signatures WHERE enabled ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("load database signatures: %w", err)
	}
	srcs, err := pgx.CollectRows(rows, pgx.RowTo[[]byte])
	if err != nil {
		return nil, fmt.Errorf("load database signatures: %w", err)
	}
	for _, sealed := range srcs {
		src, err := l.open(sealed)
		if err != nil {
			return nil, fmt.Errorf("database signature: %w", err)
		}
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
	if id, err := inPack(sig.ID); err != nil || id != "" {
		if err == nil {
			err = &RuleError{ID: id, Rule: RuleDuplicateID, Detail: "a built-in signature already has this id"}
		}
		return Signature{}, err
	}
	sealed, err := l.seal(src)
	if err != nil {
		return Signature{}, err
	}
	err = l.change(ctx, a, AuditCreate, []string{sig.ID}, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO signatures (id, name, kind, source, enabled, updated_by)
			VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (id) DO NOTHING`, sig.ID, sig.Name, sig.Kind, sealed, on, a.Username)
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
	if b, err := inPack(id); err != nil || b != "" {
		if err == nil {
			err = builtinReadOnly(id)
		}
		return Signature{}, err
	}
	sig, err := ParseOne([]byte(src))
	if err != nil {
		return Signature{}, err
	}
	if sig.ID != id {
		return Signature{}, &RuleError{ID: sig.ID, Rule: RuleSchema, Detail: fmt.Sprintf("the id of %q cannot change; create a new signature instead", id)}
	}
	sealed, err := l.seal(src)
	if err != nil {
		return Signature{}, err
	}
	err = l.change(ctx, a, AuditUpdate, []string{id}, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE signatures SET name = $2, kind = $3, source = $4, enabled = $5,
			updated_at = now(), updated_by = $6 WHERE id = $1`, id, sig.Name, sig.Kind, sealed, on, a.Username)
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
	b, err := inPack(id)
	if err != nil {
		return err
	}
	if b != "" {
		return l.change(ctx, a, action, []string{id}, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `INSERT INTO builtin_signatures (id, enabled, updated_by) VALUES ($1, $2, $3)
				ON CONFLICT (id) DO UPDATE SET enabled = $2, updated_at = now(), updated_by = $3`, id, on, a.Username); err != nil {
				return fmt.Errorf("%s %q: %w", action, id, err)
			}
			return nil
		})
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
	if b, err := inPack(id); err != nil || b != "" {
		if err == nil {
			err = builtinReadOnly(id)
		}
		return err
	}
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
	if id, err := inPack(ids...); err != nil || id != "" {
		if err == nil {
			err = &RuleError{ID: id, Rule: RuleDuplicateID, Detail: "a built-in signature already has this id"}
		}
		return nil, err
	}
	sealed := make([][]byte, len(srcs))
	for i, src := range srcs {
		if sealed[i], err = l.seal(string(src)); err != nil {
			return nil, err
		}
	}
	err = l.change(ctx, a, AuditImport, ids, func(tx pgx.Tx) error {
		for i, s := range sigs {
			if _, err := tx.Exec(ctx, `INSERT INTO signatures (id, name, kind, source, updated_by) VALUES ($1, $2, $3, $4, $5)
				ON CONFLICT (id) DO UPDATE SET name = $2, kind = $3, source = $4, updated_at = now(), updated_by = $5`,
				s.ID, s.Name, s.Kind, sealed[i], a.Username); err != nil {
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
	defer l.forget()
	return l.db.Tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `LOCK TABLE signatures IN SHARE ROW EXCLUSIVE MODE`); err != nil {
			return fmt.Errorf("lock signatures: %w", err)
		}
		if err := write(tx); err != nil {
			return err
		}
		on, err := l.enabled(ctx, tx)
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

func (l *Library) forget() {
	l.mu.Lock()
	l.set = nil
	l.mu.Unlock()
}
