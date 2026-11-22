package diff

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"asi/internal/inventory"
)

type Exporter interface {
	Export(ctx context.Context, asOfRun string) (inventory.Export, error)
}

type UnknownRunError struct {
	Name string
}

func (e *UnknownRunError) Error() string { return fmt.Sprintf("unknown run %q", e.Name) }

func (e *UnknownRunError) Is(target error) bool { return target == inventory.ErrUnknownRun }

func Between(ctx context.Context, src Exporter, from, to string, opts Options) (Diff, error) {
	exports := make([]inventory.Export, 2)
	for i, name := range []string{from, to} {
		if name == "" {
			return Diff{}, &UnknownRunError{Name: name}
		}
		exp, err := src.Export(ctx, name)
		if errors.Is(err, inventory.ErrUnknownRun) {
			return Diff{}, &UnknownRunError{Name: name}
		}
		if err != nil {
			return Diff{}, err
		}
		exports[i] = exp
	}
	return Compute(exports[0], exports[1], opts), nil
}

func WriteJSON(w io.Writer, d Diff) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(d); err != nil {
		return fmt.Errorf("encode diff: %w", err)
	}
	return nil
}
