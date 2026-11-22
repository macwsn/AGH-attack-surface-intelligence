package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"maps"
	"slices"

	"asi/internal/config"
	"asi/internal/store"
)

const defaultRotateBatch = 500

type keyAction struct {
	rotate bool
	batch  int
}

func parseKey(args []string) (keyAction, error) {
	if len(args) == 1 && args[0] == "status" {
		return keyAction{}, nil
	}
	if len(args) == 0 || args[0] != "rotate" {
		return keyAction{}, errUsage
	}
	fs := newFlagSet("key rotate")
	batch := fs.Int("batch", defaultRotateBatch, "")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() > 0 || *batch < 1 {
		return keyAction{}, errUsage
	}
	return keyAction{rotate: true, batch: *batch}, nil
}

func withKeys(ctx context.Context, cfg config.Config, stdout io.Writer, a keyAction) error {
	keys, err := store.NewKeyring(cfg.MasterKey, cfg.PreviousKeys...)
	if err != nil {
		return err
	}
	s, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer s.Close()
	id := keys.KeyID()
	current := hex.EncodeToString(id[:])
	if a.rotate {
		res, err := s.RotateKeys(ctx, keys, a.batch, nil)
		for _, r := range res {
			fmt.Fprintf(stdout, "%s: %d rows rewritten\n", r.Table, r.Rewritten)
		}
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "key rotate: done, all encrypted rows are under key id %s\n", current)
		return nil
	}
	status, err := s.KeyStatus(ctx, keys)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "current key id %s\n", current)
	var total int64
	for _, t := range status {
		var old int64
		for _, n := range t.Old {
			old += n
		}
		total += old
		fmt.Fprintf(stdout, "%s: %d rows under current key, %d rows under old key ids", t.Table, t.Current, old)
		for _, k := range slices.Sorted(maps.Keys(t.Old)) {
			fmt.Fprintf(stdout, " %s=%d", k, t.Old[k])
		}
		fmt.Fprintln(stdout)
	}
	fmt.Fprintf(stdout, "total: %d rows under old key ids\n", total)
	return nil
}
