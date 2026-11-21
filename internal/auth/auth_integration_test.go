//go:build integration

package auth

import (
	"context"
	"testing"

	"asi/internal/store"
	"asi/internal/store/storetest"
)

func newTestService(t *testing.T, cfg Config) *Service {
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
	return NewService(st, cfg)
}
