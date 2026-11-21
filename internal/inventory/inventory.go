package inventory

import "asi/internal/store"

const (
	DefaultInactiveAfter = 3
	StabilityWindow      = 10
	ExportSchema         = "asi.export/v1"
)

type Inventory struct {
	db   *store.Store
	keys *store.Keyring
}

func New(s *store.Store, k *store.Keyring) *Inventory {
	return &Inventory{db: s, keys: k}
}
