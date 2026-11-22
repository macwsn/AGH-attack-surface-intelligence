package inventory

import (
	"slices"
	"strings"

	"asi/internal/store"
)

const (
	DefaultInactiveAfter = 3
	StabilityWindow      = 10
	ExportSchema         = "asi.export/v1"
	MaxStoredBody        = 64 << 10
	DefaultBodyRetention = 10
)

type Inventory struct {
	db              *store.Store
	keys            *store.Keyring
	Interest        InterestWeights
	BodyRetention   int
	VolatileHeaders []string
}

func New(s *store.Store, k *store.Keyring) *Inventory {
	return &Inventory{db: s, keys: k, BodyRetention: DefaultBodyRetention}
}

func ParseHeaderNames(list string) []string {
	var out []string
	for _, name := range strings.Split(list, ",") {
		if name = strings.ToLower(strings.TrimSpace(name)); name != "" && !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	return out
}
