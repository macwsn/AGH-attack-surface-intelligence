//go:build integration

package diff

import (
	"context"
	"crypto/rand"
	"fmt"
	"reflect"
	"testing"

	"asi/internal/inventory"
	"asi/internal/probe"
	"asi/internal/store"
	"asi/internal/store/storetest"
)

func openInventory(t *testing.T) *inventory.Inventory {
	t.Helper()
	ctx := context.Background()
	s, err := store.Open(ctx, storetest.DatabaseURL(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(s.Close)
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	k, err := store.NewKeyring(master)
	if err != nil {
		t.Fatal(err)
	}
	return inventory.New(s, k)
}

// REQ-DIFF-015
func TestLearnedVolatilityThroughRecordGroup(t *testing.T) {
	ctx := context.Background()
	inv := openInventory(t)
	const addr = "10.20.0.1"
	titles := []string{"a", "b", "c", "d", "e", "e", "e", "e", "f", "g"}
	wantChanged := []bool{false, true, true, false, false, false, false, false, true, true}
	var prev string
	for i, title := range titles {
		name := fmt.Sprintf("v%d", i)
		run, err := inv.CreateRun(ctx, inventory.RunSpec{Name: name})
		if err != nil {
			t.Fatal(err)
		}
		svc := inventory.ServiceResult{Port: 80, Protocol: "tcp", State: "open", Service: "http",
			HTTP: &probe.HTTP{Scheme: "http", URL: "http://" + addr + "/", StatusCode: 200, Title: title, Headers: map[string]string{"server": "x"}}}
		if err := inv.RecordGroup(ctx, run.ID, inventory.GroupResult{Index: 0, Addresses: []string{addr},
			Hosts: []inventory.HostResult{{Address: addr, Services: []inventory.ServiceResult{svc}}}}); err != nil {
			t.Fatal(err)
		}
		if i > 0 {
			d, err := Between(ctx, inv, prev, name, Options{})
			if err != nil {
				t.Fatal(err)
			}
			if changed := len(d.Changes) > 0; changed != wantChanged[i] {
				t.Errorf("run %s (title %q): changes = %+v, want changed = %v", name, title, d.Changes, wantChanged[i])
			}
		}
		prev = name
	}

	e, err := inv.Export(ctx, "v7")
	if err != nil {
		t.Fatal(err)
	}
	want := []inventory.VolatileField{{Field: "http.title", Values: []any{"c", "d", "e"}}}
	if got := e.Hosts[0].Services[0].Volatile; !reflect.DeepEqual(got, want) {
		t.Errorf("volatile as of v7 = %+v, want %+v", got, want)
	}
	e, err = inv.Export(ctx, "v8")
	if err != nil {
		t.Fatal(err)
	}
	if got := e.Hosts[0].Services[0].Volatile; len(got) != 0 {
		t.Errorf("volatile as of v8 = %+v, want none after 3 stable runs and a change", got)
	}
}
