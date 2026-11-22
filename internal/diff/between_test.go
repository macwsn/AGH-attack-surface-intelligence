package diff

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"

	"asi/internal/inventory"
)

type exports map[string]inventory.Export

func (e exports) Export(_ context.Context, name string) (inventory.Export, error) {
	exp, ok := e[name]
	if !ok {
		return inventory.Export{}, fmt.Errorf("export: %w: %q", inventory.ErrUnknownRun, name)
	}
	return exp, nil
}

// REQ-DIFF-007
func TestBetween(t *testing.T) {
	src := exports{
		"a": {Run: "a"},
		"b": {Run: "b", Hosts: []inventory.ExportHost{{Address: "10.0.0.1", Status: inventory.StatusActive}}},
	}
	d, err := Between(context.Background(), src, "a", "b", Options{})
	if err != nil {
		t.Fatalf("Between: %v", err)
	}
	if d.From != "a" || d.To != "b" || len(d.Changes) != 1 || d.Changes[0].Type != HostNew {
		t.Fatalf("Between = %+v", d)
	}
	var buf bytes.Buffer
	if err := WriteJSON(&buf, d); err != nil {
		t.Fatal(err)
	}
	want := "{\n  \"schema\": \"asi.diff/v1\",\n  \"from\": \"a\",\n  \"to\": \"b\",\n  \"changes\": [\n    {\n      \"type\": \"host_new\",\n      \"address\": \"10.0.0.1\"\n    }\n  ]\n}\n"
	if buf.String() != want {
		t.Errorf("WriteJSON =\n%s\nwant\n%s", buf.String(), want)
	}
	for _, c := range [][2]string{{"nope", "b"}, {"a", "nope"}, {"", "b"}} {
		_, err := Between(context.Background(), src, c[0], c[1], Options{})
		var unknown *UnknownRunError
		if !errors.As(err, &unknown) || !errors.Is(err, inventory.ErrUnknownRun) || err.Error() != fmt.Sprintf("unknown run %q", unknown.Name) {
			t.Errorf("Between(%q, %q) error = %v, want UnknownRunError", c[0], c[1], err)
		}
	}
}
