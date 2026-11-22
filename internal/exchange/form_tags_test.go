package exchange

import (
	"net/url"
	"reflect"
	"testing"

	"asi/internal/inventory"
)

func TestEntryFormKeepsTagsWithSpaces(t *testing.T) {
	rt := FormFromHost(inventory.ExportHost{Address: "10.0.0.2", Tags: []string{"crown jewel", "dmz"}})
	if got := rt.Batch().Entries[0].User.Tags; !reflect.DeepEqual(got, []string{"crown jewel", "dmz"}) {
		t.Errorf("round trip through the form = %q", got)
	}
	for in, want := range map[string][]string{
		"crown jewel, dmz":     {"crown jewel", "dmz"},
		" crown jewel ;dmz,, ": {"crown jewel", "dmz"},
		"one":                  {"one"},
		"":                     nil,
		"a b c":                {"a b c"},
		"x,\ny z":              {"x", "y z"},
	} {
		b := HostFormFrom(url.Values{"address": {"10.0.0.2"}, "tags": {in}, "hostnames": {"a.example b.example"}}).Batch()
		if len(b.Entries) != 1 {
			t.Fatalf("%q: entries = %d (%v)", in, len(b.Entries), b.Errors)
		}
		got := b.Entries[0].User.Tags
		if len(got) == 0 {
			got = nil
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("tags %q -> %q, want %q", in, got, want)
		}
		if h := b.Entries[0].Host.Hostnames; len(h) != 2 {
			t.Errorf("hostnames = %q", h)
		}
	}
}
