package exchange

import (
	"slices"
	"strings"
	"testing"
)

// REQ-EXCHANGE-011
func TestCSVColumnsCoverTheExportAndHaveMeanings(t *testing.T) {
	var names []string
	for _, c := range CSVColumns {
		if strings.TrimSpace(c.Meaning) == "" {
			t.Errorf("column %s has no meaning", c.Name)
		}
		names = append(names, c.Name)
	}
	for _, h := range CSVHeader {
		if !slices.Contains(names, h) {
			t.Errorf("export column %s is not in CSVColumns", h)
		}
	}
	b, err := ParseCSV([]byte("address,bogus,notes\n192.0.2.1,ignored,hello\n"))
	if err != nil || len(b.Entries) != 1 || b.Entries[0].User.Notes != "hello" || b.Invalid != 0 {
		t.Fatalf("ParseCSV with an unknown column = %+v, %v", b, err)
	}
}

// REQ-EXCHANGE-010
func TestSamplesParseCleanly(t *testing.T) {
	for _, format := range []string{"csv", "json"} {
		data, err := Sample(format)
		if err != nil {
			t.Fatal(err)
		}
		b, err := Parse(format, data)
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		services := 0
		for _, e := range b.Entries {
			services += len(e.Host.Services)
		}
		if b.Invalid != 0 || len(b.Errors) != 0 || len(b.Entries) != 3 || services != 3 {
			t.Errorf("%s sample parses to %d hosts, %d services, %d invalid %v", format, len(b.Entries), services, b.Invalid, b.Errors)
		}
	}
	if _, err := Sample("xml"); err == nil {
		t.Error("Sample(xml) did not fail")
	}
}
