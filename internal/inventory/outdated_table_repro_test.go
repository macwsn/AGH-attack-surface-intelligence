package inventory

import (
	"testing"
	"time"

	"asi/internal/detect"
)

func TestReproInterestOutdatedFollowsTheOutdatedTable(t *testing.T) {
	cases := []struct{ name, version string }{
		{"Apache", "2.4.55"},
		{"OpenSSH", "8.9"},
		{"WordPress", "6.2"},
		{"vsftpd", "2.3.4"},
		{"nginx", "1.20.1"},
		{"PHP", "8.3.0"},
	}
	at := time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC)
	for _, c := range cases {
		table := len(detect.Outdated([]detect.Technology{{Name: c.name, Version: c.version, Confidence: 90}})) > 0
		h := ExportHost{Address: "192.0.2.1", Services: []ExportService{{
			Port: 80, Protocol: "tcp", Status: StatusActive,
			Technologies: []Technology{{Name: c.name, Version: c.version, Confidence: 90}},
		}}}
		_, reasons := Score(h, at, nil)
		score := false
		for _, r := range reasons {
			if r.Code == ReasonOutdated {
				score = true
			}
		}
		if score != table {
			t.Errorf("%s %s: interest score outdated=%t, outdated.yaml outdated=%t; want the same table for both", c.name, c.version, score, table)
		}
	}
}
