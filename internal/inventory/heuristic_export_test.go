package inventory

import (
	"encoding/json"
	"strings"
	"testing"
)

// REQ-SIGNATURES-021: heuristic technologies keep their source and confidence in the export.
func TestExportKeepsHeuristicLabel(t *testing.T) {
	b, err := json.Marshal(ExportService{Port: 80, Protocol: "tcp", Technologies: []Technology{{Name: "Quorvel", Confidence: 30, Source: "heuristic"}},
		Findings: []Finding{{SignatureID: "builtin-heuristic-title-corroborated", Kind: "technology", Name: "Quorvel", Confidence: 30, Evidence: "page title, corroborated by cookie quorvel_sid"}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"source":"heuristic"`, `"confidence":30`, `"signature_id":"builtin-heuristic-title-corroborated"`, `"evidence":"page title, corroborated by cookie quorvel_sid"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("export %s lacks %s", b, want)
		}
	}
}
