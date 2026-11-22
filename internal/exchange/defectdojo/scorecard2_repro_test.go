package defectdojo

import (
	"strings"
	"testing"
	"time"

	"asi/internal/inventory"
	"asi/internal/probe"
)

// AC1: the DefectDojo payload carries each kind+name of one service once, even when several signatures found it.
func TestReproGenericFindingsHaveNoDuplicateKindAndNamePerService(t *testing.T) {
	seen := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	staging := "Staging or test environment"
	exp := inventory.Export{Run: "r", Hosts: []inventory.ExportHost{{Address: "192.0.2.7", Status: inventory.StatusActive, Services: []inventory.ExportService{{
		Port: 80, Protocol: "tcp", State: "open", Status: inventory.StatusActive, Service: "http", LastSeen: seen, HTTP: &probe.HTTP{Scheme: "http"},
		Findings: []inventory.Finding{
			{SignatureID: "staging-environment", Kind: "staging", Name: staging, Confidence: 75, Evidence: "GET /: header x-environment"},
			{SignatureID: "builtin-staging-header", Kind: "staging", Name: staging, Confidence: 75, Evidence: "X-Environment: staging"},
			{SignatureID: "builtin-staging-title", Kind: "staging", Name: staging, Confidence: 70, Evidence: "title [STAGING] Rekrutacja"},
			{SignatureID: "admin-panel-login", Kind: "admin-panel", Name: "Admin panel login form", Confidence: 80},
			{SignatureID: "admin-panel-login-2", Kind: "admin-panel", Name: "Admin panel login form", Confidence: 60},
		},
	}}}}}
	body, n, err := GenericFindings(exp)
	if err != nil {
		t.Fatal(err)
	}
	titles := map[string]int{}
	for _, f := range decodeFindings(t, body) {
		if f.VulnIDFromTool == serviceVulnID {
			continue
		}
		titles[f.Title]++
		if strings.HasPrefix(f.Title, "Staging: ") && f.Impact != "Confidence 75/100." {
			t.Errorf("merged staging finding impact = %q, want the highest confidence 75", f.Impact)
		}
	}
	for title, c := range titles {
		if c > 1 {
			t.Errorf("payload carries %q %d times, want once", title, c)
		}
	}
	if n != 2 {
		t.Errorf("findings = %d, want 2 (one staging, one admin panel): %s", n, body)
	}
}
