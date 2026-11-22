package web

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"asi/internal/inventory"
)

// REQ-SIGNATURES-021: heuristic technologies and findings keep their source and confidence on the host page.
func TestHostPageLabelsHeuristicTechnology(t *testing.T) {
	r, _ := newTestRouter(t)
	d := inventory.HostDetail{Run: "r1", Host: inventory.ExportHost{Address: "10.0.0.5", Stability: 1, Services: []inventory.ExportService{{
		Port: 80, Protocol: "tcp", State: "open", Service: "http",
		Technologies: []inventory.Technology{{Name: "Quorvel", Confidence: 30, Source: "heuristic"}},
		Findings: []inventory.Finding{{SignatureID: "builtin-heuristic-title-corroborated", Kind: "technology", Name: "Quorvel", Confidence: 30,
			Evidence: "page title, corroborated by asset path /static/quorvel.js"}},
	}}}}
	rec := httptest.NewRecorder()
	r.Render(rec, httptest.NewRequest(http.MethodGet, "/hosts/10.0.0.5", nil), http.StatusOK, "host.html", View{Data: newHostView(d, time.Now())})
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("host page = %d:\n%s", rec.Code, body)
	}
	row := regexp.MustCompile(`(?s)<td>Quorvel</td>.*?</tr>`).FindString(body)
	if !strings.Contains(row, ">heuristic<") || !strings.Contains(row, `value="30"`) {
		t.Errorf("technology row = %q, want source heuristic and confidence 30", row)
	}
	for _, want := range []string{"builtin-heuristic-title-corroborated", "page title, corroborated by asset path /static/quorvel.js"} {
		if !strings.Contains(body, want) {
			t.Errorf("host page lacks %q", want)
		}
	}
}
