//go:build integration

package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"asi/internal/exchange"
)

// REQ-EXCHANGE-010
func TestImportSamplesImportCleanly(t *testing.T) {
	for _, format := range []string{"csv", "json"} {
		e := newExchangeEnv(t)
		edna := e.login("edna")
		rec := e.serve(httptest.NewRequest(http.MethodGet, "/import/sample."+format, nil), edna)
		want, _ := exchange.Sample(format)
		if rec.Code != http.StatusOK || rec.Body.String() != string(want) ||
			rec.Header().Get("Content-Disposition") != `attachment; filename="asi-import-sample.`+format+`"` {
			t.Fatalf("GET /import/sample.%s = %d %q", format, rec.Code, rec.Header().Get("Content-Disposition"))
		}
		if olga := e.login("olga"); e.serve(httptest.NewRequest(http.MethodGet, "/import/sample."+format, nil), olga).Code != http.StatusForbidden {
			t.Errorf("sample.%s is served without the import permission", format)
		}
		sample := rec.Body.Bytes()

		dry := e.upload(edna, map[string]string{"dry_run": "1"}, "sample."+format, sample)
		body := dry.Body.String()
		if dry.Code != http.StatusOK || !strings.Contains(body, "Dry run: 3 hosts and 3 services would be imported") ||
			figureValue(body, "Invalid rows") != "0" || figureValue(body, "New hosts") != "3" || figureValue(body, "New services") != "3" {
			t.Fatalf("%s sample dry run = %d\n%s", format, dry.Code, body)
		}
		m := importToken.FindStringSubmatch(body)
		if m == nil {
			t.Fatalf("%s sample dry run offers no import button", format)
		}
		real := e.confirm(edna, m[1])
		if real.Code != http.StatusOK || !strings.Contains(real.Body.String(), "Imported 3 hosts and 3 services") || figureValue(real.Body.String(), "Invalid rows") != "0" {
			t.Fatalf("%s sample import = %d\n%s", format, real.Code, real.Body.String())
		}
		exp, err := e.inv.Export(context.Background(), "")
		if err != nil || len(exp.Hosts) != 3 || exp.Hosts[0].Address != "192.0.2.10" || len(exp.Hosts[0].Services) != 2 || exp.Hosts[0].Tags == nil {
			t.Fatalf("%s: export after importing the sample = %+v (%v)", format, exp.Hosts, err)
		}
		again := e.upload(edna, map[string]string{"dry_run": "1"}, "sample."+format, sample)
		if figureValue(again.Body.String(), "New hosts") != "0" || figureValue(again.Body.String(), "Invalid rows") != "0" {
			t.Errorf("%s: dry run of the sample after importing it:\n%s", format, again.Body.String())
		}
	}
}
