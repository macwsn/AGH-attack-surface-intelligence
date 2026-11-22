package web

import (
	"net/http"
	"regexp"
	"testing"
	"time"

	"asi/internal/exchange"
)

// REQ-EXCHANGE-011
func TestImportPageListsEveryCSVColumn(t *testing.T) {
	r, fa := newTestRouter(t)
	rec := do(r, http.MethodGet, "/import", nil, fa.session(t, "alice"))
	page := rec.Body.String()
	rows := regexp.MustCompile(`<tr><td><code>([a-z_]+)</code></td><td>([^<]+)</td></tr>`).FindAllStringSubmatch(page, -1)
	if rec.Code != http.StatusOK || len(rows) != len(exchange.CSVColumns) {
		t.Fatalf("GET /import = %d with %d column rows, want %d", rec.Code, len(rows), len(exchange.CSVColumns))
	}
	for i, c := range exchange.CSVColumns {
		if rows[i][1] != c.Name || rows[i][2] == "" {
			t.Errorf("row %d = %q, want column %s with its meaning", i, rows[i][1:], c.Name)
		}
	}
	for _, want := range []string{`href="/import/sample.csv"`, `href="/import/sample.json"`, `name="dry_run" value="1" checked`} {
		if !regexp.MustCompile(regexp.QuoteMeta(want)).MatchString(page) {
			t.Errorf("import page lacks %s", want)
		}
	}
	if regexp.MustCompile(`style\s*=`).MatchString(page) {
		t.Error("import page has inline styles")
	}
}

// REQ-EXCHANGE-012
func TestPendingImportsAreBounded(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	c := &pendingImports{items: map[string]pendingImport{}, now: func() time.Time { return now }}
	a, _ := c.put("ann", "csv", "", []byte("address\n192.0.2.1\n"))
	if _, err := c.take(a, "bob"); err == nil {
		t.Error("another user took ann's upload")
	}
	b, _ := c.put("ann", "csv", "", []byte("address\n192.0.2.2\n"))
	if _, err := c.take(a, "ann"); err == nil {
		t.Error("an older upload of the same user is still held")
	}
	now = now.Add(pendingTTL + time.Second)
	if _, err := c.take(b, "ann"); err == nil {
		t.Error("an expired upload was taken")
	}
	big := make([]byte, exchange.MaxUploadBytes)
	var tokens []string
	for _, u := range []string{"u1", "u2", "u3", "u4"} {
		tok, err := c.put(u, "csv", "", big)
		if err != nil {
			t.Fatal(err)
		}
		tokens = append(tokens, tok)
		now = now.Add(time.Second)
	}
	held := 0
	for _, p := range c.items {
		held += len(p.data)
	}
	if held > pendingBytes || len(c.items) != 3 {
		t.Fatalf("held %d bytes in %d uploads, limit %d", held, len(c.items), pendingBytes)
	}
	if _, err := c.take(tokens[0], "u1"); err == nil {
		t.Error("the oldest upload was not evicted")
	}
	if p, err := c.take(tokens[3], "u4"); err != nil || len(p.data) != len(big) {
		t.Errorf("the newest upload is gone: %v", err)
	}
}
