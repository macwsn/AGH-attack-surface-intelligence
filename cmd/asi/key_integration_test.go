//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"asi/internal/exchange/defectdojo"
	"asi/internal/store"
)

var rotatedKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 32))

// REQ-INVENTORY-021 REQ-INVENTORY-022 REQ-INVENTORY-023
func TestKeyRotate(t *testing.T) {
	ctx := context.Background()
	c := newCLIEnv(t, "192.0.2.0/29", "192.0.2.0")
	sigs := filepath.Join(c.dir, "sigs")
	if err := os.MkdirAll(sigs, 0o700); err != nil {
		t.Fatal(err)
	}
	sig := "- id: admin-console\n  name: Admin console\n  kind: admin-panel\n  confidence: 80\n  match:\n    all:\n      - { type: title_regex, value: 'Admin console' }\n"
	if err := os.WriteFile(filepath.Join(sigs, "s.yaml"), []byte(sig), 0o600); err != nil {
		t.Fatal(err)
	}
	c.net.up("192.0.2.1", 80)
	c.net.title("192.0.2.1", "Admin console")
	c.net.up("192.0.2.2", 80)
	c.scan("k1", "--signatures-dir", sigs)
	c.mustRun("host", "edit", "192.0.2.1", "--notes", "rack 4, ask Jan")
	srv := httptest.NewServer(&dojoServer{})
	t.Cleanup(srv.Close)
	if code, _, stderr := c.runDojo(srv, dojoToken+"\n", "defectdojo", "configure", "--url", srv.URL+"/", "--product", "4", "--engagement", "5", "--token-stdin"); code != 0 {
		t.Fatalf("configure: exit %d stderr %q", code, stderr)
	}
	var bodies int
	if err := c.st.Pool.QueryRow(ctx, `SELECT count(*) FROM service_observations WHERE http_body IS NOT NULL`).Scan(&bodies); err != nil || bodies != 2 {
		t.Fatalf("stored bodies = %d, %v; want 2", bodies, err)
	}
	runsBefore := countRuns(t, c.st)

	c.env["ASI_MASTER_KEY"] = rotatedKey
	code, _, stderr := c.run(c.scanArgs("k2")...)
	assertOneLineError(t, "scan with a key that cannot read the data", code, stderr, "ASI_MASTER_KEY cannot read stored data", "ASI_MASTER_KEY_PREVIOUS")
	if n := countRuns(t, c.st); n != runsBefore {
		t.Fatalf("refused scan wrote runs: %d, want %d", n, runsBefore)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c.env["ASI_LISTEN"] = ln.Addr().String()
	ln.Close()
	code, stdout, stderr := c.run("serve")
	assertOneLineError(t, "serve with a key that cannot read the data", code, stderr, "ASI_MASTER_KEY cannot read stored data")
	if strings.Contains(stdout, "listening") {
		t.Fatalf("refused serve listened: %q", stdout)
	}

	c.env["ASI_MASTER_KEY_PREVIOUS"] = "not-a-key"
	code, _, stderr = c.run("key", "status")
	assertOneLineError(t, "malformed previous key", code, stderr, "ASI_MASTER_KEY_PREVIOUS is malformed")

	c.env["ASI_MASTER_KEY_PREVIOUS"] = rotatedKey + "," + testKey
	if h, ok := hostByAddr(c.export(""), "192.0.2.1"); !ok || h.Notes != "rack 4, ask Jan" {
		t.Fatalf("export under previous key: notes %q", h.Notes)
	}
	status := c.mustRun("key", "status")
	for _, want := range []string{"settings: 0 rows under current key, 1 rows under old key ids",
		"hosts: 0 rows under current key, 1 rows under old key ids", "service_observations: 0 rows under current key, 2 rows under old key ids",
		"findings: 0 rows under current key, 1 rows under old key ids", "runs: 0 rows under current key, 1 rows under old key ids",
		"total: 6 rows under old key ids"} {
		if !strings.Contains(status, want) {
			t.Fatalf("status before rotate %q, want %q", status, want)
		}
	}

	out := c.mustRun("key", "rotate", "--batch", "1")
	for _, want := range []string{"settings: 1 rows rewritten\n", "hosts: 1 rows rewritten\n", "service_observations: 2 rows rewritten\n",
		"findings: 1 rows rewritten\n", "runs: 1 rows rewritten\n", "hunt_results: 0 rows rewritten\n"} {
		if !strings.Contains(out, want) {
			t.Fatalf("rotate output %q, want %q", out, want)
		}
	}
	if out := c.mustRun("key", "rotate"); strings.Count(out, ": 0 rows rewritten\n") != 9 {
		t.Fatalf("second rotate output %q, want nothing rewritten", out)
	}
	if status := c.mustRun("key", "status"); !strings.Contains(status, "total: 0 rows under old key ids") ||
		!strings.Contains(status, "service_observations: 2 rows under current key, 0 rows under old key ids") {
		t.Fatalf("status after rotate %q", status)
	}

	delete(c.env, "ASI_MASTER_KEY_PREVIOUS")
	raw, _ := base64.StdEncoding.DecodeString(rotatedKey)
	only, err := store.NewKeyring(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.st.CheckKeys(ctx, only); err != nil {
		t.Fatalf("CheckKeys with only the new key: %v", err)
	}
	exp := c.export("")
	h, ok := hostByAddr(exp, "192.0.2.1")
	if !ok || h.Notes != "rack 4, ask Jan" || len(h.Services) != 1 || h.Services[0].HTTP == nil || len(h.Services[0].HTTP.Headers) == 0 ||
		len(h.Services[0].Findings) != 1 {
		t.Fatalf("export with only the new key: %+v", h)
	}
	rows, err := c.st.Pool.Query(ctx, `SELECT http_body FROM service_observations WHERE http_body IS NOT NULL`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			t.Fatal(err)
		}
		if plain, err := only.Decrypt(b); err != nil || !bytes.Contains(plain, []byte("<title>")) {
			t.Fatalf("body with only the new key: %q, %v", plain, err)
		}
	}
	rows.Close()
	settings, err := defectdojo.DBStore{DB: c.st, Keys: only}.Load(ctx)
	if err != nil || settings.Token != dojoToken {
		t.Fatalf("defectdojo token with only the new key: %v", err)
	}
	c.scan("k2")
}
