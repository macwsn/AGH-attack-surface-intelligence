//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"asi/internal/diff"
	"asi/internal/scan/scantest"
)

func (c *cliEnv) runHandler(h http.HandlerFunc, args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	tr := &scantest.Transport{Handler: h}
	code := runWith(context.Background(), scanDeps{runner: c.net.runner(), transport: tr.For}, args, strings.NewReader(""), &stdout, &stderr, func(k string) string { return c.env[k] })
	return code, stdout.String(), stderr.String()
}

func (c *cliEnv) diffDoc(from, to string) diff.Diff {
	c.t.Helper()
	out := filepath.Join(c.dir, "diff-"+from+"-"+to+".json")
	c.mustRun("diff", "--from", from, "--to", to, "--format", "json", "--out", out)
	raw, err := os.ReadFile(out)
	if err != nil {
		c.t.Fatal(err)
	}
	var d diff.Diff
	if err := json.Unmarshal(raw, &d); err != nil {
		c.t.Fatalf("decode diff: %v\n%s", err, raw)
	}
	return d
}

func TestReproReportedConfidenceIsMultipliedByStability(t *testing.T) {
	c := newCLIEnv(t, "192.0.2.0/29", "192.0.2.0")
	nginx := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.27.5")
		fmt.Fprint(w, "<html><title>web</title></html>")
	}
	c.net.up("192.0.2.1", 80)
	c.net.up("192.0.2.2", 80)
	for _, name := range []string{"c1", "c2", "c3"} {
		if name == "c2" {
			c.net.down("192.0.2.1")
		} else {
			c.net.up("192.0.2.1", 80)
		}
		if code, _, stderr := c.runHandler(nginx, c.scanArgs(name)...); code != 0 {
			t.Fatalf("scan %s: exit %d, stderr %q", name, code, stderr)
		}
	}
	h, ok := hostByAddr(c.export(""), "192.0.2.1")
	if !ok || len(h.Services) != 1 {
		t.Fatalf("host = %+v", h)
	}
	if h.Stability <= 0 || h.Stability >= 1 {
		t.Fatalf("stability = %v, want between 0 and 1 after missing one of three runs", h.Stability)
	}
	found := false
	for _, tech := range h.Services[0].Technologies {
		if tech.Name != "nginx" {
			continue
		}
		found = true
		want := int(math.Round(90 * h.Stability))
		if tech.Confidence != want {
			t.Errorf("exported nginx confidence = %d, want detected 90 x stability %.2f = %d", tech.Confidence, h.Stability, want)
		}
	}
	if !found {
		t.Fatalf("no nginx technology in %+v", h.Services[0].Technologies)
	}
}

func TestReproVolatileHeadersFromConfigurationNeverProduceAChange(t *testing.T) {
	c := newCLIEnv(t, "192.0.2.0/29", "192.0.2.0")
	c.env["ASI_VOLATILE_HEADERS"] = "X-Trace-Id, x-backend-node"
	var n atomic.Int64
	varying := func(w http.ResponseWriter, r *http.Request) {
		i := n.Add(1)
		w.Header().Set("X-Trace-Id", fmt.Sprintf("trace-%d", i))
		w.Header().Set("X-Backend-Node", fmt.Sprintf("node-%d", i))
		fmt.Fprint(w, "<html><title>stable</title></html>")
	}
	c.net.up("192.0.2.1", 80)
	for _, name := range []string{"v1", "v2"} {
		if code, _, stderr := c.runHandler(varying, c.scanArgs(name)...); code != 0 {
			t.Fatalf("scan %s: exit %d, stderr %q", name, code, stderr)
		}
	}
	for _, ch := range c.diffDoc("v1", "v2").Changes {
		for _, f := range ch.Fields {
			if f.Field == "http.headers.x-trace-id" || f.Field == "http.headers.x-backend-node" {
				t.Errorf("header listed in ASI_VOLATILE_HEADERS produced a change: %+v", f)
			}
		}
	}
}

func TestReproScanRunWithClashingSignaturesDirLeavesNoRun(t *testing.T) {
	c := newCLIEnv(t, "192.0.2.0/29", "192.0.2.0")
	c.net.up("192.0.2.1", 80)
	dir := filepath.Join(c.dir, "sigs")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "clash.yaml"), []byte("- {id: builtin-grafana, name: Clash, kind: custom, confidence: 1, match: {all: [{type: status, value: 200}]}}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := countRuns(t, c.st)
	code, _, stderr := c.run(c.scanArgs("clash", "--signatures-dir", dir)...)
	if code == 0 {
		t.Fatalf("scan run with a signature id clashing with a built-in exited 0, stderr %q", stderr)
	}
	if after := countRuns(t, c.st); after != before {
		t.Fatalf("scan run with an invalid --signatures-dir left %d run(s) behind (stderr %q)", after-before, stderr)
	}
}

func TestReproImportedHostNotCoveredByScanIsNotReportedByScanDiff(t *testing.T) {
	src := newCLIEnv(t, "198.51.100.0/29", "198.51.100.0")
	src.net.up("198.51.100.5", 80)
	src.scan("elsewhere")
	file := filepath.Join(src.dir, "export.json")
	src.mustRun("export", "--format", "json", "--out", file)

	c := newCLIEnv(t, "192.0.2.0/29", "192.0.2.0")
	c.net.up("192.0.2.1", 80)
	c.scan("s1")
	c.mustRun("import", "--format", "json", "--file", file, "--name", "imp")
	c.scan("s2")
	for _, ch := range c.diffDoc("s1", "s2").Changes {
		if ch.Address == "198.51.100.5" {
			t.Errorf("diff s1..s2 reports imported host never covered by a scan: %+v", ch)
		}
	}
}

func TestReproHostEditPrintsEveryChangedField(t *testing.T) {
	c := newCLIEnv(t, "192.0.2.0/29", "192.0.2.0")
	c.net.up("192.0.2.1", 80)
	c.scan("e1")
	out := c.mustRun("host", "edit", "192.0.2.1", "--add-tag", "a", "--notes", "owned by web team")
	if !strings.Contains(out, "tags=") || !strings.Contains(out, "notes=") || !strings.Contains(out, "owned by web team") {
		t.Fatalf("host edit stdout = %q, want the changed tags and notes", out)
	}
}
