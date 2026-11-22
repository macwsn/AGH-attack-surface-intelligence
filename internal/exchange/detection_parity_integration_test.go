//go:build integration

package exchange_test

import (
	"context"
	"net/url"
	"reflect"
	"slices"
	"testing"

	"asi/internal/detect"
	"asi/internal/exchange"
	"asi/internal/inventory"
)

func packSignatures(t *testing.T) *detect.Set {
	t.Helper()
	sigs, err := detect.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return &detect.Set{Signatures: sigs}
}

type detected struct {
	techs    []string
	findings []string
}

func detectedOn(t *testing.T, inv *inventory.Inventory, addr string) map[int]detected {
	t.Helper()
	exp, err := inv.Export(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	out := map[int]detected{}
	for _, h := range exp.Hosts {
		if h.Address != addr {
			continue
		}
		for _, s := range h.Services {
			var d detected
			for _, tc := range s.Technologies {
				d.techs = append(d.techs, tc.Name+" "+tc.Version)
			}
			for _, f := range s.Findings {
				d.findings = append(d.findings, f.SignatureID)
			}
			slices.Sort(d.techs)
			slices.Sort(d.findings)
			out[s.Port] = d
		}
	}
	return out
}

// REQ-EXCHANGE-001 AC1: a service entered by form, imported from CSV or imported from JSON is processed like a
// scanned one: product nginx 1.14.0 and Apache httpd 2.2.15 give technologies and outdated findings.
func TestEnteredAndImportedServicesGetSameDetectionAsScanned(t *testing.T) {
	inv, _ := openInventory(t)
	ctx := context.Background()
	sigs := packSignatures(t)
	opts := func(src inventory.RunSource) exchange.Options {
		return exchange.Options{Source: src, Signatures: sigs, ReplaceUserFields: true}
	}

	form := url.Values{"address": {"10.80.0.1"},
		"port": {"80", "8080"}, "protocol": {"tcp", "tcp"}, "service": {"http", "http"},
		"product": {"nginx", "Apache httpd"}, "version": {"1.14.0", "2.2.15"}}
	if _, err := exchange.Apply(ctx, inv, exchange.HostFormFrom(form).Batch(), opts(inventory.SourceManual)); err != nil {
		t.Fatalf("form: %v", err)
	}
	csvData := "address,port,protocol,service,product,version\n" +
		"10.80.0.2,80,tcp,http,nginx,1.14.0\n" +
		"10.80.0.2,8080,tcp,http,Apache httpd,2.2.15\n"
	b, err := exchange.ParseCSV([]byte(csvData))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exchange.Apply(ctx, inv, b, opts(inventory.SourceImport)); err != nil {
		t.Fatalf("csv: %v", err)
	}
	jsonData := `{"schema":"asi.export/v1","hosts":[{"address":"10.80.0.3","services":[
		{"port":80,"protocol":"tcp","service":"http","product":"nginx","version":"1.14.0"},
		{"port":8080,"protocol":"tcp","service":"http","product":"Apache httpd","version":"2.2.15"}]}]}`
	if b, err = exchange.ParseJSON([]byte(jsonData)); err != nil {
		t.Fatal(err)
	}
	if _, err := exchange.Apply(ctx, inv, b, opts(inventory.SourceImport)); err != nil {
		t.Fatalf("json: %v", err)
	}

	want := map[int]detected{
		80:   {techs: []string{"nginx 1.14.0"}, findings: []string{"outdated-nginx"}},
		8080: {techs: []string{"Apache 2.2.15"}, findings: []string{"outdated-apache"}},
	}
	for _, c := range []struct{ path, addr string }{{"form", "10.80.0.1"}, {"csv", "10.80.0.2"}, {"json", "10.80.0.3"}} {
		got := detectedOn(t, inv, c.addr)
		for port, w := range want {
			g := got[port]
			if !reflect.DeepEqual(g.techs, w.techs) || !reflect.DeepEqual(g.findings, w.findings) {
				t.Errorf("%s %d/tcp: technologies %q findings %q, want technologies %q findings %q",
					c.path, port, g.techs, g.findings, w.techs, w.findings)
			}
		}
	}
}

// REQ-EXCHANGE-001 AC1: an imported service whose stored headers reveal PHP 5.6.40 gets the outdated finding a
// scanned service with the same headers gets.
func TestImportedJSONWithOldPHPGetsOutdatedFinding(t *testing.T) {
	inv, _ := openInventory(t)
	ctx := context.Background()
	jsonData := `{"schema":"asi.export/v1","hosts":[{"address":"10.80.0.4","services":[
		{"port":80,"protocol":"tcp","service":"http",
		 "http":{"scheme":"http","status_code":200,"title":"ok","headers":{"X-Powered-By":"PHP/5.6.40"}}}]}]}`
	b, err := exchange.ParseJSON([]byte(jsonData))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exchange.Apply(ctx, inv, b, exchange.Options{Signatures: packSignatures(t)}); err != nil {
		t.Fatal(err)
	}
	g := detectedOn(t, inv, "10.80.0.4")[80]
	if !slices.Contains(g.techs, "PHP 5.6.40") || !slices.Contains(g.findings, "outdated-php") {
		t.Errorf("imported PHP 5.6.40: technologies %q findings %q, want PHP 5.6.40 with finding outdated-php", g.techs, g.findings)
	}
}
