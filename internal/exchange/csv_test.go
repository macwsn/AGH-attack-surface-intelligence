package exchange

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"
	"time"

	"asi/internal/inventory"
	"asi/internal/probe"
)

func TestCSVExport(t *testing.T) {
	ts := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	exp := inventory.Export{Hosts: []inventory.ExportHost{
		{
			Address: "10.0.0.1", Hostnames: []string{"a.example", "b.example"}, Status: "active",
			Tags: []string{"crown", "x"}, FirstSeen: ts, LastSeen: ts,
			Services: []inventory.ExportService{
				{Port: 80, Protocol: "tcp", Service: "http", Product: "nginx", Version: "1.2", Status: "unstable",
					FirstSeen: ts, LastSeen: ts,
					HTTP: &probe.HTTP{Scheme: "http", StatusCode: 200, Title: "Hello, \"world\"\nline2",
						Cookies: []probe.Cookie{{Name: "sid"}}, Headers: map[string]string{"set-cookie": "sid=SECRETVALUE"}},
					Technologies: []inventory.Technology{{Name: "nginx", Version: "1.2"}, {Name: "PHP"}},
					Findings:     []inventory.Finding{{SignatureID: "sig-a"}, {SignatureID: "sig-b"}}},
				{Port: 22, Protocol: "tcp", Service: "ssh"},
			},
		},
		{Address: "10.0.0.2", Status: "inactive", FirstSeen: ts, LastSeen: ts},
	}}
	var buf bytes.Buffer
	if err := WriteCSV(&buf, exp); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "SECRETVALUE") {
		t.Fatal("cookie value leaked")
	}
	if !strings.HasPrefix(buf.String(), strings.Join(CSVHeader, ",")+"\n") {
		t.Fatalf("bad header: %q", buf.String())
	}
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 4 {
		t.Fatalf("rows = %d, want 4", len(rows))
	}
	col := map[string]int{}
	for i, h := range rows[0] {
		col[h] = i
	}
	r := rows[1]
	want := map[string]string{
		"address": "10.0.0.1", "hostnames": "a.example;b.example", "status": "active", "port": "80",
		"protocol": "tcp", "service": "http", "product": "nginx", "version": "1.2", "scheme": "http",
		"status_code": "200", "title": "Hello, \"world\"\nline2", "technologies": "nginx:1.2;PHP",
		"findings": "sig-a;sig-b", "tags": "crown;x", "first_seen": "2026-01-02T03:04:05Z", "last_seen": "2026-01-02T03:04:05Z",
	}
	for k, v := range want {
		if r[col[k]] != v {
			t.Errorf("%s = %q, want %q", k, r[col[k]], v)
		}
	}
	if rows[2][col["port"]] != "22" || rows[2][col["status_code"]] != "" {
		t.Errorf("ssh row = %v", rows[2])
	}
	e := rows[3]
	if e[col["address"]] != "10.0.0.2" || e[col["status"]] != "inactive" || e[col["port"]] != "" || e[col["protocol"]] != "" || e[col["service"]] != "" {
		t.Errorf("host without services row = %v", e)
	}
}
