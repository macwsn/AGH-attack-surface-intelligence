package exchange

import (
	"bytes"
	"encoding/csv"
	"errors"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"asi/internal/inventory"
	"asi/internal/probe"
)

// REQ-EXCHANGE-001 REQ-EXCHANGE-002 AC3
func TestParseCSVReportsInvalidRowsAndKeepsValidOnes(t *testing.T) {
	data := "address,hostnames,port,protocol,service,title,technologies,findings,tags\n" +
		"10.0.0.1,A.example.;b.example,80,TCP,http,'=Home,nginx:1.2;PHP,sig-a,crown\n" +
		"10.0.0.300,,80,tcp,http,,,,\n" +
		"10.0.0.1,,22,,ssh,,,,x\n" +
		"10.0.0.2,,abc,,,,,,\n" +
		"10.0.0.1,,80,tcp,http,,,,\n" +
		"10.0.0.3,,70000,,,,,,\n" +
		"10.0.0.4,,,,ssh,,,,\n" +
		"10.0.0.5,,,,,,,,\n" +
		"10.0.0.6,,80,ftp,,,,,\n"
	b, err := ParseCSV([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	want := []RowError{
		{3, `"10.0.0.300" is not an address.`},
		{5, `"abc" is not a port.`},
		{6, "Service 80/tcp of 10.0.0.1 is listed twice (first in row 2)."},
		{7, "port 70000 is out of range 1-65535."},
		{8, "service is set but port is empty."},
		{10, `"ftp" is not a protocol (tcp, udp or sctp).`},
	}
	if !reflect.DeepEqual(b.Errors, want) {
		t.Errorf("errors = %#v\nwant %#v", b.Errors, want)
	}
	if len(b.Entries) != 2 {
		t.Fatalf("entries = %+v, want 10.0.0.1 and 10.0.0.5", b.Entries)
	}
	h := b.Entries[0]
	if h.Host.Address != "10.0.0.1" || !reflect.DeepEqual(h.Host.Hostnames, []string{"a.example", "b.example"}) ||
		!reflect.DeepEqual(h.User.Tags, []string{"crown", "x"}) || len(h.Host.Services) != 2 {
		t.Fatalf("10.0.0.1 = %+v", h)
	}
	web := h.Host.Services[0]
	if web.Protocol != "tcp" || web.State != "open" || web.HTTP == nil || web.HTTP.Title != "=Home" ||
		!reflect.DeepEqual(web.Technologies, []inventory.Technology{{Name: "nginx", Version: "1.2", Source: "import"}, {Name: "PHP", Source: "import"}}) ||
		!reflect.DeepEqual(web.Findings, []inventory.Finding{{SignatureID: "sig-a"}}) {
		t.Errorf("80/tcp = %+v http %+v", web, web.HTTP)
	}
	if b.Entries[1].Host.Address != "10.0.0.5" || len(b.Entries[1].Host.Services) != 0 {
		t.Errorf("targets row = %+v", b.Entries[1])
	}
}

// REQ-EXCHANGE-001
func TestParseCSVNeedsAddressColumn(t *testing.T) {
	if _, err := ParseCSV([]byte("host,port\n10.0.0.1,80\n")); err == nil || !strings.Contains(err.Error(), "address") {
		t.Fatalf("err = %v", err)
	}
}

// REQ-EXCHANGE-001 REQ-EXCHANGE-002
func TestParseJSON(t *testing.T) {
	data := `{"schema":"asi.export/v1","hosts":[
		{"address":"10.0.0.1","status":"active","first_seen":"2026-01-01T00:00:00Z","tags":["a"],"services":[
			{"port":443,"protocol":"tcp","service":"http","http":{"scheme":"HTTPS","status_code":200,"headers":{"Server":"nginx","set-cookie":"sid=SECRET"}},
			 "technologies":[{"name":"nginx","confidence":90,"source":"builtin"}],"findings":[{"signature_id":"x","confidence":80}]}]},
		{"address":"nope"},
		{"address":"10.0.0.1"},
		{"address":"10.0.0.2","services":[{"port":0}]},
		{"address":"10.0.0.3","services":"bad"},
		{"address":"10.0.0.4","services":[{"port":80,"technologies":[{"name":"x","confidence":101}]}]}
	]}`
	b, err := ParseJSON([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	rows := []int{}
	for _, e := range b.Errors {
		rows = append(rows, e.Row)
	}
	if !reflect.DeepEqual(rows, []int{2, 3, 4, 5, 6}) || b.Errors[1].Reason != `"10.0.0.1" is listed twice (first in row 1).` {
		t.Fatalf("errors = %+v", b.Errors)
	}
	if len(b.Entries) != 1 {
		t.Fatalf("entries = %+v", b.Entries)
	}
	s := b.Entries[0].Host.Services[0]
	if s.HTTP.Scheme != "https" || !reflect.DeepEqual(s.HTTP.Headers, map[string]string{"server": "nginx"}) ||
		s.HTTP.Cookies == nil || s.HTTP.RedirectChain == nil {
		t.Errorf("http = %+v", s.HTTP)
	}
	for _, bad := range []string{`{"schema":"other/v1","hosts":[]}`, `not json`} {
		if _, err := ParseJSON([]byte(bad)); err == nil {
			t.Errorf("ParseJSON(%s) succeeded", bad)
		}
	}
}

// REQ-EXCHANGE-007 AC4
func TestReadAllLimitsTo20MiB(t *testing.T) {
	if MaxUploadBytes != 20<<20 {
		t.Fatalf("MaxUploadBytes = %d", MaxUploadBytes)
	}
	data, err := ReadAll(bytes.NewReader(make([]byte, MaxUploadBytes)))
	if err != nil || len(data) != MaxUploadBytes {
		t.Fatalf("20 MiB: len %d err %v", len(data), err)
	}
	if _, err := ReadAll(bytes.NewReader(make([]byte, MaxUploadBytes+1))); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("20 MiB + 1: err %v, want ErrTooLarge", err)
	}
}

// REQ-EXCHANGE-007 AC4
func TestCSVExportNeutralisesFormulas(t *testing.T) {
	exp := inventory.Export{Hosts: []inventory.ExportHost{{
		Address: "10.0.0.1", Hostnames: []string{"=evil.example"}, Status: "active", Tags: []string{"@SUM(A1)"},
		Services: []inventory.ExportService{{Port: 80, Protocol: "tcp", Service: "+http", Product: "-nginx", Version: "\t1",
			HTTP:         &probe.HTTP{Scheme: "http", Title: `=HYPERLINK("http://evil.example","x")`},
			Technologies: []inventory.Technology{{Name: "=cmd|' /C calc'!A0"}}}},
	}}}
	var buf bytes.Buffer
	if err := WriteCSV(&buf, exp); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(bytes.NewReader(buf.Bytes())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	for _, cell := range rows[1] {
		if cell != "" && strings.ContainsRune("=+-@\t\r", rune(cell[0])) {
			t.Errorf("cell %q starts with a formula character", cell)
		}
	}
	col := map[string]int{}
	for i, h := range rows[0] {
		col[h] = i
	}
	if got := rows[1][col["title"]]; got != `'=HYPERLINK("http://evil.example","x")` {
		t.Errorf("title = %q", got)
	}
	b, err := ParseCSV(buf.Bytes())
	if err != nil || len(b.Entries) != 1 {
		t.Fatalf("re-import: %+v %v", b, err)
	}
	if s := b.Entries[0].Host.Services[0]; s.HTTP.Title != `=HYPERLINK("http://evil.example","x")` || s.Product != "-nginx" ||
		b.Entries[0].User.Tags[0] != "@SUM(A1)" {
		t.Errorf("re-imported values = %+v %+v", s, b.Entries[0].User)
	}
}

// REQ-EXCHANGE-008 AC2
func TestHostFormUsesTheCSVRowPath(t *testing.T) {
	form := url.Values{
		"address": {" 10.0.0.9 "}, "hostnames": {"a.example, B.example"}, "tags": {"crown, dmz"}, "notes": {"owner: web team"},
		"port": {"80", "", "22", "x"}, "protocol": {"", "", "tcp", ""}, "service": {"http", "", "ssh", ""},
		"product": {"nginx", "", "", ""}, "version": {"1.2", "", "", ""}, "scheme": {"http", "", "", ""},
		"status_code": {"200", "", "", ""}, "title": {"Shop", "", "", ""}, "technologies": {"nginx:1.2", "", "", ""},
		"findings": {"", "", "", ""},
	}
	got := HostFormFrom(form).Batch()
	csvData := "address,hostnames,tags,notes,port,protocol,service,product,version,scheme,status_code,title,technologies\n" +
		"10.0.0.9,a.example;B.example,crown;dmz,owner: web team,80,,http,nginx,1.2,http,200,Shop,nginx:1.2\n" +
		"10.0.0.9,,,,22,tcp,ssh,,,,,,\n"
	want, err := ParseCSV([]byte(csvData))
	if err != nil {
		t.Fatal(err)
	}
	for i := range want.Entries {
		want.Entries[i].Row--
	}
	if !reflect.DeepEqual(got.Entries, want.Entries) {
		t.Errorf("form entries = %+v\ncsv entries = %+v", got.Entries, want.Entries)
	}
	if !reflect.DeepEqual(got.Errors, []RowError{{4, `"x" is not a port.`}}) {
		t.Errorf("form errors = %+v", got.Errors)
	}
	host := HostFormFrom(url.Values{"address": {"10.0.0.9"}, "port": {""}}).Batch()
	if len(host.Entries) != 1 || len(host.Entries[0].Host.Services) != 0 {
		t.Errorf("host without services = %+v", host)
	}
}

// REQ-EXCHANGE-008 AC6
func TestFilter(t *testing.T) {
	exp := inventory.Export{Hosts: []inventory.ExportHost{
		{Address: "10.0.0.1", Status: "active", Tags: []string{"dmz"}, Hostnames: []string{"Shop.example"}},
		{Address: "10.0.0.2", Status: "inactive"},
		{Address: "10.0.1.3", Status: "active"},
	}}
	addrs := func(e inventory.Export) []string {
		out := []string{}
		for _, h := range e.Hosts {
			out = append(out, h.Address)
		}
		return out
	}
	for _, tc := range []struct {
		f    Filter
		want []string
	}{
		{Filter{}, []string{"10.0.0.1", "10.0.0.2", "10.0.1.3"}},
		{Filter{Status: "active"}, []string{"10.0.0.1", "10.0.1.3"}},
		{Filter{Query: "10.0.0."}, []string{"10.0.0.1", "10.0.0.2"}},
		{Filter{Query: "shop"}, []string{"10.0.0.1"}},
		{Filter{Tag: "dmz"}, []string{"10.0.0.1"}},
	} {
		if got := addrs(tc.f.Apply(exp)); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%+v: %v, want %v", tc.f, got, tc.want)
		}
	}
}

// REQ-EXCHANGE-001 REQ-EXCHANGE-002
func TestParseMarksEntriesNotActiveInTheFile(t *testing.T) {
	j, err := ParseJSON([]byte(`{"schema":"asi.export/v1","hosts":[
		{"address":"10.0.0.1","status":"active","services":[{"port":22,"status":"active"},{"port":80,"protocol":"TCP","status":"unstable"}]},
		{"address":"10.0.0.2","status":"inactive","services":[{"port":22}]},
		{"address":"10.0.0.3"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(j.Entries) != 3 || len(j.Entries[0].Host.Services) != 2 || j.Entries[0].staleHost || !j.Entries[1].staleHost || j.Entries[2].staleHost ||
		!reflect.DeepEqual(j.Entries[0].staleSvc, map[string]bool{"80/tcp": true}) {
		t.Fatalf("json = %+v", j)
	}
	c, err := ParseCSV([]byte("address,status,port\n10.0.0.1,active,22\n10.0.0.2,unstable,22\n10.0.0.3,,80\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Entries) != 3 || c.Entries[0].staleHost || !c.Entries[1].staleHost || c.Entries[2].staleHost {
		t.Fatalf("csv = %+v", c)
	}
}

// REQ-EXCHANGE-002 AC4
func TestRowErrorsAreCapped(t *testing.T) {
	data := "address\n" + strings.Repeat("nope\n", MaxRowErrors+5) + "10.0.0.1\n"
	b, err := ParseCSV([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if b.Invalid != MaxRowErrors+5 || len(b.Errors) != MaxRowErrors || len(b.Entries) != 1 {
		t.Fatalf("invalid %d, listed %d, entries %d", b.Invalid, len(b.Errors), len(b.Entries))
	}
}
