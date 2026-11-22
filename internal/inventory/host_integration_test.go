//go:build integration

package inventory

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"asi/internal/probe"
)

func TestHostDetail(t *testing.T) {
	ctx := context.Background()
	inv, _ := openInventory(t)
	const A, B = "10.2.0.1", "10.2.0.2"
	web := ServiceResult{Port: 443, Protocol: "tcp", State: "open", Service: "http", Product: "nginx", Version: "1.27.5",
		HTTP: &probe.HTTP{Scheme: "https", URL: "https://10.2.0.1/", StatusCode: 200, Title: "Panel",
			Headers: map[string]string{"server": "nginx/1.27.5", "x-debug-token": "abc123"},
			Cookies: []probe.Cookie{{Name: "PHPSESSID", HTTPOnly: true}},
			TLS:     &probe.TLS{SubjectCN: "panel.example", IssuerCN: "panel.example", NotAfter: "2027-01-01T00:00:00Z", SelfSigned: true}},
		Technologies: []Technology{{Name: "nginx", Version: "1.27.5", Confidence: 90, Source: "builtin"}},
		Findings:     []Finding{{SignatureID: "admin-panel-login", Kind: "admin-panel", Name: "Admin login", Confidence: 80, Evidence: "<form action=/login>"}},
	}
	ssh := ServiceResult{Port: 22, Protocol: "tcp", State: "open", Service: "ssh"}
	hostA := HostResult{Address: A, Hostnames: []string{"panel.example"}, Services: []ServiceResult{web, ssh}}
	hostA2 := HostResult{Address: A, Hostnames: []string{"panel.example"}, Services: []ServiceResult{web}}
	hostB := HostResult{Address: B}

	r1 := mustRun(t, inv, "h1", 3)
	mustRecord(t, inv, r1, GroupResult{Index: 0, Addresses: []string{A, B}, Hosts: []HostResult{hostA, hostB}})
	r2 := mustRun(t, inv, "h2", 3)
	mustRecord(t, inv, r2, GroupResult{Index: 0, Addresses: []string{A, B}, Hosts: []HostResult{hostB}})
	r3 := mustRun(t, inv, "h3", 3)
	mustRecord(t, inv, r3, GroupResult{Index: 1, Addresses: []string{"10.2.0.9"}})
	r4 := mustRun(t, inv, "h4", 3)
	mustRecord(t, inv, r4, GroupResult{Index: 0, Addresses: []string{A, B}, Hosts: []HostResult{hostA2, hostB}})

	d, err := inv.HostDetail(ctx, A)
	if err != nil {
		t.Fatalf("HostDetail: %v", err)
	}
	if d.Run != "h4" || d.Host.Address != A || d.Host.Status != StatusActive || len(d.Host.Services) != 2 {
		t.Fatalf("detail = run %q host %+v", d.Run, d.Host)
	}
	s := findService(t, d.Host, 443)
	if s.HTTP == nil || s.HTTP.Headers["x-debug-token"] != "abc123" || s.HTTP.Headers["server"] != "nginx/1.27.5" ||
		s.HTTP.TLS == nil || !s.HTTP.TLS.SelfSigned || s.HTTP.TLS.SubjectCN != "panel.example" {
		t.Errorf("https service = %+v", s.HTTP)
	}
	if len(s.Findings) != 1 || s.Findings[0].Evidence != "<form action=/login>" || len(s.Technologies) != 1 || s.Technologies[0].Confidence != 90 {
		t.Errorf("detections = %+v %+v", s.Technologies, s.Findings)
	}
	if old := findService(t, d.Host, 22); old.Status != StatusUnstable || old.MissedRuns != 2 {
		t.Errorf("ssh service = %s/%d, want unstable/2", old.Status, old.MissedRuns)
	}

	var got []HostRunEntry
	for _, e := range d.History {
		got = append(got, HostRunEntry{Run: e.Run, Seen: e.Seen, Services: e.Services})
	}
	want := []HostRunEntry{
		{Run: "h4", Seen: true, Services: []string{"443/tcp"}},
		{Run: "h2", Seen: false, Services: []string{}},
		{Run: "h1", Seen: true, Services: []string{"22/tcp", "443/tcp"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("history = %+v, want %+v (one row per covering run, newest first)", got, want)
	}
	for _, e := range d.History {
		if e.StartedAt.IsZero() {
			t.Errorf("history row %s has no date", e.Run)
		}
	}

	for _, addr := range []string{"10.2.0.200", "not-an-address", "10.2.0.9", ""} {
		if _, err := inv.HostDetail(ctx, addr); !errors.Is(err, ErrUnknownHost) {
			t.Errorf("HostDetail(%q) = %v, want ErrUnknownHost", addr, err)
		}
	}
}
