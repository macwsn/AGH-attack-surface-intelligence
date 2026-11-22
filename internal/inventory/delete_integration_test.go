//go:build integration

package inventory

import (
	"context"
	"errors"
	"testing"
)

func deleteAudit(t *testing.T, inv *Inventory, action string) []string {
	t.Helper()
	rows, err := inv.db.Pool.Query(context.Background(),
		`SELECT actor || ' ' || target || ' ' || address FROM audit_log WHERE action = $1 ORDER BY id`, action)
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

func hostRows(t *testing.T, inv *Inventory, table, address string) int {
	t.Helper()
	q := map[string]string{
		"hosts":                `SELECT count(*) FROM hosts WHERE address = $1`,
		"services":             `SELECT count(*) FROM services s JOIN hosts h ON h.id = s.host_id WHERE h.address = $1`,
		"host_observations":    `SELECT count(*) FROM host_observations o JOIN hosts h ON h.id = o.host_id WHERE h.address = $1`,
		"service_observations": `SELECT count(*) FROM service_observations o JOIN services s ON s.id = o.service_id JOIN hosts h ON h.id = s.host_id WHERE h.address = $1`,
	}[table]
	var n int
	if err := inv.db.Pool.QueryRow(context.Background(), q, address).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// REQ-INVENTORY-028
func TestDeleteHostAndService(t *testing.T) {
	ctx := context.Background()
	inv, s := openInventory(t)
	r := mustRun(t, inv, "d1", 3)
	ssh := ServiceResult{Port: 22, Protocol: "tcp", State: "open", Service: "ssh"}
	mustRecord(t, inv, r, GroupResult{Index: 0, Hosts: []HostResult{
		{Address: "10.4.0.1", Services: []ServiceResult{webService("Panel"), ssh}},
		{Address: "10.4.0.2", Services: []ServiceResult{ssh}},
	}})
	before := rowCounts(t, s)
	ed := Editor{Username: "eddie", Addr: "192.0.2.9"}

	if err := inv.DeleteService(ctx, ed, "10.4.0.1", 443, "tcp"); err != nil {
		t.Fatalf("DeleteService: %v", err)
	}
	h := findHost(t, mustExport(t, inv, "d1"), "10.4.0.1")
	if len(h.Services) != 1 || h.Services[0].Port != 22 {
		t.Fatalf("services after deleting 443/tcp = %+v, want only 22/tcp", h.Services)
	}
	if got := deleteAudit(t, inv, "service.delete"); len(got) != 1 || got[0] != "eddie 10.4.0.1:443/tcp 192.0.2.9" {
		t.Fatalf("service.delete audit = %q", got)
	}
	after := rowCounts(t, s)
	for _, table := range []string{"technologies", "findings"} {
		if before[table] == 0 || after[table] != 0 {
			t.Errorf("%s rows %d -> %d, want the deleted service's rows gone", table, before[table], after[table])
		}
	}

	if err := inv.DeleteHost(ctx, ed, "10.4.0.1"); err != nil {
		t.Fatalf("DeleteHost: %v", err)
	}
	for _, table := range []string{"hosts", "services", "host_observations", "service_observations"} {
		if n := hostRows(t, inv, table, "10.4.0.1"); n != 0 {
			t.Errorf("%s rows of the deleted host = %d, want 0", table, n)
		}
	}
	if _, err := inv.HostDetail(ctx, "10.4.0.1"); !errors.Is(err, ErrUnknownHost) {
		t.Fatalf("HostDetail after delete err = %v, want ErrUnknownHost", err)
	}
	if n := hostRows(t, inv, "services", "10.4.0.2"); n != 1 {
		t.Fatalf("other host lost services: %d", n)
	}
	if got := deleteAudit(t, inv, "host.delete"); len(got) != 1 || got[0] != "eddie 10.4.0.1 192.0.2.9" {
		t.Fatalf("host.delete audit = %q", got)
	}

	for name, err := range map[string]error{
		"unknown host":            inv.DeleteHost(ctx, ed, "10.4.0.1"),
		"invalid address":         inv.DeleteHost(ctx, ed, "nope"),
		"service of unknown host": inv.DeleteService(ctx, ed, "10.4.0.9", 22, "tcp"),
		"unknown service":         inv.DeleteService(ctx, ed, "10.4.0.2", 443, "tcp"),
	} {
		if err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if err := inv.DeleteService(ctx, ed, "10.4.0.2", 443, "tcp"); !errors.Is(err, ErrUnknownService) {
		t.Errorf("unknown service err = %v, want ErrUnknownService", err)
	}
	if err := inv.DeleteHost(ctx, ed, "10.4.0.1"); !errors.Is(err, ErrUnknownHost) {
		t.Errorf("unknown host err = %v, want ErrUnknownHost", err)
	}
	if n := len(deleteAudit(t, inv, "host.delete")) + len(deleteAudit(t, inv, "service.delete")); n != 2 {
		t.Errorf("audit rows = %d; failed deletes must not be audited", n)
	}
}

// REQ-INVENTORY-029
func TestDeletedHostReturnsAsNew(t *testing.T) {
	ctx := context.Background()
	inv, _ := openInventory(t)
	host := HostResult{Address: "10.5.0.1", Services: []ServiceResult{{Port: 22, Protocol: "tcp", State: "open", Service: "ssh"}}}
	r1 := mustRun(t, inv, "n1", 3)
	mustRecord(t, inv, r1, GroupResult{Index: 0, Addresses: []string{"10.5.0.1"}, Hosts: []HostResult{host}})
	r2 := mustRun(t, inv, "n2", 3)
	mustRecord(t, inv, r2, GroupResult{Index: 0, Addresses: []string{"10.5.0.1"}, Hosts: []HostResult{host}})
	first := findHost(t, mustExport(t, inv, "n2"), "10.5.0.1").FirstSeen

	if err := inv.DeleteHost(ctx, Editor{Username: "eddie"}, "10.5.0.1"); err != nil {
		t.Fatalf("DeleteHost: %v", err)
	}
	for _, run := range []string{"n1", "n2"} {
		for _, h := range mustExport(t, inv, run).Hosts {
			if h.Address == "10.5.0.1" {
				t.Fatalf("export of %s still has the deleted host", run)
			}
		}
	}
	r3 := mustRun(t, inv, "n3", 3)
	mustRecord(t, inv, r3, GroupResult{Index: 0, Addresses: []string{"10.5.0.1"}, Hosts: []HostResult{host}})
	d, err := inv.HostDetail(ctx, "10.5.0.1")
	if err != nil {
		t.Fatalf("HostDetail: %v", err)
	}
	if d.Run != "n3" || !d.Host.FirstSeen.After(first) || d.Host.MissedRuns != 0 || len(d.Host.Services) != 1 {
		t.Fatalf("returned host = run %s first seen %v (before delete %v), %d services; want a new host first seen in n3",
			d.Run, d.Host.FirstSeen, first, len(d.Host.Services))
	}
	if s := d.Host.Services[0]; !s.FirstSeen.Equal(d.Host.FirstSeen) {
		t.Fatalf("service first seen %v, host first seen %v; want both from n3", s.FirstSeen, d.Host.FirstSeen)
	}
}
