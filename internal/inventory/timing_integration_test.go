//go:build integration

package inventory

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"asi/internal/probe"
)

// REQ-INVENTORY-018
func TestResponseTimesStoredAndSummarised(t *testing.T) {
	inv, _ := openInventory(t)
	ctx := context.Background()
	const addr = "10.0.0.7"
	timed := []int64{100, 120, 90, 110, 100, 95, 105, 2000, 100, 115, 100, 1800}
	for i, ms := range timed {
		r := mustRun(t, inv, fmt.Sprintf("rt-%d", i), 3)
		svcs := []ServiceResult{
			{Port: 22, Protocol: "tcp", State: "open", Service: "ssh"},
			{Port: 80, Protocol: "tcp", State: "open", Service: "http",
				HTTP: &probe.HTTP{Scheme: "http", URL: "http://10.0.0.7/", StatusCode: 200, TTFBMS: ms / 2, ResponseMS: ms}},
			{Port: 8080, Protocol: "tcp", State: "open", Service: "http",
				HTTP: &probe.HTTP{Scheme: "http", URL: "http://10.0.0.7:8080/", ResponseMS: 10000, Error: probe.ErrorTimeout}},
		}
		mustRecord(t, inv, r, GroupResult{Index: 0, Addresses: []string{addr}, Hosts: []HostResult{{Address: addr, Services: svcs}}})
	}

	h := findHost(t, mustExport(t, inv, ""), addr)
	web := findService(t, h, 80)
	if web.HTTP == nil || web.HTTP.ResponseMS != 1800 || web.HTTP.TTFBMS != 900 || web.HTTP.Error != "" {
		t.Errorf("export of :80 http = %+v", web.HTTP)
	}
	stalled := findService(t, h, 8080)
	if stalled.State != "open" || stalled.Status != StatusActive || stalled.HTTP == nil || stalled.HTTP.Error != "timeout" {
		t.Errorf("export of :8080 = %+v http %+v", stalled, stalled.HTTP)
	}
	old := findService(t, findHost(t, mustExport(t, inv, "rt-0"), addr), 80)
	if old.HTTP.ResponseMS != 100 {
		t.Errorf("observation of rt-0 response_time_ms = %d", old.HTTP.ResponseMS)
	}

	got, err := inv.ResponseTimes(ctx, addr)
	if err != nil {
		t.Fatal(err)
	}
	want := []ServiceTiming{
		{Port: 80, Protocol: "tcp", Service: "http", LatestMS: 1800, MedianMS: 102, Runs: 10, Slower: true},
		{Port: 8080, Protocol: "tcp", Service: "http", Error: "timeout", LatestMS: 10000, MedianMS: 10000, Runs: 10},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ResponseTimes = %+v\nwant %+v", got, want)
	}

	if _, err := inv.ResponseTimes(ctx, "10.9.9.9"); !errors.Is(err, ErrUnknownHost) {
		t.Errorf("unknown host err = %v", err)
	}
}
