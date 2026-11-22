package diff

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"asi/internal/inventory"
)

// REQ-DIFF-008
func TestCount(t *testing.T) {
	port := 80
	d := Diff{From: "a", To: "b", Changes: []Change{
		{Type: HostNew}, {Type: ServiceNew, Port: &port}, {Type: HostReturned}, {Type: ServiceReturned, Port: &port},
		{Type: HostMissing}, {Type: ServiceMissing, Port: &port}, {Type: HostInactive}, {Type: ServiceInactive, Port: &port},
		{Type: ServiceInactive, Port: &port},
		{Type: ServiceChanged, Port: &port},
	}}
	if got, want := Count(d), (RunCounts{From: "a", To: "b", New: 4, Missing: 5, Changed: 1}); got != want {
		t.Fatalf("Count = %+v, want %+v", got, want)
	}
	if got := Count(Diff{From: "a", To: "a", Changes: []Change{}}); got != (RunCounts{From: "a", To: "a"}) {
		t.Fatalf("empty Count = %+v", got)
	}
}

// REQ-DIFF-008
func TestSeries(t *testing.T) {
	src := exports{}
	var names []string
	for i := 0; i < 22; i++ {
		name := fmt.Sprintf("r%02d", i)
		var hosts []inventory.ExportHost
		for j := 0; j <= i%3; j++ {
			hosts = append(hosts, inventory.ExportHost{Address: fmt.Sprintf("10.0.0.%d", j+1), Status: inventory.StatusActive})
		}
		src[name] = inventory.Export{Run: name, Hosts: hosts}
		names = append(names, name)
	}
	ctx := context.Background()
	series, err := Series(ctx, src, names, ChartRuns, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(series) != 20 || series[0].From != "r01" || series[0].To != "r02" || series[19].To != "r21" {
		t.Fatalf("series = %+v, want 20 pairs r01..r21", series)
	}
	for _, c := range series {
		d, err := Between(ctx, src, c.From, c.To, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if want := Count(d); !reflect.DeepEqual(c, want) {
			t.Errorf("%s..%s = %+v, want %+v", c.From, c.To, c, want)
		}
	}
	if series[0].New != 1 {
		t.Errorf("r01..r02 new = %d, want 1", series[0].New)
	}
	for _, n := range []int{0, 1} {
		if s, err := Series(ctx, src, names[:n], ChartRuns, Options{}); err != nil || len(s) != 0 {
			t.Errorf("Series of %d runs = %+v, %v; want empty", n, s, err)
		}
	}
	if s, err := Series(ctx, src, names[:4], ChartRuns, Options{}); err != nil || len(s) != 3 {
		t.Errorf("Series of 4 runs = %+v, %v; want 3 entries", s, err)
	}
	if _, err := Series(ctx, src, []string{"r00", "nope"}, ChartRuns, Options{}); err == nil || err.Error() != `unknown run "nope"` {
		t.Errorf("unknown run error = %v", err)
	}
}
