package nmaptest

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"asi/internal/scan/nmap"
)

func TestRunner(t *testing.T) {
	boom := errors.New("boom")
	r := &Runner{
		DiscoverFunc: func(_ context.Context, addrs []string, _ nmap.Options) ([]nmap.Host, error) {
			return []nmap.Host{{Address: addrs[0], Up: true}}, nil
		},
		ServicesFunc: func(context.Context, []string, []int, nmap.Options) ([]nmap.Host, error) {
			return nil, boom
		},
	}
	var runner nmap.Runner = r
	hosts, err := runner.Discover(context.Background(), []string{"192.0.2.1"}, nmap.Options{MaxRate: 5})
	if err != nil || len(hosts) != 1 || hosts[0].Address != "192.0.2.1" {
		t.Fatalf("Discover = %+v, %v", hosts, err)
	}
	if _, err := runner.Services(context.Background(), []string{"192.0.2.1"}, []int{443}, nmap.Options{}); !errors.Is(err, boom) {
		t.Fatalf("Services err = %v", err)
	}
	want := []Call{
		{Method: "Discover", Addrs: []string{"192.0.2.1"}, Opts: nmap.Options{MaxRate: 5}},
		{Method: "Services", Addrs: []string{"192.0.2.1"}, Ports: []int{443}},
	}
	if got := r.Calls(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Calls = %+v, want %+v", got, want)
	}
	if hosts, err := (&Runner{}).Services(context.Background(), nil, nil, nmap.Options{}); hosts != nil || err != nil {
		t.Fatalf("zero Runner = %+v, %v", hosts, err)
	}
}
