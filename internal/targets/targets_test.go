package targets

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
)

type fakeResolver map[string][]string

func (f fakeResolver) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	if network != "ip4" {
		return nil, errors.New("unexpected network " + network)
	}
	ips, ok := f[host]
	if !ok {
		return nil, errors.New("no such host")
	}
	var out []netip.Addr
	for _, ip := range ips {
		out = append(out, netip.MustParseAddr(ip))
	}
	return out, nil
}

func mustParse(t *testing.T, text string) []Entry {
	t.Helper()
	entries, err := Parse(strings.NewReader(text))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return entries
}

func build(t *testing.T, targets, excludes string, res Resolver) *Set {
	t.Helper()
	s, err := Build(context.Background(), mustParse(t, targets), mustParse(t, excludes), res)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return s
}

func addrs(s *Set) []string {
	var out []string
	for tg := range s.All() {
		out = append(out, tg.Addr.String())
	}
	return out
}

func TestParse(t *testing.T) {
	entries := mustParse(t, `
# comment
192.0.2.1
  198.51.100.0/24   # trailing comment

10.1.2.10-12
Example.COM.
10-0-0-1.ip.example.com
`)
	want := []Entry{
		{Line: 3, Kind: KindAddr, First: netip.MustParseAddr("192.0.2.1"), Last: netip.MustParseAddr("192.0.2.1")},
		{Line: 4, Kind: KindCIDR, First: netip.MustParseAddr("198.51.100.0"), Last: netip.MustParseAddr("198.51.100.255")},
		{Line: 6, Kind: KindRange, First: netip.MustParseAddr("10.1.2.10"), Last: netip.MustParseAddr("10.1.2.12")},
		{Line: 7, Kind: KindDomain, Name: "example.com"},
		{Line: 8, Kind: KindDomain, Name: "10-0-0-1.ip.example.com"},
	}
	if !reflect.DeepEqual(entries, want) {
		t.Fatalf("Parse = %+v\nwant %+v", entries, want)
	}
}

func TestParseInvalidReportsLine(t *testing.T) {
	for _, bad := range []string{"10.0.0.256", "10.0.0.0/33", "10.0.0.5-3", "10.0.0.1-256", "10.0.0.1-+5", "10.0.0.1-10.0.0.5", "bad_host.example", "localhost", "2001:db8::1", "2001:db8::/64", "10.0.0"} {
		_, err := Parse(strings.NewReader("# header\n10.0.0.1\n\n" + bad + "\n10.0.0.2\n"))
		var pe *ParseError
		if !errors.As(err, &pe) || pe.Line != 4 || !strings.Contains(err.Error(), "line 4") {
			t.Errorf("Parse(%q) error = %v, want ParseError on line 4", bad, err)
		}
	}
}

func TestExpandLargeCIDRIterates(t *testing.T) {
	s := build(t, "10.0.0.0/18\n", "", nil)
	count := 0
	var first, last netip.Addr
	for tg := range s.All() {
		if count == 0 {
			first = tg.Addr
		}
		last = tg.Addr
		count++
	}
	if count != 16382 || first.String() != "10.0.0.1" || last.String() != "10.0.63.254" {
		t.Fatalf("count=%d first=%s last=%s", count, first, last)
	}
	if n := len(s.spans); n != 1 {
		t.Fatalf("set holds %d spans, want 1 (addresses must not be materialised)", n)
	}
	groups, total := 0, 0
	for g := range s.Group(64) {
		groups++
		total += len(g)
		if cap(g) > 64 {
			t.Fatalf("group capacity %d > 64", cap(g))
		}
	}
	if total != 16382 || groups != 256 {
		t.Fatalf("groups=%d total=%d", groups, total)
	}
}

func TestExpandSmallPrefixesKeepAllAddresses(t *testing.T) {
	got := addrs(build(t, "192.0.2.10/31\n192.0.2.20/32\n192.0.2.0/30\n", "", nil))
	want := []string{"192.0.2.1", "192.0.2.2", "192.0.2.10", "192.0.2.11", "192.0.2.20"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestExcludesWin(t *testing.T) {
	targets := "10.0.0.0/28\n10.0.0.3\n10.0.0.12-14\nweb.example\n"
	excludes := "10.0.0.3\n10.0.0.4/31\n10.0.0.9-10\n10.0.0.12\n"
	res := fakeResolver{"web.example": {"10.0.0.5", "10.0.0.200"}}
	got := addrs(build(t, targets, excludes, res))
	want := []string{"10.0.0.1", "10.0.0.2", "10.0.0.6", "10.0.0.7", "10.0.0.8", "10.0.0.11", "10.0.0.13", "10.0.0.14", "10.0.0.200"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestExcludeCIDRCoversNetworkAndBroadcast(t *testing.T) {
	res := fakeResolver{"edge.example": {"10.0.1.0", "10.0.1.255"}}
	got := addrs(build(t, "10.0.0.255-255\n10.0.1.0-1\n10.0.1.254-255\n10.0.2.0\nedge.example\n", "10.0.1.0/24\n", res))
	if !slices.Equal(got, []string{"10.0.0.255", "10.0.2.0"}) {
		t.Fatalf("got %v", got)
	}
}

func TestExcludeDomainByName(t *testing.T) {
	res := fakeResolver{"a.example": {"192.0.2.1"}, "b.example": {"192.0.2.2"}}
	got := addrs(build(t, "a.example\nb.example\n", "a.example\n", res))
	if !slices.Equal(got, []string{"192.0.2.2"}) {
		t.Fatalf("got %v", got)
	}
}

func TestDomainsResolvedWithHostname(t *testing.T) {
	res := fakeResolver{
		"multi.example": {"192.0.2.9", "192.0.2.7", "::ffff:192.0.2.8"},
		"alias.example": {"192.0.2.7"},
	}
	s := build(t, "multi.example\n192.0.2.6/31\nalias.example\n", "", res)
	var got []Target
	for tg := range s.All() {
		got = append(got, tg)
	}
	want := []Target{
		{Addr: netip.MustParseAddr("192.0.2.6")},
		{Addr: netip.MustParseAddr("192.0.2.7"), Hostnames: []string{"alias.example", "multi.example"}},
		{Addr: netip.MustParseAddr("192.0.2.8"), Hostnames: []string{"multi.example"}},
		{Addr: netip.MustParseAddr("192.0.2.9"), Hostnames: []string{"multi.example"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

func TestDomainResolveError(t *testing.T) {
	_, err := Build(context.Background(), mustParse(t, "10.0.0.1\ngone.example\n"), nil, fakeResolver{})
	if err == nil || !strings.Contains(err.Error(), "line 2") || !strings.Contains(err.Error(), "gone.example") {
		t.Fatalf("err = %v", err)
	}
}

func TestGroupStable(t *testing.T) {
	res := fakeResolver{"x.example": {"172.16.0.200"}}
	collect := func(targets string) [][]string {
		var out [][]string
		for g := range build(t, targets, "", res).Group(3) {
			var row []string
			for _, tg := range g {
				row = append(row, tg.Addr.String())
			}
			out = append(out, row)
		}
		return out
	}
	a := collect("172.16.0.9\nx.example\n172.16.0.1-4\n172.16.0.3\n172.16.0.0/29\n")
	b := collect("172.16.0.0/29\n172.16.0.3\n172.16.0.1-4\nx.example\n172.16.0.9\n")
	want := [][]string{
		{"172.16.0.1", "172.16.0.2", "172.16.0.3"},
		{"172.16.0.4", "172.16.0.5", "172.16.0.6"},
		{"172.16.0.9", "172.16.0.200"},
	}
	if !reflect.DeepEqual(a, want) || !reflect.DeepEqual(b, want) {
		t.Fatalf("a=%v b=%v want %v", a, b, want)
	}
	if !reflect.DeepEqual(collect("172.16.0.0/29\n"), collect("172.16.0.0/29\n")) {
		t.Fatal("same input yielded different groups")
	}
}

func TestGroupStopsEarly(t *testing.T) {
	n := 0
	for range build(t, "10.0.0.0/18\n", "", nil).Group(10) {
		n++
		if n == 2 {
			break
		}
	}
	if n != 2 {
		t.Fatalf("n=%d", n)
	}
}
