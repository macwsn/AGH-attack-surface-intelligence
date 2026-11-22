package targets

import (
	"bufio"
	"cmp"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"iter"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

type Kind int

const (
	KindAddr Kind = iota
	KindCIDR
	KindRange
	KindDomain
)

type Entry struct {
	Line  int
	Kind  Kind
	First netip.Addr
	Last  netip.Addr
	Name  string
}

type ParseError struct {
	Line int
	Text string
	Err  error
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("line %d: invalid target %q: %v", e.Line, e.Text, e.Err)
}

func (e *ParseError) Unwrap() error { return e.Err }

func Parse(r io.Reader) ([]Entry, error) { return parse(r, false) }

func ParseHosts(r io.Reader) ([]Entry, error) { return parse(r, true) }

func parse(r io.Reader, hostnames bool) ([]Entry, error) {
	var entries []Entry
	sc := bufio.NewScanner(r)
	line := 0
	for sc.Scan() {
		line++
		text := sc.Text()
		if i := strings.IndexByte(text, '#'); i >= 0 {
			text = text[:i]
		}
		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}
		e, err := parseEntry(text, hostnames)
		if err != nil {
			return nil, &ParseError{Line: line, Text: text, Err: err}
		}
		e.Line = line
		entries = append(entries, e)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read targets: %w", err)
	}
	return entries, nil
}

func parseEntry(s string, hostnames bool) (Entry, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil || !p.Addr().Is4() {
			return Entry{}, errors.New("not an IPv4 CIDR")
		}
		p = p.Masked()
		last := toU32(p.Addr()) | (1<<(32-p.Bits()) - 1)
		return Entry{Kind: KindCIDR, First: p.Addr(), Last: fromU32(last)}, nil
	}
	if start, end, ok := strings.Cut(s, "-"); ok && looksNumeric(start) && looksNumeric(end) {
		a, err := netip.ParseAddr(start)
		if err != nil || !a.Is4() {
			return Entry{}, errors.New("range start is not an IPv4 address")
		}
		n, err := strconv.Atoi(end)
		first := a.As4()
		if err != nil || strings.Contains(end, ".") || n < int(first[3]) || n > 255 {
			return Entry{}, errors.New("range end must be a last octet not below the start")
		}
		last := first
		last[3] = byte(n)
		return Entry{Kind: KindRange, First: a, Last: netip.AddrFrom4(last)}, nil
	}
	if looksNumeric(s) {
		a, err := netip.ParseAddr(s)
		if err != nil || !a.Is4() {
			return Entry{}, errors.New("not an IPv4 address")
		}
		return Entry{Kind: KindAddr, First: a, Last: a}, nil
	}
	name, err := parseDomain(s, hostnames)
	if err != nil {
		return Entry{}, err
	}
	return Entry{Kind: KindDomain, Name: name}, nil
}

func looksNumeric(s string) bool {
	return s != "" && strings.Trim(s, "0123456789.") == ""
}

func parseDomain(s string, hostnames bool) (string, error) {
	name := strings.TrimSuffix(strings.ToLower(s), ".")
	labels := strings.Split(name, ".")
	if len(name) > 253 || (len(labels) < 2 && !hostnames) {
		return "", errors.New("not a domain name")
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return "", errors.New("not a domain name")
		}
		for _, c := range l {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return "", errors.New("not a domain name")
			}
		}
	}
	if looksNumeric(labels[len(labels)-1]) {
		return "", errors.New("not a domain name")
	}
	return name, nil
}

type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

type Target struct {
	Addr      netip.Addr
	Hostnames []string
}

type span struct{ first, last uint32 }

type Set struct {
	spans []span
	named []Target
}

func Count(targets, excludes []Entry) uint64 {
	var include, exclude []span
	excludedNames := map[string]bool{}
	for _, e := range excludes {
		if e.Kind == KindDomain {
			excludedNames[e.Name] = true
			continue
		}
		exclude = append(exclude, span{toU32(e.First), toU32(e.Last)})
	}
	names := map[string]bool{}
	for _, e := range targets {
		if e.Kind != KindDomain {
			include = append(include, span{toU32(e.First), toU32(e.Last)})
		} else if !excludedNames[e.Name] {
			names[e.Name] = true
		}
	}
	n := uint64(len(names))
	for _, sp := range subtract(merge(include), merge(exclude)) {
		n += uint64(sp.last-sp.first) + 1
	}
	return n
}

func Build(ctx context.Context, targets, excludes []Entry, res Resolver) (*Set, error) {
	var include, exclude []span
	excludedNames := map[string]bool{}
	for _, e := range excludes {
		if e.Kind == KindDomain {
			excludedNames[e.Name] = true
			continue
		}
		exclude = append(exclude, span{toU32(e.First), toU32(e.Last)})
	}
	exclude = merge(exclude)
	names := map[netip.Addr][]string{}
	for _, e := range targets {
		if e.Kind != KindDomain {
			sp := span{toU32(e.First), toU32(e.Last)}
			if e.Kind == KindCIDR && sp.last-sp.first > 1 {
				sp.first, sp.last = sp.first+1, sp.last-1
			}
			include = append(include, sp)
			continue
		}
		if excludedNames[e.Name] {
			continue
		}
		if res == nil {
			return nil, fmt.Errorf("line %d: resolve %s: no resolver", e.Line, e.Name)
		}
		addrs, err := res.LookupNetIP(ctx, "ip4", e.Name)
		if err != nil {
			return nil, fmt.Errorf("line %d: resolve %s: %w", e.Line, e.Name, err)
		}
		for _, a := range addrs {
			a = a.Unmap()
			if !a.Is4() || contains(exclude, toU32(a)) || slices.Contains(names[a], e.Name) {
				continue
			}
			names[a] = append(names[a], e.Name)
		}
	}
	s := &Set{spans: subtract(merge(include), exclude)}
	for a, hs := range names {
		slices.Sort(hs)
		s.named = append(s.named, Target{Addr: a, Hostnames: hs})
	}
	slices.SortFunc(s.named, func(a, b Target) int { return a.Addr.Compare(b.Addr) })
	return s, nil
}

func (s *Set) All() iter.Seq[Target] {
	return func(yield func(Target) bool) {
		named := s.named
		emitNamedBelow := func(limit uint64) bool {
			for len(named) > 0 && uint64(toU32(named[0].Addr)) < limit {
				if !yield(named[0]) {
					return false
				}
				named = named[1:]
			}
			return true
		}
		for _, sp := range s.spans {
			if !emitNamedBelow(uint64(sp.first)) {
				return
			}
			for v := uint64(sp.first); v <= uint64(sp.last); v++ {
				t := Target{Addr: fromU32(uint32(v))}
				if len(named) > 0 && named[0].Addr == t.Addr {
					t = named[0]
					named = named[1:]
				}
				if !yield(t) {
					return
				}
			}
		}
		emitNamedBelow(1 << 32)
	}
}

func (s *Set) Contains(a netip.Addr) bool {
	a = a.Unmap()
	if !a.Is4() {
		return false
	}
	return contains(s.spans, toU32(a)) || slices.ContainsFunc(s.named, func(t Target) bool { return t.Addr == a })
}

func (s *Set) Group(n int) iter.Seq[[]Target] {
	n = max(n, 1)
	return func(yield func([]Target) bool) {
		group := make([]Target, 0, n)
		for t := range s.All() {
			group = append(group, t)
			if len(group) == n {
				if !yield(group) {
					return
				}
				group = make([]Target, 0, n)
			}
		}
		if len(group) > 0 {
			yield(group)
		}
	}
}

func merge(spans []span) []span {
	slices.SortFunc(spans, func(a, b span) int {
		return cmp.Or(cmp.Compare(a.first, b.first), cmp.Compare(a.last, b.last))
	})
	var out []span
	for _, sp := range spans {
		if n := len(out); n > 0 && uint64(sp.first) <= uint64(out[n-1].last)+1 {
			out[n-1].last = max(out[n-1].last, sp.last)
			continue
		}
		out = append(out, sp)
	}
	return out
}

func subtract(include, exclude []span) []span {
	var out []span
	for _, sp := range include {
		first := uint64(sp.first)
		for _, ex := range exclude {
			if uint64(ex.last) < first || ex.first > sp.last {
				continue
			}
			if uint64(ex.first) > first {
				out = append(out, span{uint32(first), ex.first - 1})
			}
			first = uint64(ex.last) + 1
		}
		if first <= uint64(sp.last) {
			out = append(out, span{uint32(first), sp.last})
		}
	}
	return out
}

func contains(spans []span, v uint32) bool {
	_, found := slices.BinarySearchFunc(spans, v, func(sp span, v uint32) int {
		if sp.last < v {
			return -1
		}
		if sp.first > v {
			return 1
		}
		return 0
	})
	return found
}

func toU32(a netip.Addr) uint32 {
	b := a.As4()
	return binary.BigEndian.Uint32(b[:])
}

func fromU32(v uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}
