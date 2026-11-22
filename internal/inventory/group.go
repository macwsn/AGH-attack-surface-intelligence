package inventory

import (
	"sort"
	"strings"
)

type ServiceGroupKey struct {
	Technologies  []string
	Title         string
	FaviconSHA256 string
}

type ServiceGroupMember struct {
	Address  string
	Port     int
	Protocol string
}

type ServiceGroup struct {
	Key     ServiceGroupKey
	Count   int
	Members []ServiceGroupMember
}

func GroupServices(hosts []ExportHost) []ServiceGroup {
	byKey := map[string]*ServiceGroup{}
	for _, h := range hosts {
		for _, s := range h.Services {
			if s.HTTP == nil {
				continue
			}
			key := ServiceGroupKey{Technologies: techSet(s.Technologies), Title: s.HTTP.Title, FaviconSHA256: s.HTTP.FaviconSHA256}
			id := groupID(key)
			g, ok := byKey[id]
			if !ok {
				g = &ServiceGroup{Key: key}
				byKey[id] = g
			}
			g.Count++
			g.Members = append(g.Members, ServiceGroupMember{Address: h.Address, Port: s.Port, Protocol: s.Protocol})
		}
	}
	groups := make([]ServiceGroup, 0, len(byKey))
	for _, g := range byKey {
		sort.Slice(g.Members, func(i, j int) bool { return memberLess(g.Members[i], g.Members[j]) })
		groups = append(groups, *g)
	}
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].Count != groups[j].Count {
			return groups[i].Count > groups[j].Count
		}
		return groupID(groups[i].Key) < groupID(groups[j].Key)
	})
	return groups
}

func techSet(techs []Technology) []string {
	set := []string{}
	for _, t := range techs {
		item := t.Name
		if t.Version != "" {
			item += " " + t.Version
		}
		set = append(set, item)
	}
	sort.Strings(set)
	out := []string{}
	for i, s := range set {
		if i == 0 || set[i-1] != s {
			out = append(out, s)
		}
	}
	return out
}

func groupID(k ServiceGroupKey) string {
	return strings.Join(k.Technologies, "\x1f") + "\x1e" + k.Title + "\x1e" + k.FaviconSHA256
}

func memberLess(a, b ServiceGroupMember) bool {
	if a.Address != b.Address {
		return addressLess(a.Address, b.Address)
	}
	if a.Port != b.Port {
		return a.Port < b.Port
	}
	return a.Protocol < b.Protocol
}
