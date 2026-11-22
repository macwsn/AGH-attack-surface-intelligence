package exchange

import (
	"net/url"
	"strconv"
	"strings"

	"asi/internal/inventory"
)

type HostForm struct {
	Address   string
	Hostnames string
	Tags      string
	Notes     string
	Services  []ServiceForm
}

type ServiceForm struct {
	Port, Protocol, Service, Product, Version, Scheme, StatusCode, Title, Technologies, Findings string
}

var serviceFields = []string{"port", "protocol", "service", "product", "version", "scheme", "status_code", "title", "technologies", "findings"}

func (s ServiceForm) cells() []string {
	return []string{s.Port, s.Protocol, s.Service, s.Product, s.Version, s.Scheme, s.StatusCode, s.Title, s.Technologies, s.Findings}
}

func HostFormFrom(v url.Values) HostForm {
	f := HostForm{Address: strings.TrimSpace(v.Get("address")), Hostnames: v.Get("hostnames"), Tags: v.Get("tags"), Notes: v.Get("notes")}
	n := 0
	for _, name := range serviceFields {
		n = max(n, len(v[name]))
	}
	for i := 0; i < n; i++ {
		at := func(name string) string {
			if vs := v[name]; i < len(vs) {
				return strings.TrimSpace(vs[i])
			}
			return ""
		}
		f.Services = append(f.Services, ServiceForm{Port: at("port"), Protocol: at("protocol"), Service: at("service"),
			Product: at("product"), Version: at("version"), Scheme: at("scheme"), StatusCode: at("status_code"),
			Title: at("title"), Technologies: at("technologies"), Findings: at("findings")})
	}
	return f
}

func FormFromHost(h inventory.ExportHost) HostForm {
	f := HostForm{Address: h.Address, Hostnames: strings.Join(h.Hostnames, ", "), Tags: strings.Join(h.Tags, ", "), Notes: h.Notes}
	for _, s := range h.Services {
		sf := ServiceForm{Port: strconv.Itoa(s.Port), Protocol: s.Protocol, Service: s.Service, Product: s.Product, Version: s.Version}
		if s.HTTP != nil {
			sf.Scheme, sf.Title = s.HTTP.Scheme, s.HTTP.Title
			if s.HTTP.StatusCode != 0 {
				sf.StatusCode = strconv.Itoa(s.HTTP.StatusCode)
			}
		}
		techs := make([]string, 0, len(s.Technologies))
		for _, t := range s.Technologies {
			techs = append(techs, strings.TrimSuffix(t.Name+":"+t.Version, ":"))
		}
		finds := make([]string, 0, len(s.Findings))
		for _, x := range s.Findings {
			finds = append(finds, x.SignatureID)
		}
		sf.Technologies, sf.Findings = strings.Join(techs, "; "), strings.Join(finds, "; ")
		f.Services = append(f.Services, sf)
	}
	return f
}

func (f *HostForm) Pad(n int) {
	for i := 0; i < n; i++ {
		f.Services = append(f.Services, ServiceForm{})
	}
}

func (f HostForm) Rows() []map[string]string {
	list := func(s string) string {
		return strings.Join(strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\r' || r == '\t' }), ";")
	}
	base := func() map[string]string {
		return map[string]string{"address": f.Address, "hostnames": list(f.Hostnames), "tags": tagList(f.Tags), "notes": strings.TrimSpace(f.Notes)}
	}
	rows := make([]map[string]string, len(f.Services))
	any := false
	for i, s := range f.Services {
		cells, blank := base(), true
		for j, v := range s.cells() {
			cells[serviceFields[j]] = v
			blank = blank && v == ""
		}
		if !blank {
			rows[i], any = cells, true
		}
	}
	if !any {
		return []map[string]string{base()}
	}
	return rows
}

func tagList(s string) string {
	var out []string
	for _, t := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' || r == '\n' || r == '\r' }) {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	return strings.Join(out, ";")
}

func (f HostForm) Batch() Batch {
	return FromRows(f.Rows(), 1)
}
