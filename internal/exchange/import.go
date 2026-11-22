package exchange

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"asi/internal/inventory"
	"asi/internal/probe"
)

const MaxUploadBytes = 20 << 20

var ErrTooLarge = fmt.Errorf("exchange: file is larger than %d MiB", MaxUploadBytes>>20)

const SourceImported = "import"

type RowError struct {
	Row    int    `json:"row"`
	Reason string `json:"reason"`
}

func (e RowError) String() string { return fmt.Sprintf("Row %d: %s", e.Row, e.Reason) }

type Entry struct {
	Row       int
	Host      inventory.HostResult
	User      inventory.HostUserFields
	staleHost bool
	staleSvc  map[string]bool
	statedSvc map[string]bool
}

const MaxRowErrors = 1000

type Batch struct {
	Entries []Entry
	Errors  []RowError
	Invalid int
}

func (b *Batch) addError(row int, reason string) {
	b.Invalid++
	if len(b.Errors) < MaxRowErrors {
		b.Errors = append(b.Errors, RowError{row, reason})
	}
}

func ReadAll(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxUploadBytes+1))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return nil, ErrTooLarge
		}
		return nil, fmt.Errorf("read import file: %w", err)
	}
	if len(data) > MaxUploadBytes {
		return nil, ErrTooLarge
	}
	return data, nil
}

func Parse(format string, data []byte) (Batch, error) {
	switch format {
	case "json":
		return ParseJSON(data)
	case "csv":
		return ParseCSV(data)
	}
	return Batch{}, fmt.Errorf("format must be json or csv, got %q", format)
}

type jsonExport struct {
	Schema string            `json:"schema"`
	Hosts  []json.RawMessage `json:"hosts"`
}

type jsonHost struct {
	Address        string        `json:"address"`
	Status         string        `json:"status"`
	Hostnames      []string      `json:"hostnames"`
	Tags           []string      `json:"tags"`
	Notes          string        `json:"notes"`
	DisplayName    string        `json:"display_name"`
	Owner          string        `json:"owner"`
	Criticality    string        `json:"criticality"`
	StatusOverride string        `json:"status_override"`
	Services       []jsonService `json:"services"`
}

type jsonService struct {
	Port         int                    `json:"port"`
	Status       string                 `json:"status"`
	Protocol     string                 `json:"protocol"`
	State        string                 `json:"state"`
	Service      string                 `json:"service"`
	Product      string                 `json:"product"`
	Version      string                 `json:"version"`
	HTTP         *probe.HTTP            `json:"http"`
	Technologies []inventory.Technology `json:"technologies"`
	Findings     []inventory.Finding    `json:"findings"`
}

func ParseJSON(data []byte) (Batch, error) {
	var doc jsonExport
	if err := json.Unmarshal(data, &doc); err != nil {
		return Batch{}, fmt.Errorf("the file is not valid JSON: %w", err)
	}
	if doc.Schema != inventory.ExportSchema {
		return Batch{}, fmt.Errorf("schema must be %q, got %q", inventory.ExportSchema, doc.Schema)
	}
	var b Batch
	first := map[string]int{}
	for i, raw := range doc.Hosts {
		row := i + 1
		var h jsonHost
		if err := json.Unmarshal(raw, &h); err != nil {
			b.addError(row, "host is not valid: "+err.Error())
			continue
		}
		e := Entry{Row: row, staleHost: notActive(h.Status), staleSvc: map[string]bool{}, statedSvc: map[string]bool{}, Host: inventory.HostResult{Address: h.Address, Hostnames: h.Hostnames},
			User: inventory.HostUserFields{Tags: h.Tags, Notes: h.Notes, DisplayName: h.DisplayName, Owner: h.Owner,
				Criticality: h.Criticality, StatusOverride: h.StatusOverride}}
		for _, s := range h.Services {
			if notActive(s.Status) {
				e.staleSvc[serviceKey(s.Port, s.Protocol)] = true
			}
			if s.Technologies != nil {
				e.statedSvc[serviceKey(s.Port, s.Protocol)] = true
			}
			e.Host.Services = append(e.Host.Services, inventory.ServiceResult{Port: s.Port, Protocol: s.Protocol,
				State: s.State, Service: s.Service, Product: s.Product, Version: s.Version, HTTP: s.HTTP,
				Technologies: s.Technologies, Findings: s.Findings})
		}
		if err := normalize(&e); err != nil {
			b.addError(row, err.Error())
			continue
		}
		if r, dup := first[e.Host.Address]; dup {
			b.addError(row, fmt.Sprintf("%q is listed twice (first in row %d).", e.Host.Address, r))
			continue
		}
		first[e.Host.Address] = row
		b.Entries = append(b.Entries, e)
	}
	return b, nil
}

func serviceKey(port int, protocol string) string {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if protocol == "" {
		protocol = "tcp"
	}
	return fmt.Sprintf("%d/%s", port, protocol)
}

func notActive(status string) bool {
	return status == string(inventory.StatusUnstable) || status == string(inventory.StatusInactive)
}

func ParseCSV(data []byte) (Batch, error) {
	cr := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(data, []byte("\ufeff"))))
	cr.FieldsPerRecord = -1
	cr.ReuseRecord = true
	header, err := cr.Read()
	if err != nil {
		return Batch{}, fmt.Errorf("the file has no CSV header: %w", err)
	}
	col := map[string]int{}
	for i, name := range header {
		if name = strings.ToLower(strings.TrimSpace(name)); knownColumn(name) {
			col[name] = i
		}
	}
	if _, ok := col["address"]; !ok {
		return Batch{}, errors.New("the CSV header has no address column")
	}
	rb := newRowBuilder()
	for row := 2; ; row++ {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			var pe *csv.ParseError
			if !errors.As(err, &pe) {
				return Batch{}, fmt.Errorf("read csv: %w", err)
			}
			rb.b.addError(row, "the row is not valid CSV: "+pe.Err.Error())
			continue
		}
		cells := map[string]string{}
		for name, i := range col {
			if i < len(rec) {
				cells[name] = unneutralize(strings.TrimSpace(rec[i]))
			}
		}
		rb.add(row, cells)
	}
	return rb.b, nil
}

func FromRows(rows []map[string]string, firstRow int) Batch {
	rb := newRowBuilder()
	for i, cells := range rows {
		if cells != nil {
			rb.add(firstRow+i, cells)
		}
	}
	return rb.b
}

type rowBuilder struct {
	b       Batch
	index   map[string]int
	seenSvc map[string]int
}

func newRowBuilder() *rowBuilder {
	return &rowBuilder{index: map[string]int{}, seenSvc: map[string]int{}}
}

func (rb *rowBuilder) add(row int, cells map[string]string) {
	b := &rb.b
	e, err := rowEntry(row, cells)
	e.staleHost = notActive(cells["status"])
	if err == nil {
		err = normalize(&e)
	}
	if err != nil {
		b.addError(row, err.Error())
		return
	}
	if len(e.Host.Services) == 1 {
		s := e.Host.Services[0]
		key := fmt.Sprintf("%s %d/%s", e.Host.Address, s.Port, s.Protocol)
		if r, dup := rb.seenSvc[key]; dup {
			b.addError(row, fmt.Sprintf("Service %d/%s of %s is listed twice (first in row %d).", s.Port, s.Protocol, e.Host.Address, r))
			return
		}
		rb.seenSvc[key] = row
	}
	j, ok := rb.index[e.Host.Address]
	if !ok {
		rb.index[e.Host.Address] = len(b.Entries)
		b.Entries = append(b.Entries, e)
		return
	}
	cur := &b.Entries[j]
	cur.Host.Hostnames = union(cur.Host.Hostnames, e.Host.Hostnames)
	cur.User.Tags = union(cur.User.Tags, e.User.Tags)
	cur.Host.Services = append(cur.Host.Services, e.Host.Services...)
}

func rowEntry(row int, c map[string]string) (Entry, error) {
	e := Entry{Row: row, Host: inventory.HostResult{Address: c["address"], Hostnames: splitList(c["hostnames"])},
		User: inventory.HostUserFields{Tags: splitList(c["tags"]), Notes: c["notes"]}}
	if c["port"] == "" {
		for _, name := range []string{"protocol", "service", "product", "version", "scheme", "status_code", "title", "technologies", "findings"} {
			if c[name] != "" {
				return e, fmt.Errorf("%s is set but port is empty.", name)
			}
		}
		return e, nil
	}
	port, err := strconv.Atoi(c["port"])
	if err != nil {
		return e, fmt.Errorf("%q is not a port.", c["port"])
	}
	s := inventory.ServiceResult{Port: port, Protocol: c["protocol"], Service: c["service"], Product: c["product"], Version: c["version"]}
	if c["scheme"] != "" || c["status_code"] != "" || c["title"] != "" {
		s.HTTP = &probe.HTTP{Scheme: c["scheme"], Title: c["title"]}
		if c["status_code"] != "" {
			if s.HTTP.StatusCode, err = strconv.Atoi(c["status_code"]); err != nil {
				return e, fmt.Errorf("%q is not a status code.", c["status_code"])
			}
		}
	}
	for _, t := range splitList(c["technologies"]) {
		tech := inventory.Technology{Name: t, Source: SourceImported}
		if i := strings.LastIndexByte(t, ':'); i > 0 {
			tech.Name, tech.Version = strings.TrimSpace(t[:i]), strings.TrimSpace(t[i+1:])
		}
		s.Technologies = append(s.Technologies, tech)
	}
	for _, f := range splitList(c["findings"]) {
		s.Findings = append(s.Findings, inventory.Finding{SignatureID: f})
	}
	e.Host.Services = []inventory.ServiceResult{s}
	return e, nil
}

func normalize(e *Entry) error {
	a, err := netip.ParseAddr(strings.TrimSpace(e.Host.Address))
	if err != nil {
		return fmt.Errorf("%q is not an address.", e.Host.Address)
	}
	e.Host.Address = a.Unmap().String()
	var hostnames []string
	for _, h := range e.Host.Hostnames {
		hostnames = append(hostnames, strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), ".")))
	}
	e.Host.Hostnames = union(nil, hostnames)
	e.User.Tags = union(nil, e.User.Tags)
	switch inventory.Status(e.User.StatusOverride) {
	case "", inventory.StatusActive, inventory.StatusUnstable, inventory.StatusInactive:
	default:
		return fmt.Errorf("%q is not a status override.", e.User.StatusOverride)
	}
	seen := map[string]bool{}
	for i := range e.Host.Services {
		s := &e.Host.Services[i]
		if s.Port < 1 || s.Port > 65535 {
			return fmt.Errorf("port %d is out of range 1-65535.", s.Port)
		}
		s.Protocol = strings.ToLower(strings.TrimSpace(s.Protocol))
		if s.Protocol == "" {
			s.Protocol = "tcp"
		}
		if s.Protocol != "tcp" && s.Protocol != "udp" && s.Protocol != "sctp" {
			return fmt.Errorf("%q is not a protocol (tcp, udp or sctp).", s.Protocol)
		}
		key := fmt.Sprintf("%d/%s", s.Port, s.Protocol)
		if seen[key] {
			return fmt.Errorf("service %s is listed twice.", key)
		}
		seen[key] = true
		if s.State == "" {
			s.State = "open"
		}
		s.Service = strings.TrimSpace(s.Service)
		if err := normalizeHTTP(s.HTTP); err != nil {
			return fmt.Errorf("service %s: %w", key, err)
		}
		techs := s.Technologies[:0:0]
		for _, t := range s.Technologies {
			if t.Name = strings.TrimSpace(t.Name); t.Name == "" {
				return fmt.Errorf("service %s: a technology has no name.", key)
			}
			if t.Confidence < 0 || t.Confidence > 100 {
				return fmt.Errorf("service %s: confidence %d of %s is out of range 0-100.", key, t.Confidence, t.Name)
			}
			if t.ConfidenceRaw != nil {
				if *t.ConfidenceRaw < 0 || *t.ConfidenceRaw > 100 {
					return fmt.Errorf("service %s: confidence_raw %d of %s is out of range 0-100.", key, *t.ConfidenceRaw, t.Name)
				}
				t.Confidence, t.ConfidenceRaw = *t.ConfidenceRaw, nil
			}
			techs = append(techs, t)
		}
		s.Technologies = techs
		for _, f := range s.Findings {
			if strings.TrimSpace(f.SignatureID) == "" {
				return fmt.Errorf("service %s: a finding has no signature_id.", key)
			}
			if f.Confidence < 0 || f.Confidence > 100 {
				return fmt.Errorf("service %s: confidence %d of %s is out of range 0-100.", key, f.Confidence, f.SignatureID)
			}
		}
	}
	return nil
}

func normalizeHTTP(h *probe.HTTP) error {
	if h == nil {
		return nil
	}
	h.Scheme = strings.ToLower(strings.TrimSpace(h.Scheme))
	if h.Scheme != "" && h.Scheme != "http" && h.Scheme != "https" {
		return fmt.Errorf("%q is not a scheme (http or https).", h.Scheme)
	}
	if h.StatusCode != 0 && (h.StatusCode < 100 || h.StatusCode > 599) {
		return fmt.Errorf("status code %d is out of range 100-599.", h.StatusCode)
	}
	headers := make(map[string]string, len(h.Headers))
	for name, v := range h.Headers {
		if name = strings.ToLower(strings.TrimSpace(name)); name != "" && name != "set-cookie" {
			headers[name] = v
		}
	}
	h.Headers = headers
	if h.Cookies == nil {
		h.Cookies = []probe.Cookie{}
	}
	if h.RedirectChain == nil {
		h.RedirectChain = []string{}
	}
	return nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ";") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func union(a, b []string) []string {
	out := []string{}
	for _, s := range append(slices.Clone(a), b...) {
		if s = strings.TrimSpace(s); s != "" && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

func neutralize(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

func unneutralize(s string) string {
	if len(s) > 1 && s[0] == '\'' && strings.ContainsRune("=+-@\t\r", rune(s[1])) {
		return s[1:]
	}
	return s
}
