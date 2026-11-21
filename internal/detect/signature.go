package detect

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"asi/internal/probe"
)

const (
	RuleSchema        = "signature format (docs/contracts.md §4)"
	RuleMethod        = "methods GET and HEAD only"
	RuleBody          = "no request body"
	RuleHeaders       = "no custom headers"
	RuleCredentials   = "no credentials"
	RulePath          = "path is a literal absolute path without query string"
	RuleRegex         = "regexes are valid RE2"
	RuleDuplicateID   = "id is unique"
	RuleExtraRequests = "at most 5 extra requests per service"
)

var (
	idPattern = regexp.MustCompile(`^[a-z0-9-]+$`)
	kinds     = map[string]bool{
		"technology": true, "admin-panel": true, "staging": true, "iot": true,
		"interesting-header": true, "interesting-cookie": true, "custom": true,
	}
	sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type RuleError struct {
	ID     string
	Rule   string
	Detail string
}

func (e *RuleError) Error() string {
	return fmt.Sprintf("signature %q violates rule %q: %s", e.ID, e.Rule, e.Detail)
}

type Signature struct {
	ID         string
	Name       string
	Kind       string
	Category   string
	Confidence int
	Method     string
	Path       string
	All        []Matcher
	Any        []Matcher
	Version    *Matcher
}

type Matcher struct {
	Type   string
	Name   string
	Value  string
	Group  int
	status int
	mmh3   int32
	name   *regexp.Regexp
	value  *regexp.Regexp
}

type Set struct {
	Signatures []Signature
}

type rawSignature struct {
	ID         string         `yaml:"id"`
	Name       string         `yaml:"name"`
	Kind       string         `yaml:"kind"`
	Category   string         `yaml:"category"`
	Confidence *int           `yaml:"confidence"`
	Request    map[string]any `yaml:"request"`
	Match      struct {
		All []rawMatcher `yaml:"all"`
		Any []rawMatcher `yaml:"any"`
	} `yaml:"match"`
	Version *rawMatcher `yaml:"version"`
}

type rawMatcher struct {
	Type  string `yaml:"type"`
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
	Group int    `yaml:"group"`
}

func LoadDir(dir string) (*Set, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, fmt.Errorf("list signatures in %s: %w", dir, err)
	}
	sort.Strings(files)
	var all []Signature
	seen := map[string]string{}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("read signatures: %w", err)
		}
		sigs, err := Parse(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		for _, s := range sigs {
			if prev, ok := seen[s.ID]; ok {
				return nil, fmt.Errorf("%s: %w", f, &RuleError{ID: s.ID, Rule: RuleDuplicateID, Detail: "already defined in " + prev})
			}
			seen[s.ID] = f
		}
		all = append(all, sigs...)
	}
	if err := checkExtraRequests(all); err != nil {
		return nil, err
	}
	return &Set{Signatures: all}, nil
}

func Parse(data []byte) ([]Signature, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var raws []rawSignature
	if err := dec.Decode(&raws); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse signatures: %w", err)
	}
	out := make([]Signature, 0, len(raws))
	ids := map[string]bool{}
	for _, r := range raws {
		s, err := compile(r)
		if err != nil {
			return nil, err
		}
		if ids[s.ID] {
			return nil, &RuleError{ID: s.ID, Rule: RuleDuplicateID, Detail: "defined twice in one file"}
		}
		ids[s.ID] = true
		out = append(out, s)
	}
	if err := checkExtraRequests(out); err != nil {
		return nil, err
	}
	return out, nil
}

func checkExtraRequests(sigs []Signature) error {
	paths := map[string]bool{}
	for _, s := range sigs {
		if s.Path == "/" || paths[s.Path] {
			continue
		}
		paths[s.Path] = true
		if len(paths) > probe.MaxExtraRequests {
			return &RuleError{ID: s.ID, Rule: RuleExtraRequests, Detail: fmt.Sprintf("path %q is extra request number %d", s.Path, len(paths))}
		}
	}
	return nil
}

func compile(r rawSignature) (Signature, error) {
	fail := func(rule, format string, args ...any) (Signature, error) {
		return Signature{}, &RuleError{ID: r.ID, Rule: rule, Detail: fmt.Sprintf(format, args...)}
	}
	if !idPattern.MatchString(r.ID) {
		return fail(RuleSchema, "id %q must match [a-z0-9-]+", r.ID)
	}
	if strings.TrimSpace(r.Name) == "" {
		return fail(RuleSchema, "name is required")
	}
	if !kinds[r.Kind] {
		return fail(RuleSchema, "unknown kind %q", r.Kind)
	}
	if r.Confidence == nil || *r.Confidence < 0 || *r.Confidence > 100 {
		return fail(RuleSchema, "confidence must be 0-100")
	}
	s := Signature{ID: r.ID, Name: r.Name, Kind: r.Kind, Category: r.Category, Confidence: *r.Confidence, Method: "GET", Path: "/"}
	for key, v := range r.Request {
		switch strings.ToLower(key) {
		case "method":
			m, _ := v.(string)
			if m != "GET" && m != "HEAD" {
				return fail(RuleMethod, "method %v", v)
			}
			s.Method = m
		case "path":
			p, _ := v.(string)
			if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.ContainsAny(p, "?#") {
				return fail(RulePath, "path %v", v)
			}
			s.Path = p
		case "body", "data", "form", "json":
			return fail(RuleBody, "request field %q", key)
		case "headers", "header", "cookies", "cookie":
			return fail(RuleHeaders, "request field %q", key)
		case "auth", "credentials", "username", "user", "password", "token", "basic_auth":
			return fail(RuleCredentials, "request field %q", key)
		default:
			return fail(RuleSchema, "unknown request field %q", key)
		}
	}
	if len(r.Match.All) == 0 && len(r.Match.Any) == 0 {
		return fail(RuleSchema, "match needs an all or any group")
	}
	var err error
	if s.All, err = compileMatchers(r.ID, r.Match.All); err != nil {
		return Signature{}, err
	}
	if s.Any, err = compileMatchers(r.ID, r.Match.Any); err != nil {
		return Signature{}, err
	}
	if r.Version != nil {
		v, err := compileMatcher(r.ID, *r.Version)
		if err != nil {
			return Signature{}, err
		}
		if v.value == nil {
			return fail(RuleSchema, "version type %q cannot extract a value", v.Type)
		}
		if v.Group < 0 || v.Group > v.value.NumSubexp() {
			return fail(RuleRegex, "version group %d out of range for %q", v.Group, v.Value)
		}
		s.Version = &v
	}
	return s, nil
}

func compileMatchers(id string, raws []rawMatcher) ([]Matcher, error) {
	out := make([]Matcher, 0, len(raws))
	for _, r := range raws {
		m, err := compileMatcher(id, r)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

func compileMatcher(id string, r rawMatcher) (Matcher, error) {
	m := Matcher{Type: r.Type, Name: r.Name, Value: r.Value, Group: r.Group}
	fail := func(rule, format string, args ...any) (Matcher, error) {
		return Matcher{}, &RuleError{ID: id, Rule: rule, Detail: fmt.Sprintf(format, args...)}
	}
	re := func(expr string) (*regexp.Regexp, error) {
		c, err := regexp.Compile(expr)
		if err != nil {
			return nil, &RuleError{ID: id, Rule: RuleRegex, Detail: fmt.Sprintf("%s %q: %v", r.Type, expr, err)}
		}
		return c, nil
	}
	var err error
	switch r.Type {
	case "status":
		if m.status, err = strconv.Atoi(r.Value); err != nil {
			return fail(RuleSchema, "status value %q is not an integer", r.Value)
		}
	case "header":
		if r.Name == "" {
			return fail(RuleSchema, "header matcher needs a name")
		}
		m.Name = strings.ToLower(r.Name)
		if m.value, err = re(r.Value); err != nil {
			return Matcher{}, err
		}
	case "cookie":
		if m.name, err = re(r.Name); err != nil {
			return Matcher{}, err
		}
	case "title_regex", "body_regex":
		if m.value, err = re(r.Value); err != nil {
			return Matcher{}, err
		}
	case "favicon_sha256":
		m.Value = strings.ToLower(r.Value)
		if !sha256Hex.MatchString(m.Value) {
			return fail(RuleSchema, "favicon_sha256 %q is not a hex SHA-256", r.Value)
		}
	case "favicon_mmh3":
		n, err := strconv.ParseInt(r.Value, 10, 32)
		if err != nil {
			return fail(RuleSchema, "favicon_mmh3 %q is not a 32-bit integer", r.Value)
		}
		m.mmh3 = int32(n)
	default:
		return fail(RuleSchema, "unknown matcher type %q", r.Type)
	}
	return m, nil
}

func (m *Matcher) match(r *probe.Response, h *probe.HTTP) (bool, string) {
	switch m.Type {
	case "status":
		return r.StatusCode == m.status, fmt.Sprintf("status %d", m.status)
	case "header":
		v, ok := r.Headers[m.Name]
		return ok && m.value.MatchString(v), fmt.Sprintf("header %s matches %q", m.Name, m.Value)
	case "cookie":
		for _, c := range r.Cookies {
			if m.name.MatchString(c.Name) {
				return true, "cookie " + c.Name
			}
		}
		return false, ""
	case "title_regex":
		return m.value.MatchString(r.Title), fmt.Sprintf("title matches %q", m.Value)
	case "body_regex":
		return m.value.Match(r.Body), fmt.Sprintf("body matches %q", m.Value)
	case "favicon_sha256":
		return h.FaviconSHA256 == m.Value, "favicon sha256 " + m.Value
	case "favicon_mmh3":
		return h.FaviconSHA256 != "" && h.FaviconMMH3 == m.mmh3, fmt.Sprintf("favicon mmh3 %d", m.mmh3)
	}
	return false, ""
}

func (m *Matcher) extract(r *probe.Response) string {
	var sub [][]byte
	switch m.Type {
	case "header":
		sub = m.value.FindSubmatch([]byte(r.Headers[m.Name]))
	case "title_regex":
		sub = m.value.FindSubmatch([]byte(r.Title))
	case "body_regex":
		sub = m.value.FindSubmatch(r.Body)
	}
	if len(sub) <= m.Group {
		return ""
	}
	return string(sub[m.Group])
}

func (s *Signature) evaluate(r *probe.Response, h *probe.HTTP) (bool, []string) {
	var ev []string
	for i := range s.All {
		ok, e := s.All[i].match(r, h)
		if !ok {
			return false, nil
		}
		ev = append(ev, e)
	}
	if len(s.Any) > 0 {
		hit := false
		for i := range s.Any {
			if ok, e := s.Any[i].match(r, h); ok {
				hit = true
				ev = append(ev, e)
			}
		}
		if !hit {
			return false, nil
		}
	}
	return true, ev
}

func ParseOne(src []byte) (Signature, error) {
	item, err := signatureNode(src)
	if err != nil {
		return Signature{}, err
	}
	seq, err := yaml.Marshal(&yaml.Node{Kind: yaml.SequenceNode, Content: []*yaml.Node{item}})
	if err != nil {
		return Signature{}, fmt.Errorf("parse signature: %w", err)
	}
	sigs, err := Parse(seq)
	if err != nil {
		return Signature{}, asRuleError(err)
	}
	return sigs[0], nil
}

func asRuleError(err error) error {
	var re *RuleError
	if errors.As(err, &re) {
		return err
	}
	return &RuleError{Rule: RuleSchema, Detail: err.Error()}
}

func signatureNode(src []byte) (*yaml.Node, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(src, &doc); err != nil {
		return nil, asRuleError(err)
	}
	if len(doc.Content) == 1 {
		n := doc.Content[0]
		if n.Kind == yaml.SequenceNode && len(n.Content) == 1 {
			n = n.Content[0]
		}
		if n.Kind == yaml.MappingNode {
			return n, nil
		}
	}
	return nil, &RuleError{Rule: RuleSchema, Detail: "write exactly one signature as a YAML mapping"}
}

func SplitSources(data []byte) ([]Signature, [][]byte, error) {
	sigs, err := Parse(data)
	if err != nil {
		return nil, nil, asRuleError(err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, nil, asRuleError(err)
	}
	srcs := make([][]byte, 0, len(sigs))
	if len(doc.Content) == 1 {
		for _, n := range doc.Content[0].Content {
			b, err := yaml.Marshal(n)
			if err != nil {
				return nil, nil, fmt.Errorf("encode signature: %w", err)
			}
			srcs = append(srcs, b)
		}
	}
	if len(srcs) != len(sigs) {
		return nil, nil, &RuleError{Rule: RuleSchema, Detail: "the file must be a YAML list of signatures"}
	}
	return sigs, srcs, nil
}

func JoinSources(srcs [][]byte) ([]byte, error) {
	seq := &yaml.Node{Kind: yaml.SequenceNode}
	for _, src := range srcs {
		n, err := signatureNode(src)
		if err != nil {
			return nil, err
		}
		seq.Content = append(seq.Content, n)
	}
	if len(seq.Content) == 0 {
		return []byte("[]\n"), nil
	}
	out, err := yaml.Marshal(seq)
	if err != nil {
		return nil, fmt.Errorf("encode signatures: %w", err)
	}
	return out, nil
}

func Combine(file *Set, extra []Signature) (*Set, error) {
	var all []Signature
	seen := map[string]bool{}
	if file != nil {
		all = append(all, file.Signatures...)
		for _, s := range file.Signatures {
			seen[s.ID] = true
		}
	}
	for _, s := range extra {
		if seen[s.ID] {
			return nil, &RuleError{ID: s.ID, Rule: RuleDuplicateID, Detail: "already defined in the signatures directory"}
		}
		seen[s.ID] = true
		all = append(all, s)
	}
	if err := checkExtraRequests(all); err != nil {
		return nil, err
	}
	return &Set{Signatures: all}, nil
}

type Evaluation struct {
	Matched  bool
	Version  string
	Evidence []string
	Reason   string
}

func (s *Signature) EvaluateStored(h *probe.HTTP) Evaluation {
	if h == nil {
		return Evaluation{Reason: "The latest observation of this service has no HTTP response."}
	}
	if s.Path != "/" {
		return Evaluation{Reason: fmt.Sprintf("Only the response for / is stored; testing never sends the request %s %s.", s.Method, s.Path)}
	}
	r := &probe.Response{URL: h.URL, StatusCode: h.StatusCode, Title: h.Title, Headers: h.Headers, Cookies: h.Cookies, RedirectChain: h.RedirectChain}
	ok, ev := s.evaluate(r, h)
	if !ok {
		reason := "The stored response does not satisfy the match groups."
		for _, m := range append(slices.Clone(s.All), s.Any...) {
			if m.Type == "body_regex" {
				reason += " Response bodies are not stored, so body matchers never hold in a test."
				break
			}
		}
		return Evaluation{Reason: reason}
	}
	e := Evaluation{Matched: true, Evidence: ev}
	if s.Version != nil {
		e.Version = s.Version.extract(r)
	}
	return e
}
