package detect

import (
	"bytes"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	FieldID         = "id"
	FieldName       = "name"
	FieldKind       = "kind"
	FieldConfidence = "confidence"
	FieldRequest    = "request"
	FieldMatch      = "match"
	FieldVersion    = "version"
)

func ConditionField(group string, i int) string { return fmt.Sprintf("match.%s.%d", group, i) }

var Kinds = []string{"technology", "admin-panel", "staging", "iot", "interesting-header", "interesting-cookie", "custom"}

var FormMatchers = []string{"header", "cookie", "title", "body", "status", "favicon"}

var VersionSources = []string{"header", "title", "body"}

type Form struct {
	ID          string
	Name        string
	Kind        string
	Category    string
	Confidence  string
	Any         bool
	Conditions  []Condition
	VersionFrom string
	VersionName string
	Version     string
	Path        string
}

type Condition struct {
	Matcher string
	Name    string
	Value   string
}

var (
	slugRun   = regexp.MustCompile(`[^a-z0-9]+`)
	sha256Any = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
)

func (f Form) Group() string {
	if f.Any {
		return "any"
	}
	return "all"
}

func (f Form) SignatureID() string {
	if id := strings.TrimSpace(f.ID); id != "" {
		return id
	}
	return strings.Trim(slugRun.ReplaceAllString(strings.ToLower(f.Name), "-"), "-")
}

func (c Condition) raw() rawMatcher {
	value := c.Value
	switch c.Matcher {
	case "header":
		return rawMatcher{Type: "header", Name: strings.TrimSpace(c.Name), Value: value}
	case "cookie":
		return rawMatcher{Type: "cookie", Name: c.Name}
	case "title":
		return rawMatcher{Type: "title_regex", Value: value}
	case "body":
		return rawMatcher{Type: "body_regex", Value: value}
	case "status":
		return rawMatcher{Type: "status", Value: strings.TrimSpace(value)}
	case "favicon":
		value = strings.TrimSpace(value)
		if sha256Any.MatchString(value) {
			return rawMatcher{Type: "favicon_sha256", Value: value}
		}
		return rawMatcher{Type: "favicon_mmh3", Value: value}
	}
	return rawMatcher{Type: c.Matcher, Name: c.Name, Value: value}
}

func (f Form) raw() rawSignature {
	r := rawSignature{ID: f.SignatureID(), Name: strings.TrimSpace(f.Name), Kind: f.Kind, Category: strings.TrimSpace(f.Category)}
	if n, err := strconv.Atoi(strings.TrimSpace(f.Confidence)); err == nil {
		r.Confidence = &n
	}
	if p := strings.TrimSpace(f.Path); p != "" && p != "/" {
		r.Request = map[string]any{"path": p}
	}
	conds := make([]rawMatcher, 0, len(f.Conditions))
	for _, c := range f.Conditions {
		conds = append(conds, c.raw())
	}
	if f.Any {
		r.Match.Any = conds
	} else {
		r.Match.All = conds
	}
	if f.Version != "" {
		v := Condition{Matcher: f.VersionFrom, Name: f.VersionName, Value: f.Version}.raw()
		if re, err := regexp.Compile(f.Version); err == nil && re.NumSubexp() > 0 {
			v.Group = 1
		}
		r.Version = &v
	}
	return r
}

func (f Form) YAML() ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode([]rawSignature{f.raw()}); err != nil {
		return nil, fmt.Errorf("encode signature form: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("encode signature form: %w", err)
	}
	return buf.Bytes(), nil
}

var formMatcherOf = map[string]string{
	"header": "header", "cookie": "cookie", "title_regex": "title", "body_regex": "body",
	"status": "status", "favicon_sha256": "favicon", "favicon_mmh3": "favicon",
}

func FormOf(src []byte) (Form, bool) {
	sig, err := ParseOne(src)
	if err != nil || len(sig.All) > 0 && len(sig.Any) > 0 {
		return Form{}, false
	}
	node, err := signatureNode(src)
	if err != nil {
		return Form{}, false
	}
	var r rawSignature
	if err := node.Decode(&r); err != nil {
		return Form{}, false
	}
	f := Form{ID: r.ID, Name: r.Name, Kind: r.Kind, Category: r.Category, Confidence: strconv.Itoa(sig.Confidence), Any: len(r.Match.Any) > 0}
	if sig.Path != "/" {
		f.Path = sig.Path
	}
	for _, m := range append(slices.Clone(r.Match.All), r.Match.Any...) {
		f.Conditions = append(f.Conditions, Condition{Matcher: formMatcherOf[m.Type], Name: m.Name, Value: m.Value})
	}
	if v := r.Version; v != nil {
		f.VersionFrom, f.VersionName, f.Version = formMatcherOf[v.Type], v.Name, v.Value
	}
	out, err := f.YAML()
	if err != nil {
		return Form{}, false
	}
	back, err := ParseOne(out)
	if err != nil || !sameSignature(sig, back) {
		return Form{}, false
	}
	return f, true
}

func sameMatcher(a, b Matcher) bool {
	return a.Type == b.Type && a.Name == b.Name && a.Value == b.Value && a.Group == b.Group
}

func sameSignature(a, b Signature) bool {
	if a.ID != b.ID || a.Name != b.Name || a.Kind != b.Kind || a.Category != b.Category || a.Confidence != b.Confidence ||
		a.Method != b.Method || a.Path != b.Path || !slices.EqualFunc(a.All, b.All, sameMatcher) || !slices.EqualFunc(a.Any, b.Any, sameMatcher) {
		return false
	}
	if a.Version == nil || b.Version == nil {
		return a.Version == b.Version
	}
	return sameMatcher(*a.Version, *b.Version)
}
