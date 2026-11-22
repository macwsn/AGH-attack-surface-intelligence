package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"asi/internal/probe"
)

var DefaultVolatileHeaders = []string{
	"date", "expires", "last-modified", "etag", "age", "set-cookie", "content-length", "x-request-id", "cf-ray",
}

const (
	FaviconField     = "http.favicon_sha256"
	VolatileToken    = "<volatile>"
	VolatileAfter    = 3
	VolatileValues   = 3
	headerFieldStart = "http.headers."
)

var (
	cspSource  = regexp.MustCompile(`(?i)'(nonce|sha256|sha384|sha512)-[^']*'`)
	tokenLike  = regexp.MustCompile(`[A-Za-z0-9+/_-]{16,}={0,2}`)
	uuidLike   = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	isoTime    = regexp.MustCompile(`\b[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}(?::[0-9]{2}(?:\.[0-9]+)?)?(?:Z|[+-][0-9]{2}:?[0-9]{2})?`)
	httpTime   = regexp.MustCompile(`(?i)\b(?:mon|tue|wed|thu|fri|sat|sun), [0-9]{2}[ -][a-z]{3}[ -][0-9]{2,4} [0-9]{2}:[0-9]{2}:[0-9]{2} GMT`)
	epochTime  = regexp.MustCompile(`\b1[0-9]{9}(?:[0-9]{3})?\b`)
	hasDigit   = regexp.MustCompile(`[0-9]`)
	hasLetter  = regexp.MustCompile(`[A-Za-z]`)
	allHexLike = regexp.MustCompile(`^[0-9a-fA-F]+$`)
)

func NormalizeHeader(name, value string) string {
	name = strings.ToLower(name)
	if strings.HasPrefix(name, "content-security-policy") {
		value = cspSource.ReplaceAllStringFunc(value, func(s string) string {
			kind, _, _ := strings.Cut(strings.Trim(s, "'"), "-")
			return "'" + strings.ToLower(kind) + "-" + VolatileToken + "'"
		})
	}
	value = uuidLike.ReplaceAllString(value, VolatileToken)
	value = isoTime.ReplaceAllString(value, VolatileToken)
	value = httpTime.ReplaceAllString(value, VolatileToken)
	value = epochTime.ReplaceAllString(value, VolatileToken)
	return tokenLike.ReplaceAllStringFunc(value, func(s string) string {
		if !hasDigit.MatchString(s) || !hasLetter.MatchString(s) {
			return s
		}
		if len(s) < 20 && !allHexLike.MatchString(s) {
			return s
		}
		return VolatileToken
	})
}

func ProbeFailed(s ExportService) bool {
	return s.HTTP != nil && s.HTTP.Error != ""
}

func ServiceFields(s ExportService, volatile map[string]bool) (compared, shown map[string]any) {
	v := map[string]any{
		"service":             s.Service,
		"product":             s.Product,
		"version":             s.Version,
		"technologies":        technologySet(s.Technologies),
		"findings":            findingSet(s.Findings),
		"http.status_code":    nil,
		"http.title":          nil,
		"http.cookies":        nil,
		"http.redirect_chain": nil,
		"http.tls.sha256":     nil,
		FaviconField:          nil,
	}
	if s.HTTP == nil {
		return v, v
	}
	v["http.status_code"] = s.HTTP.StatusCode
	v["http.title"] = s.HTTP.Title
	v["http.cookies"] = cookieSet(s.HTTP.Cookies)
	chain := []string{}
	chain = append(chain, s.HTTP.RedirectChain...)
	v["http.redirect_chain"] = chain
	if s.HTTP.TLS != nil {
		v["http.tls.sha256"] = s.HTTP.TLS.SHA256
	}
	v[FaviconField] = s.HTTP.FaviconSHA256
	if s.HTTP.FaviconUnstable {
		delete(v, FaviconField)
	}
	shown = make(map[string]any, len(v)+len(s.HTTP.Headers))
	for name, value := range v {
		shown[name] = value
	}
	for name, value := range s.HTTP.Headers {
		name = strings.ToLower(name)
		if volatile[name] {
			continue
		}
		v[headerFieldStart+name] = NormalizeHeader(name, value)
		shown[headerFieldStart+name] = value
	}
	return v, shown
}

func ChangedFields(old, cur map[string]any, probed bool) []string {
	names := map[string]bool{}
	for k := range old {
		names[k] = true
	}
	for k := range cur {
		names[k] = true
	}
	var changed []string
	for name := range names {
		if !probed && name != "product" && name != "version" {
			continue
		}
		o, inOld := old[name]
		n, inCur := cur[name]
		if name == FaviconField && (!inOld || !inCur) {
			continue
		}
		if reflect.DeepEqual(o, n) {
			continue
		}
		changed = append(changed, name)
	}
	sort.Strings(changed)
	return changed
}

type VolatileField struct {
	Field  string `json:"field"`
	Values []any  `json:"values"`
}

type FieldState struct {
	Probed bool                  `json:"probed"`
	Hashes map[string]any        `json:"hashes"`
	Track  map[string]FieldTrack `json:"track,omitempty"`
}

type FieldTrack struct {
	Changes  int   `json:"changes,omitempty"`
	Stable   int   `json:"stable,omitempty"`
	Volatile bool  `json:"volatile,omitempty"`
	Values   []any `json:"values,omitempty"`
}

func Learn(prev *FieldState, s ExportService) FieldState {
	compared, shown := ServiceFields(s, volatileHeaderSet())
	cur := FieldState{Probed: !ProbeFailed(s), Hashes: make(map[string]any, len(compared))}
	for name, v := range compared {
		b, _ := json.Marshal(v)
		sum := sha256.Sum256(b)
		cur.Hashes[name] = hex.EncodeToString(sum[:8])
	}
	if prev == nil {
		return cur
	}
	probed := prev.Probed && cur.Probed
	changed := map[string]bool{}
	for _, name := range ChangedFields(prev.Hashes, cur.Hashes, probed) {
		changed[name] = true
	}
	cur.Track = map[string]FieldTrack{}
	names := unionKeys(prev.Hashes, cur.Hashes)
	for name, t := range prev.Track {
		cur.Track[name] = t
		names[name] = true
	}
	for name := range names {
		_, inOld := prev.Hashes[name]
		_, inCur := cur.Hashes[name]
		if !probed && name != "product" && name != "version" || name == FaviconField && (!inOld || !inCur) {
			continue
		}
		t := cur.Track[name]
		switch {
		case changed[name] && t.Volatile && t.Stable >= VolatileAfter:
			t = FieldTrack{Changes: 1}
		case changed[name] && t.Volatile:
			t.Stable = 0
		case changed[name]:
			t.Changes++
			if t.Changes >= VolatileAfter {
				t.Volatile, t.Stable = true, 0
			}
		case t.Volatile:
			t.Stable++
		default:
			t = FieldTrack{}
		}
		if changed[name] {
			t.Values = append(t.Values, shown[name])
			if len(t.Values) > VolatileValues {
				t.Values = t.Values[len(t.Values)-VolatileValues:]
			}
		}
		if t.Changes == 0 && !t.Volatile {
			delete(cur.Track, name)
			continue
		}
		cur.Track[name] = t
	}
	if len(cur.Track) == 0 {
		cur.Track = nil
	}
	return cur
}

func (st FieldState) Volatile() []VolatileField {
	var out []VolatileField
	for name, t := range st.Track {
		if t.Volatile {
			out = append(out, VolatileField{Field: name, Values: nonNil(t.Values)})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Field < out[j].Field })
	return out
}

func volatileHeaderSet() map[string]bool {
	set := make(map[string]bool, len(DefaultVolatileHeaders))
	for _, h := range DefaultVolatileHeaders {
		set[h] = true
	}
	return set
}

func unionKeys(a, b map[string]any) map[string]bool {
	out := make(map[string]bool, len(a)+len(b))
	for k := range a {
		out[k] = true
	}
	for k := range b {
		out[k] = true
	}
	return out
}

func cookieSet(cookies []probe.Cookie) []string {
	names := make([]string, 0, len(cookies))
	for _, c := range cookies {
		names = append(names, c.Name)
	}
	return set(names)
}

func technologySet(techs []Technology) []string {
	items := make([]string, 0, len(techs))
	for _, t := range techs {
		item := t.Name
		if t.Version != "" {
			item += " " + t.Version
		}
		items = append(items, item)
	}
	return set(items)
}

func findingSet(findings []Finding) []string {
	ids := make([]string, 0, len(findings))
	for _, f := range findings {
		ids = append(ids, f.SignatureID)
	}
	return set(ids)
}

func set(items []string) []string {
	sort.Strings(items)
	out := []string{}
	for i, s := range items {
		if i > 0 && items[i-1] == s {
			continue
		}
		out = append(out, s)
	}
	return out
}
