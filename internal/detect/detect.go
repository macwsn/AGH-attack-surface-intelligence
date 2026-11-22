package detect

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/net/html"

	"asi/internal/probe"
)

const (
	SourceBuiltin   = "builtin"
	maxEvidenceLen  = 200
	signatureSource = "signature:"
)

type Technology struct {
	Name          string `json:"name"`
	Category      string `json:"category"`
	Version       string `json:"version"`
	Confidence    int    `json:"confidence"`
	ConfidenceRaw *int   `json:"confidence_raw,omitempty"`
	Source        string `json:"source"`
}

type Finding struct {
	SignatureID string `json:"signature_id"`
	Kind        string `json:"kind"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Confidence  int    `json:"confidence"`
	Evidence    string `json:"evidence"`
	Source      string `json:"source,omitempty"`
}

type Result struct {
	Technologies []Technology
	Findings     []Finding
	fetched      []*probe.Response
}

type fetcher interface {
	Fetch(ctx context.Context, path string) (*probe.Response, error)
}

type headFetcher interface {
	Head(ctx context.Context, path string) (*probe.Response, error)
}

func (s *Set) Detect(ctx context.Context, sess *probe.Session) Result {
	return s.withNotable(s.detect(ctx, sess, &sess.HTTP), &sess.HTTP, sess.Body)
}

func (s *Set) DetectRecorded(h *probe.HTTP) Result {
	r := &probe.Response{URL: h.URL, StatusCode: h.StatusCode, Title: h.Title, Headers: h.Headers, Cookies: h.Cookies, RedirectChain: h.RedirectChain}
	return s.withNotable(s.detect(context.Background(), recorded{r}, h), h, nil)
}

type recorded struct{ root *probe.Response }

func (f recorded) Fetch(_ context.Context, path string) (*probe.Response, error) {
	if path != "/" {
		return nil, fmt.Errorf("detect: no recorded response for %s", path)
	}
	return f.root, nil
}

func (s *Set) detect(ctx context.Context, f fetcher, h *probe.HTTP) Result {
	var res Result
	var techs []Technology
	responses := map[string]*probe.Response{}
	if root, err := f.Fetch(ctx, "/"); err == nil {
		responses["/"] = root
	}
	if s != nil {
		head, canHead := f.(headFetcher)
		key := func(sig *Signature) string {
			if canHead && sig.Method == http.MethodHead && sig.Path != "/" {
				return http.MethodHead + " " + sig.Path
			}
			return sig.Path
		}
		tried := map[string]bool{"/": true}
		for _, builtin := range []bool{false, true} {
			for i := range s.Signatures {
				sig := &s.Signatures[i]
				k := key(sig)
				if sig.builtin != builtin || tried[k] || len(tried) > probe.MaxExtraRequests {
					continue
				}
				tried[k] = true
				fetch := f.Fetch
				if k != sig.Path {
					fetch = head.Head
				}
				if r, err := fetch(ctx, sig.Path); err == nil {
					responses[k] = r
				}
			}
		}
		for i := range s.Signatures {
			sig := &s.Signatures[i]
			r := responses[key(sig)]
			if r == nil {
				continue
			}
			ok, ev := sig.evaluate(r, h)
			if !ok {
				continue
			}
			version := ""
			if sig.Version != nil {
				version = sig.Version.extract(r)
			}
			res.Findings = append(res.Findings, Finding{
				SignatureID: sig.ID,
				Kind:        sig.Kind,
				Name:        sig.Name,
				Version:     version,
				Confidence:  sig.Confidence,
				Evidence:    sig.Evidence(ev),
			})
			if sig.Kind == "technology" {
				techs = append(techs, Technology{Name: sig.Name, Category: sig.Category, Version: version, Confidence: sig.Confidence, Source: signatureSource + sig.ID})
			}
		}
	}
	if root := responses["/"]; root != nil {
		techs = append(techs, Builtin(root)...)
	}
	res.Technologies = Merge(techs)
	res.Findings = MergeFindings(res.Findings)
	for _, r := range responses {
		res.fetched = append(res.fetched, r)
	}
	return res
}

const alsoMatchedBy = "; also matched by "

var evidenceHeader = regexp.MustCompile(`^(?:[A-Z]+ [^ ]*: header ([A-Za-z0-9-]+) |([A-Za-z0-9-]+): )`)

func mergeKey(f Finding) string {
	subject := f.Name
	switch f.Kind {
	case KindAdminPanel, KindStaging:
		subject = ""
	case KindInterestingHeader:
		if m := evidenceHeader.FindStringSubmatch(f.Evidence); m != nil {
			subject = "header " + strings.ToLower(m[1]+m[2])
		}
	}
	return f.Kind + "\x00" + subject + "\x00" + f.Version
}

func MergeFindings(in []Finding) []Finding {
	var out []Finding
	var keys []string
	var groups [][]Finding
	for _, f := range in {
		k := mergeKey(f)
		i := slices.Index(keys, k)
		if i < 0 {
			out = append(out, f)
			keys = append(keys, k)
			groups = append(groups, []Finding{f})
			continue
		}
		groups[i] = append(groups[i], f)
		if user, cur := !strings.HasPrefix(f.SignatureID, PackIDPrefix), !strings.HasPrefix(out[i].SignatureID, PackIDPrefix); user && !cur ||
			user == cur && f.Confidence > out[i].Confidence {
			out[i] = f
		}
	}
	for i, group := range groups {
		if len(group) == 1 {
			continue
		}
		best := &out[i]
		ev, also, _ := strings.Cut(best.Evidence, alsoMatchedBy)
		ids := strings.Split(also, ", ")
		if also == "" {
			ids = nil
		}
		for _, f := range group {
			best.Confidence = max(best.Confidence, f.Confidence)
			_, more, _ := strings.Cut(f.Evidence, alsoMatchedBy)
			for _, id := range append([]string{f.SignatureID}, strings.Split(more, ", ")...) {
				if id != "" && id != best.SignatureID && !slices.Contains(ids, id) {
					ids = append(ids, id)
				}
			}
		}
		if len(ids) > 0 {
			best.Evidence = ev + alsoMatchedBy + strings.Join(ids, ", ")
		}
	}
	return out
}

func evidence(s string) string {
	r := []rune(s)
	if len(r) <= maxEvidenceLen {
		return s
	}
	return string(r[:maxEvidenceLen-1]) + "…"
}

type builtinRule struct {
	name, category string
	confidence     int
	header         string
	cookie         bool
	generator      bool
	body           bool
	re             *regexp.Regexp
}

const versionRe = `([0-9]+(?:\.[0-9]+)*)`

var builtinRules = []builtinRule{
	{name: "nginx", category: "web-server", confidence: 90, header: "server", re: regexp.MustCompile(`(?i)\bnginx(?:/` + versionRe + `)?`)},
	{name: "Apache", category: "web-server", confidence: 90, header: "server", re: regexp.MustCompile(`(?i)(?:^|\s)apache(?:/` + versionRe + `)?(?:\s|$)`)},
	{name: "PHP", category: "programming-language", confidence: 90, header: "x-powered-by", re: regexp.MustCompile(`(?i)\bphp(?:/` + versionRe + `)?`)},
	{name: "PHP", category: "programming-language", confidence: 90, header: "server", re: regexp.MustCompile(`(?i)\bphp/` + versionRe)},
	{name: "PHP", category: "programming-language", confidence: 60, cookie: true, re: regexp.MustCompile(`^PHPSESSID$`)},
	{name: "WordPress", category: "cms", confidence: 95, generator: true, re: regexp.MustCompile(`(?i)^wordpress(?:\s+` + versionRe + `)?`)},
	{name: "WordPress", category: "cms", confidence: 80, header: "link", re: regexp.MustCompile(`/wp-json/|api\.w\.org`)},
	{name: "WordPress", category: "cms", confidence: 60, cookie: true, re: regexp.MustCompile(`^wordpress_`)},
	{name: "WordPress", category: "cms", confidence: 70, body: true, re: regexp.MustCompile(`/wp-(?:content|includes)/`)},
	{name: "Drupal", category: "cms", confidence: 95, generator: true, re: regexp.MustCompile(`(?i)^drupal(?:\s+` + versionRe + `)?`)},
	{name: "Drupal", category: "cms", confidence: 90, header: "x-generator", re: regexp.MustCompile(`(?i)^drupal(?:\s+` + versionRe + `)?`)},
	{name: "Drupal", category: "cms", confidence: 80, header: "x-drupal-cache", re: regexp.MustCompile(``)},
	{name: "Drupal", category: "cms", confidence: 80, header: "x-drupal-dynamic-cache", re: regexp.MustCompile(``)},
	{name: "Drupal", category: "cms", confidence: 70, body: true, re: regexp.MustCompile(`data-drupal-selector|drupal-settings-json|/sites/default/files/`)},
	{name: "Drupal", category: "cms", confidence: 70, body: true, re: regexp.MustCompile(`\bcore/misc/drupal(?:\.init)?\.js\?v=([0-9]+(?:\.[0-9]+)+)`)},
	{name: "Joomla", category: "cms", confidence: 95, generator: true, re: regexp.MustCompile(`(?i)^joomla!?(?:\s+` + versionRe + `)?`)},
	{name: "Joomla", category: "cms", confidence: 60, body: true, re: regexp.MustCompile(`/media/(?:jui|system)/js/`)},
}

func Builtin(r *probe.Response) []Technology {
	generators := metaGenerators(r.Body)
	var out []Technology
	for _, rule := range builtinRules {
		var values []string
		switch {
		case rule.header != "":
			if v, ok := r.Headers[rule.header]; ok {
				values = []string{v}
			}
		case rule.cookie:
			for _, c := range r.Cookies {
				values = append(values, c.Name)
			}
		case rule.generator:
			values = generators
		case rule.body:
			if m := rule.re.FindSubmatch(r.Body); m != nil {
				t := Technology{Name: rule.name, Category: rule.category, Confidence: rule.confidence, Source: SourceBuiltin}
				if len(m) > 1 {
					t.Version = string(m[1])
				}
				out = append(out, t)
			}
		}
		for _, v := range values {
			m := rule.re.FindStringSubmatch(v)
			if m == nil {
				continue
			}
			t := Technology{Name: rule.name, Category: rule.category, Confidence: rule.confidence, Source: SourceBuiltin}
			if len(m) > 1 {
				t.Version = m[1]
			}
			out = append(out, t)
			break
		}
	}
	return Merge(out)
}

func metaGenerators(body []byte) []string {
	var out []string
	z := html.NewTokenizer(bytes.NewReader(body))
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			return out
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}
		name, hasAttr := z.TagName()
		if string(name) != "meta" || !hasAttr {
			continue
		}
		var isGen bool
		var content string
		for {
			k, v, more := z.TagAttr()
			switch string(k) {
			case "name":
				isGen = strings.EqualFold(string(v), "generator")
			case "content":
				content = strings.TrimSpace(string(v))
			}
			if !more {
				break
			}
		}
		if isGen && content != "" {
			out = append(out, content)
		}
	}
}

func Merge(techs []Technology) []Technology {
	var out []Technology
	var origins []string
	for _, t := range techs {
		o := origin(t.Source)
		i := -1
		for j, c := range out {
			if strings.EqualFold(c.Name, t.Name) && (origins[j] == o || anyOrigin(origins[j]) || anyOrigin(o)) {
				i = j
				break
			}
		}
		if i < 0 {
			out = append(out, t)
			origins = append(origins, o)
			continue
		}
		if anyOrigin(origins[i]) {
			origins[i] = o
		}
		cur := &out[i]
		if t.Confidence > cur.Confidence {
			t.Version = moreSpecific(t.Version, cur.Version)
			t.Category = firstNonEmpty(t.Category, cur.Category)
			*cur = t
			continue
		}
		cur.Version = moreSpecific(cur.Version, t.Version)
		cur.Category = firstNonEmpty(cur.Category, t.Category)
	}
	return out
}

func anyOrigin(o string) bool {
	return o == SourceBuiltin || o == SourceWappalyzer || o == SourceHeuristic
}

func origin(source string) string {
	if strings.HasPrefix(source, signatureSource+PackIDPrefix) {
		return signatureSource + PackIDPrefix
	}
	return source
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func moreSpecific(a, b string) string {
	if a == "" || strings.HasPrefix(b, a+".") {
		return b
	}
	return a
}
