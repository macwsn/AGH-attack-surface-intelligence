package detect

import (
	"bytes"
	"context"
	"regexp"
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
	Name       string `json:"name"`
	Category   string `json:"category"`
	Version    string `json:"version"`
	Confidence int    `json:"confidence"`
	Source     string `json:"source"`
}

type Finding struct {
	SignatureID string `json:"signature_id"`
	Kind        string `json:"kind"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Confidence  int    `json:"confidence"`
	Evidence    string `json:"evidence"`
}

type Result struct {
	Technologies []Technology
	Findings     []Finding
}

type fetcher interface {
	Fetch(ctx context.Context, path string) (*probe.Response, error)
}

func (s *Set) Detect(ctx context.Context, sess *probe.Session) Result {
	return s.detect(ctx, sess, &sess.HTTP)
}

func (s *Set) detect(ctx context.Context, f fetcher, h *probe.HTTP) Result {
	var res Result
	var techs []Technology
	responses := map[string]*probe.Response{}
	if root, err := f.Fetch(ctx, "/"); err == nil {
		responses["/"] = root
	}
	if s != nil {
		tried := map[string]bool{"/": true}
		for i := range s.Signatures {
			sig := &s.Signatures[i]
			if tried[sig.Path] || len(tried) > probe.MaxExtraRequests {
				continue
			}
			tried[sig.Path] = true
			if r, err := f.Fetch(ctx, sig.Path); err == nil {
				responses[sig.Path] = r
			}
		}
		for i := range s.Signatures {
			sig := &s.Signatures[i]
			r := responses[sig.Path]
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
				Evidence:    evidence(sig.Method + " " + sig.Path + ": " + strings.Join(ev, "; ")),
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
	return res
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
			if rule.re.Match(r.Body) {
				out = append(out, Technology{Name: rule.name, Category: rule.category, Confidence: rule.confidence, Source: SourceBuiltin})
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
	index := map[string]int{}
	for _, t := range techs {
		key := strings.ToLower(t.Name)
		i, ok := index[key]
		if !ok {
			index[key] = len(out)
			out = append(out, t)
			continue
		}
		cur := &out[i]
		if t.Confidence > cur.Confidence {
			t.Version = firstNonEmpty(t.Version, cur.Version)
			t.Category = firstNonEmpty(t.Category, cur.Category)
			*cur = t
			continue
		}
		cur.Version = firstNonEmpty(cur.Version, t.Version)
		cur.Category = firstNonEmpty(cur.Category, t.Category)
	}
	return out
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
