package detect

import (
	"bytes"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/net/html"

	"asi/internal/probe"
)

const (
	KindInterestingHeader = "interesting-header"
	KindInterestingCookie = "interesting-cookie"
	KindAdminPanel        = "admin-panel"
	KindStaging           = "staging"
	loginFormID           = "builtin-login-form"
	stackCookieConfidence = 40
)

type headerRule struct {
	id, header, name string
	re               *regexp.Regexp
	token            bool
}

var (
	anyValue       = regexp.MustCompile(`\S`)
	versionNumber  = regexp.MustCompile(`[0-9]+\.[0-9]+|/[0-9]|\s[0-9]+(?:\s|$)`)
	internalViaRe  = regexp.MustCompile(`(?i)(?:^|[\s,(])(?:10\.[0-9]+\.[0-9]+\.[0-9]+|192\.168\.[0-9]+\.[0-9]+|172\.(?:1[6-9]|2[0-9]|3[01])\.[0-9]+\.[0-9]+|localhost|[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:local|localdomain|internal|intranet|lan|corp|home\.arpa))(?::[0-9]+)?(?:$|[\s,)])`)
	sessionCookie  = regexp.MustCompile(`(?i)sess|^sid$|[._-]sid$|^phpmyadmin$|^pmaAuth|^wordpress_(?:logged_in_|sec_|[0-9a-f]{32}$)`)
	notableHeaders = []headerRule{
		{"builtin-header-x-powered-by", "X-Powered-By", "Version disclosed in X-Powered-By", versionNumber, false},
		{"builtin-header-x-aspnet-version", "X-AspNet-Version", "Version disclosed in X-AspNet-Version", anyValue, false},
		{"builtin-header-x-aspnetmvc-version", "X-AspNetMvc-Version", "Version disclosed in X-AspNetMvc-Version", anyValue, false},
		{"builtin-header-x-generator", "X-Generator", "Version disclosed in X-Generator", versionNumber, false},
		{"builtin-header-server", "Server", "Version disclosed in Server", versionNumber, false},
		{"builtin-header-x-debug-token", "X-Debug-Token", "Debug header exposed", anyValue, true},
		{"builtin-header-x-debug-token-link", "X-Debug-Token-Link", "Debug header exposed", anyValue, true},
		{"builtin-header-x-environment", "X-Environment", "Environment header exposed", anyValue, false},
		{"builtin-header-x-backend-server", "X-Backend-Server", "Backend server header exposed", anyValue, false},
		{"builtin-header-x-served-by", "X-Served-By", "Backend server header exposed", anyValue, false},
		{"builtin-header-via", "Via", "Internal name in Via", internalViaRe, false},
	}
	stagingWord    = regexp.MustCompile(`(?i)(?:^|[^a-z0-9])(staging|stage|test|dev|uat|preprod|sandbox)(?:[^a-z0-9]|$)`)
	stagingMarker  = regexp.MustCompile(`(?i)[\[(](staging|stage|test|dev|uat|preprod|sandbox)[\])]`)
	stagingValue   = regexp.MustCompile(`(?i)^\s*(staging|stage|test|testing|dev|development|uat|preprod|sandbox)(?:[^a-z0-9]|$)`)
	stagingHeaders = []string{"X-Environment", "X-Env", "X-Stage"}
	stackCookies   = []stackCookie{
		{regexp.MustCompile(`^PHPSESSID$`), "PHP", "programming-language"},
		{regexp.MustCompile(`^JSESSIONID(?:\.[0-9a-f]+)?$`), "Java", "programming-language"},
		{regexp.MustCompile(`^ASP\.NET_SessionId$`), "ASP.NET", "web-framework"},
		{regexp.MustCompile(`^laravel_session$`), "Laravel", "web-framework"},
		{regexp.MustCompile(`^connect\.sid$`), "Express", "web-framework"},
		{regexp.MustCompile(`^phpMyAdmin$`), "phpMyAdmin", "database-admin"},
		{regexp.MustCompile(`^wordpress_`), "WordPress", "cms"},
	}
)

type stackCookie struct {
	re             *regexp.Regexp
	name, category string
}

func (s *Set) withNotable(res Result, h *probe.HTTP, body []byte) Result {
	if s == nil || !slices.ContainsFunc(s.Signatures, func(sig Signature) bool { return sig.builtin }) {
		return res
	}
	findings, techs := notable(h, body, res.Findings)
	res.Findings = append(res.Findings, findings...)
	if h != nil {
		cookies := slices.DeleteFunc(slices.Clone(h.Cookies), func(c probe.Cookie) bool {
			return slices.ContainsFunc(stackCookies, func(sc stackCookie) bool { return sc.re.MatchString(c.Name) })
		})
		techs = append(techs, Wappalyzer(h.Headers, cookies, body)...)
	}
	res.Technologies = Merge(append(res.Technologies, techs...))
	hs := heuristics(h, body, false, res.fetched...)
	if slices.ContainsFunc(res.Technologies, func(t Technology) bool { return productCategories[t.Category] }) {
		hs = slices.DeleteFunc(hs, func(hc heuristic) bool { return hc.finding.SignatureID == heuristicTitleCorrID })
	}
	res = addHeuristics(res, hs)
	res.Findings = MergeFindings(res.Findings)
	return res
}

func notable(h *probe.HTTP, body []byte, matched []Finding) ([]Finding, []Technology) {
	if h == nil {
		return nil, nil
	}
	var out []Finding
	for _, rule := range notableHeaders {
		v, ok := h.Headers[strings.ToLower(rule.header)]
		if !ok || !rule.re.MatchString(v) {
			continue
		}
		if rule.token {
			v = "<token redacted, " + strconv.Itoa(len(v)) + " characters>"
		}
		out = append(out, Finding{SignatureID: rule.id, Kind: KindInterestingHeader, Name: rule.name, Confidence: 80, Evidence: evidence(rule.header + ": " + v)})
	}
	var techs []Technology
	var stack, noHTTPOnly, noSecure []string
	for _, c := range h.Cookies {
		for _, sc := range stackCookies {
			if sc.re.MatchString(c.Name) {
				stack = append(stack, c.Name+" ("+sc.name+")")
				techs = append(techs, Technology{Name: sc.name, Category: sc.category, Confidence: stackCookieConfidence, Source: SourceBuiltin})
				break
			}
		}
		if !sessionCookie.MatchString(c.Name) {
			continue
		}
		if !c.HTTPOnly {
			noHTTPOnly = append(noHTTPOnly, c.Name)
		}
		if !c.Secure && h.Scheme == "https" {
			noSecure = append(noSecure, c.Name)
		}
	}
	if len(stack) > 0 {
		out = append(out, Finding{SignatureID: "builtin-cookie-stack", Kind: KindInterestingCookie, Name: "Session cookie identifies the stack", Confidence: 60, Evidence: evidence("cookie " + strings.Join(stack, ", "))})
	}
	if len(noHTTPOnly) > 0 {
		out = append(out, Finding{SignatureID: "builtin-cookie-no-httponly", Kind: KindInterestingCookie, Name: "Session cookie without HttpOnly", Confidence: 70, Evidence: evidence("cookie " + strings.Join(noHTTPOnly, ", ") + " set without HttpOnly")})
	}
	if len(noSecure) > 0 {
		out = append(out, Finding{SignatureID: "builtin-cookie-no-secure", Kind: KindInterestingCookie, Name: "Session cookie without Secure on HTTPS", Confidence: 70, Evidence: evidence("cookie " + strings.Join(noSecure, ", ") + " set without Secure on " + h.URL)})
	}
	out = append(out, staging(h)...)
	out = append(out, adminFindings(h, body, matched)...)
	return out, techs
}

func hasLoginForm(body []byte) bool {
	z := html.NewTokenizer(bytes.NewReader(body))
	depth := 0
	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			return false
		case html.EndTagToken:
			if name, _ := z.TagName(); string(name) == "form" && depth > 0 {
				depth--
			}
		case html.StartTagToken, html.SelfClosingTagToken:
			name, hasAttr := z.TagName()
			switch string(name) {
			case "form":
				if tt == html.StartTagToken {
					depth++
				}
			case "input":
				for hasAttr && depth > 0 {
					var k, v []byte
					k, v, hasAttr = z.TagAttr()
					if string(k) == "type" && strings.EqualFold(strings.TrimSpace(string(v)), "password") {
						return true
					}
				}
			}
		}
	}
}

func staging(h *probe.HTTP) []Finding {
	var out []Finding
	for _, name := range stagingHeaders {
		if v := h.Headers[strings.ToLower(name)]; stagingValue.MatchString(v) {
			out = append(out, Finding{SignatureID: "builtin-staging-header", Kind: KindStaging, Name: "Staging or test environment", Confidence: 75, Evidence: evidence(name + ": " + v)})
			break
		}
	}
	if u, err := url.Parse(h.URL); err == nil && stagingWord.MatchString(u.Hostname()) {
		out = append(out, Finding{SignatureID: "builtin-staging-hostname", Kind: KindStaging, Name: "Staging or test environment", Confidence: 65, Evidence: evidence("hostname " + u.Hostname())})
	}
	switch {
	case stagingMarker.MatchString(h.Title):
		out = append(out, Finding{SignatureID: "builtin-staging-title", Kind: KindStaging, Name: "Staging or test environment", Confidence: 70, Evidence: evidence("title " + h.Title)})
	case stagingWord.MatchString(h.Title):
		out = append(out, Finding{SignatureID: "builtin-staging-title", Kind: KindStaging, Name: "Staging or test environment", Confidence: 60, Evidence: evidence("title " + h.Title)})
	}
	return out
}
