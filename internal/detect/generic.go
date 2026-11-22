package detect

import (
	"bytes"
	"encoding/json"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
	"golang.org/x/net/html"

	"asi/internal/probe"
)

const (
	SourceWappalyzer     = "wappalyzer"
	SourceHeuristic      = "heuristic"
	wappalyzerConfidence = 60
	heuristicConfidence  = 40
	genericAdminConf     = 50
	heuristicTitleID     = "builtin-heuristic-title"
	heuristicGeneratorID = "builtin-heuristic-generator"
	heuristicHeaderID    = "builtin-heuristic-header"
	heuristicMetaID      = "builtin-heuristic-app-metadata"
	heuristicTitleCorrID = "builtin-heuristic-title-corroborated"
	titleConfidence      = 30
	managementID         = "builtin-management-interface"
	installerID          = "builtin-unfinished-installation"
)

var fingerprints = sync.OnceValues(wappalyzer.New)

var wappalyzerCategories = map[string]string{
	"CMS":                   "cms",
	"Blogs":                 "cms",
	"Wikis":                 "cms",
	"DMS":                   "cms",
	"Message boards":        "cms",
	"Database managers":     "database-admin",
	"Databases":             "database",
	"Web servers":           "web-server",
	"Programming languages": "programming-language",
	"Web frameworks":        "web-framework",
	"JavaScript frameworks": "javascript-library",
	"JavaScript libraries":  "javascript-library",
	"UI frameworks":         "javascript-library",
	"Search engines":        "search-engine",
	"Webmail":               "webmail",
	"Network devices":       "network-device",
	"Webcams":               "camera",
	"CI":                    "ci-cd",
	"Containers":            "container-management",
	"Reverse proxies":       "reverse-proxy",
	"Load balancers":        "reverse-proxy",
	"Network storage":       "nas",
	"Authentication":        "identity",
	"Development":           "development-tool",
	"Analytics":             "monitoring",
	"Issue trackers":        "development-tool",
	"Hosting panels":        "web-application",
	"Remote access":         "web-application",
	"Miscellaneous":         "web-application",
}

var wappalyzerNames = map[string]string{
	"Apache HTTP Server":   "Apache",
	"Microsoft ASP.NET":    "ASP.NET",
	"Nginx":                "nginx",
	"Synology DiskStation": "Synology DSM",
}

var wappalyzerSkip = map[string]bool{
	"Basic": true, "HSTS": true, "Open Graph": true, "HTTP/3": true, "PWA": true, "RSS": true, "Priority Hints": true,
	"Cart Functionality": true,
}

func Wappalyzer(headers map[string]string, cookies []probe.Cookie, body []byte) []Technology {
	w, err := fingerprints()
	if err != nil {
		return nil
	}
	in := make(map[string][]string, len(headers)+1)
	for k, v := range headers {
		in[k] = []string{v}
	}
	if len(cookies) > 0 {
		var names []string
		for _, c := range cookies {
			names = append(names, c.Name+"=")
		}
		in["set-cookie"] = []string{strings.Join(names, " ")}
	}
	found := w.FingerprintWithInfo(in, body)
	withoutHeaders := w.FingerprintWithInfo(map[string][]string{"set-cookie": in["set-cookie"]}, body)
	implied, own := map[string]bool{}, map[string]bool{}
	for app := range found {
		name, _, _ := strings.Cut(app, ":")
		f := w.GetFingerprints().Apps[name]
		if _, ok := withoutHeaders[app]; !ok && (f == nil || !headerWordMatch(f.Headers, headers)) {
			continue
		}
		own[app] = true
		if f != nil {
			for _, imp := range f.Implies {
				imp, _, _ = strings.Cut(imp, `\;`)
				implied[imp] = true
			}
		}
	}
	var out []Technology
	for app, info := range found {
		name, version, _ := strings.Cut(app, ":")
		if !own[app] && !implied[name] {
			continue
		}
		if !exactVersion.MatchString(version) {
			version = ""
		}
		if wappalyzerSkip[name] {
			continue
		}
		if alias, ok := wappalyzerNames[name]; ok {
			name = alias
		}
		category := ""
		for _, c := range info.Categories {
			if category = wappalyzerCategories[c]; category != "" {
				break
			}
		}
		if category == "" && len(info.Categories) > 0 {
			category = strings.ToLower(strings.ReplaceAll(info.Categories[0], " ", "-"))
		}
		if implied[app] && (category == "database" || category == "search-engine") {
			continue
		}
		out = append(out, Technology{Name: name, Category: category, Version: version, Confidence: wappalyzerConfidence, Source: SourceWappalyzer})
	}
	slices.SortFunc(out, func(a, b Technology) int { return strings.Compare(a.Name, b.Name) })
	return Merge(out)
}

var (
	titleSep        = `\s*(?:[-–—|:·»]|::)\s*`
	installWords    = `(?:install(?:ation|er)?|setup|set up|setup wizard|installation wizard|first run)`
	loginWords      = `(?:sign[ -]?in|log[ -]?in|login)`
	panelWords      = `(?:admin(?:istration)?(?: console| panel| interface)?|console|dashboard|manager|management(?: console)?|web console|control panel)`
	productTitleRes = []*regexp.Regexp{
		regexp.MustCompile(`(?i)^` + installWords + titleSep + `(.+)$`),
		regexp.MustCompile(`(?i)^(.+?)` + titleSep + installWords + `$`),
		regexp.MustCompile(`(?i)^(.+?)\s+` + installWords + `$`),
		regexp.MustCompile(`(?i)^` + loginWords + `(?:\s+to)?(?:` + titleSep + `|\s+)(.+)$`),
		regexp.MustCompile(`(?i)^(.+?)` + titleSep + loginWords + `$`),
		regexp.MustCompile(`(?i)^(.+?)(?:` + titleSep + `|\s+)` + panelWords + `$`),
		regexp.MustCompile(`(?i)^` + panelWords + titleSep + `(.+)$`),
		regexp.MustCompile(`(?i)^welcome to\s+(.+?)[!.]?$`),
	}
	productTrailRe  = regexp.MustCompile(`(?i)(?:` + titleSep + `|\s+)` + panelWords + `$`)
	productVerRe    = regexp.MustCompile(`^(.*?)\s+v?([0-9]+(?:\.[0-9]+)+|[0-9]+)\b`)
	headerTokenRe   = regexp.MustCompile(`([A-Za-z][A-Za-z0-9_.-]*?)(?:/|\()v?([0-9]+(?:\.[0-9A-Za-z]+)*)`)
	headerCommentRe = regexp.MustCompile(`\s+\([^)]*\)`)
	versionHeaderRe = regexp.MustCompile(`^x-([a-z][a-z0-9]{2,})-version$`)
	headerVersionRe = regexp.MustCompile(`[0-9]+(?:\.[0-9]+)+`)
	installerPathRe = regexp.MustCompile(`(?i)/(?:install|installer|installation|setup)(?:[/._-]|$)`)
	installerTitle  = regexp.MustCompile(`(?i)(?:^|[\s\-–|:])` + installWords + `(?:$|[\s\-–|:])`)
	setupFlagRe     = regexp.MustCompile(`"(?:has[-_]user[-_]setup|setup[-_]complete|is[-_]installed|installed)"\s*:\s*false\b|"setup[-_]token"\s*:\s*"[^"]+"`)
	adminWordRe     = regexp.MustCompile(`(?i)\b(?:admin|console|manager|dashboard|log[ -]?in|sign[ -]?in)`)
	genericWords    = map[string]bool{
		"login": true, "log": true, "in": true, "sign": true, "signin": true, "dashboard": true, "home": true,
		"index": true, "of": true, "welcome": true, "admin": true, "administration": true, "administrator": true,
		"console": true, "panel": true, "control": true, "manager": true, "management": true, "interface": true,
		"setup": true, "installation": true, "install": true, "installer": true, "wizard": true, "web": true,
		"page": true, "site": true, "portal": true, "app": true, "application": true, "untitled": true,
		"document": true, "error": true, "loading": true, "redirect": true, "redirecting": true, "default": true,
		"test": true, "it": true, "works": true, "main": true, "start": true, "status": true, "overview": true,
		"not": true, "found": true, "forbidden": true, "unauthorized": true, "bad": true, "request": true,
		"server": true, "service": true, "the": true, "to": true, "your": true, "my": true, "a": true, "an": true,
		"and": true, "user": true, "account": true, "please": true, "wait": true, "new": true, "first": true,
		"run": true, "set": true, "up": true, "authentication": true, "auth": true, "required": true, "access": true,
		"denied": true, "online": true, "system": true, "react": true, "vite": true, "blank": true, "title": true,
		"homepage": true, "landing": true, "intranet": true, "blog": true, "website": true, "maintenance": true,
		"directory": true, "listing": true, "ok": true, "hello": true, "world": true, "nginx!": true,
		"api": true, "local": true, "localhost": true, "router": true, "camera": true, "printer": true,
		"metrics": true, "monitoring": true, "network": true, "storage": true, "cloud": true, "data": true,
		"file": true, "files": true, "media": true, "mail": true, "email": true, "video": true, "print": true,
		"backup": true, "logs": true, "report": true, "reports": true, "reporting": true, "search": true,
		"users": true, "device": true, "devices": true, "remote": true, "secure": true, "security": true,
		"services": true, "systems": true, "client": true, "company": true, "enterprise": true, "operations": true,
		"staging": true, "production": true, "demo": true, "office": true, "help": true, "support": true,
		"project": true, "projects": true, "docs": true, "documentation": true, "repository": true, "my-app": true,
		"settings": true, "config": true, "configuration": true, "info": true, "information": true, "store": true,
		"shop": true, "internal": true, "private": true, "public": true, "central": true, "global": true,
		"logowanie": true, "zaloguj": true, "się": true, "anmelden": true, "anmeldung": true, "connexion": true,
		"logon": true, "webmail": true, "vpn": true, "wiki": true, "helpdesk": true, "extranet": true, "continue": true,
		"runtime": true, "build": true, "content": true, "schema": true, "administracyjny": true, "strona": true,
		"główna": true, "witamy": true, "inicio": true, "accedi": true, "entrar": true, "iniciar": true, "sesión": true,
		"about": true, "us": true, "contact": true, "contacts": true, "news": true, "events": true, "event": true,
		"careers": true, "career": true, "jobs": true, "faq": true, "pricing": true, "products": true, "product": true,
		"team": true, "gallery": true, "privacy": true, "policy": true, "terms": true, "conditions": true, "cookies": true,
		"register": true, "registration": true, "signup": true, "profile": true, "cart": true, "checkout": true,
		"calendar": true, "articles": true, "article": true, "posts": true, "post": true, "category": true,
		"categories": true, "archive": true, "archives": true, "tags": true, "tag": true, "solutions": true,
		"partners": true, "customers": true, "downloads": true, "download": true, "resources": true, "forum": true,
		"community": true, "location": true, "locations": true, "sitemap": true, "kontakt": true, "aktualności": true,
	}
)

func productName(s string) string {
	s = strings.TrimSpace(strings.Trim(strings.TrimSpace(s), `"'!.,;:-–|`))
	for {
		t := strings.TrimSpace(productTrailRe.ReplaceAllString(s, ""))
		if t == s || t == "" {
			break
		}
		s = t
	}
	if s == "" || len(s) > 40 || strings.ContainsAny(s, "/<>[]{}()@#?=&") {
		return ""
	}
	words := strings.Fields(s)
	if len(words) > 4 {
		return ""
	}
	r := s[0]
	if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z') {
		return ""
	}
	generic := true
	for _, w := range words {
		if !genericWords[strings.ToLower(w)] {
			generic = false
		}
	}
	if generic {
		return ""
	}
	return s
}

type heuristic struct {
	tech    Technology
	finding Finding
}

var datasetNames = sync.OnceValue(func() map[string]string {
	out := map[string]string{}
	if w, err := fingerprints(); err == nil {
		for name := range w.GetFingerprints().Apps {
			out[strings.ToLower(name)] = name
		}
	}
	return out
})

func newHeuristic(id, name, version, ev string) heuristic {
	if canonical, ok := datasetNames()[strings.ToLower(name)]; ok {
		name = canonical
	}
	if alias, ok := wappalyzerNames[name]; ok {
		name = alias
	}
	return heuristic{
		tech:    Technology{Name: name, Version: version, Confidence: heuristicConfidence, Source: SourceHeuristic},
		finding: Finding{SignatureID: id, Kind: "technology", Name: name, Version: version, Confidence: heuristicConfidence, Evidence: evidence(ev)},
	}
}

func heuristics(h *probe.HTTP, body []byte, _ bool, fetched ...*probe.Response) []heuristic {
	if h == nil {
		return nil
	}
	var out []heuristic
	p := scanPage(body)
	p.apps = append(p.apps, manifestNames(h, p.manifest, fetched)...)
	for _, a := range p.apps {
		name, version := nameAndVersion(a.value)
		if name = productName(name); name != "" && len(strings.Fields(name)) <= 3 && !slices.ContainsFunc(out, func(hc heuristic) bool { return strings.EqualFold(hc.tech.Name, name) }) {
			out = append(out, newHeuristic(heuristicMetaID, name, version, a.tag+` "`+a.value+`"`))
		}
	}
	for _, g := range metaGenerators(body) {
		content, _, _ := strings.Cut(g, ";")
		content, _, _ = strings.Cut(content, " - ")
		content, _, _ = strings.Cut(content, "(")
		name, version := strings.TrimSpace(content), ""
		if m := productVerRe.FindStringSubmatch(name); m != nil {
			name, version = m[1], m[2]
		}
		if name = productName(name); name != "" {
			out = append(out, newHeuristic(heuristicGeneratorID, name, version, `meta generator "`+g+`"`))
		}
	}
	named := len(out) > 0
	if title := strings.TrimSpace(h.Title); title != "" {
		for _, re := range productTitleRes {
			m := re.FindStringSubmatch(title)
			if m == nil {
				continue
			}
			name, version := m[1], ""
			if v := productVerRe.FindStringSubmatch(name); v != nil {
				name, version = v[1], v[2]
			}
			if name = productName(name); name != "" {
				out = append(out, newHeuristic(heuristicTitleID, name, version, "title: "+title))
				named = true
				break
			}
		}
	}
	names := make([]string, 0, len(h.Headers))
	for k := range h.Headers {
		names = append(names, k)
	}
	slices.Sort(names)
	for _, k := range names {
		m := versionHeaderRe.FindStringSubmatch(k)
		if m == nil || genericWords[m[1]] {
			continue
		}
		if v := headerVersionRe.FindString(h.Headers[k]); v != "" {
			out = append(out, newHeuristic(heuristicHeaderID, strings.ToUpper(m[1][:1])+m[1][1:], v, k+": "+h.Headers[k]))
		}
	}
	for _, header := range []string{"server", "x-powered-by"} {
		v, ok := h.Headers[header]
		if !ok {
			continue
		}
		for _, m := range headerTokenRe.FindAllStringSubmatch(headerCommentRe.ReplaceAllString(v, ""), -1) {
			if name := productName(m[1]); name != "" {
				out = append(out, newHeuristic(heuristicHeaderID, name, m[2], header+": "+v))
			}
		}
	}
	if !named {
		if hc, ok := corroboratedTitle(h, p); ok {
			out = append(out, hc)
		}
	}
	return out
}

type appName struct{ tag, value string }

type page struct {
	apps                    []appName
	manifest                string
	assets, idents, globals []string
}

var (
	appMetaTags   = map[string]string{"application-name": "name", "og:site_name": "property", "apple-mobile-web-app-title": "name"}
	jsGlobalRe    = regexp.MustCompile(`\bwindow\.([A-Za-z_$][\w$]*)|\bwindow\[["']([^"']+)["']\]|(?:^|[;{}\s])(?:var|let|const)\s+([A-Za-z_$][\w$]*)`)
	titleSplitRe  = regexp.MustCompile(`\s+(?:-|\||·|::)\s+|:\s+|\s*[–—]\s*`)
	byVendorRe    = regexp.MustCompile(`(?i)\s+by\s+\S.*$`)
	explicitVerRe = regexp.MustCompile(`^v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)$`)
	titleWordRe   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+_'-]*$`)
	bareNumberRe  = regexp.MustCompile(`^v?[0-9]+$`)
	functionWords = map[string]bool{
		"the": true, "a": true, "an": true, "to": true, "of": true, "for": true, "and": true, "or": true, "is": true,
		"are": true, "was": true, "be": true, "your": true, "my": true, "our": true, "you": true, "we": true,
		"this": true, "that": true, "with": true, "in": true, "on": true, "at": true, "from": true, "please": true,
		"here": true, "not": true, "it": true, "has": true, "have": true,
	}
	hostLikeRe        = regexp.MustCompile(`[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+`)
	productCategories = map[string]bool{
		"cms": true, "database-admin": true, "database": true, "search-engine": true, "webmail": true,
		"network-device": true, "camera": true, "ci-cd": true, "container-management": true, "nas": true,
		"identity": true, "development-tool": true, "monitoring": true, "web-application": true,
	}
)

func scanPage(body []byte) page {
	var p page
	z := html.NewTokenizer(bytes.NewReader(body))
	inScript := false
	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			return p
		case html.TextToken:
			if inScript {
				for _, m := range jsGlobalRe.FindAllSubmatch(z.Text(), -1) {
					p.globals = append(p.globals, string(m[1])+string(m[2])+string(m[3]))
				}
			}
			continue
		case html.EndTagToken:
			inScript = false
			continue
		case html.StartTagToken, html.SelfClosingTagToken:
		default:
			continue
		}
		name, _ := z.TagName()
		tag := string(name)
		inScript = tag == "script" && tt == html.StartTagToken
		attrs := map[string]string{}
		for more := true; more; {
			var k, v []byte
			k, v, more = z.TagAttr()
			attrs[string(k)] = strings.TrimSpace(string(v))
		}
		if v := attrs["id"]; v != "" {
			p.idents = append(p.idents, v)
		}
		p.idents = append(p.idents, strings.Fields(attrs["class"])...)
		switch tag {
		case "meta":
			for _, key := range []string{"name", "property"} {
				k := strings.ToLower(attrs[key])
				if appMetaTags[k] == key && attrs["content"] != "" {
					p.apps = append(p.apps, appName{tag: `meta ` + key + `="` + k + `"`, value: attrs["content"]})
				}
			}
		case "link":
			if slices.Contains(strings.Fields(strings.ToLower(attrs["rel"])), "manifest") {
				p.manifest = attrs["href"]
			}
			p.assets = appendPath(p.assets, attrs["href"])
		case "script", "img":
			p.assets = appendPath(p.assets, attrs["src"])
		}
	}
}

func appendPath(to []string, ref string) []string {
	if ref == "" {
		return to
	}
	if u, err := url.Parse(ref); err == nil {
		ref = u.Path
	}
	return append(to, ref)
}

func manifestNames(h *probe.HTTP, href string, fetched []*probe.Response) []appName {
	if href == "" {
		return nil
	}
	base, err := url.Parse(pageOf(h))
	if err != nil {
		return nil
	}
	ref, err := base.Parse(href)
	if err != nil || ref.Host != base.Host {
		return nil
	}
	for _, r := range fetched {
		u, err := url.Parse(r.URL)
		if err != nil || u.Host != ref.Host || u.Path != ref.Path || r.StatusCode != 200 {
			continue
		}
		var m struct {
			Name      string `json:"name"`
			ShortName string `json:"short_name"`
		}
		if json.Unmarshal(r.Body, &m) != nil {
			continue
		}
		var out []appName
		for _, n := range []appName{{"manifest " + ref.Path + " name", m.Name}, {"manifest " + ref.Path + " short_name", m.ShortName}} {
			if n.value = strings.TrimSpace(n.value); n.value != "" {
				out = append(out, n)
			}
		}
		return out
	}
	return nil
}

func nameAndVersion(s string) (string, string) {
	words := strings.Fields(s)
	if n := len(words); n > 1 {
		if m := explicitVerRe.FindStringSubmatch(words[n-1]); m != nil {
			return strings.Join(words[:n-1], " "), m[1]
		}
	}
	return strings.Join(words, " "), ""
}

func titleSegment(seg string, h *probe.HTTP) (string, string) {
	seg = strings.TrimSpace(byVendorRe.ReplaceAllString(strings.TrimSpace(seg), ""))
	if strings.ContainsAny(seg[max(len(seg)-1, 0):], ".!?") {
		return "", ""
	}
	name, version := nameAndVersion(seg)
	words := strings.Fields(name)
	if len(words) == 0 || len(words) > 3 {
		return "", ""
	}
	generic := true
	for _, w := range words {
		lw := strings.ToLower(w)
		if !titleWordRe.MatchString(w) || functionWords[lw] {
			return "", ""
		}
		if !genericWords[lw] && !bareNumberRe.MatchString(lw) {
			generic = false
		}
	}
	if generic {
		return "", ""
	}
	for _, at := range []string{h.URL, pageOf(h)} {
		if u, err := url.Parse(at); err == nil && u.Hostname() != "" {
			host := strings.ToLower(u.Hostname())
			label, _, _ := strings.Cut(host, ".")
			if l := strings.ToLower(name); l == host || l == label {
				return "", ""
			}
		}
	}
	return name, version
}

func corroboratedTitle(h *probe.HTTP, p page) (heuristic, bool) {
	for _, seg := range titleSplitRe.Split(strings.TrimSpace(h.Title), -1) {
		name, version := titleSegment(seg, h)
		if name == "" {
			continue
		}
		words := strings.Fields(strings.ToLower(name))
		forms := slices.Compact([]string{strings.Join(words, ""), strings.Join(words, "-")})
		if len(forms[0]) < 3 {
			continue
		}
		where := corroboration(h, p, forms)
		if where == "" {
			continue
		}
		hc := newHeuristic(heuristicTitleCorrID, name, version, "page title, corroborated by "+where)
		hc.tech.Confidence, hc.finding.Confidence = titleConfidence, titleConfidence
		return hc, true
	}
	return heuristic{}, false
}

func corroboration(h *probe.HTTP, p page, forms []string) string {
	type source struct {
		label  string
		values []string
	}
	var cookies, headers, apps []string
	for _, c := range h.Cookies {
		cookies = append(cookies, c.Name)
	}
	names := make([]string, 0, len(h.Headers))
	for k := range h.Headers {
		names = append(names, k)
	}
	slices.Sort(names)
	for _, k := range names {
		headers = append(headers, k, hostLikeRe.ReplaceAllString(h.Headers[k], " "))
	}
	for _, a := range p.apps {
		v := strings.Join(strings.Fields(a.value), "-")
		apps = append(apps, v, strings.ReplaceAll(v, "-", ""))
	}
	for _, s := range []source{{"asset path", p.assets}, {"cookie", cookies}, {"header", headers}, {"element id/class", p.idents}, {"JS global", p.globals}, {"application metadata", apps}} {
		for _, v := range s.values {
			for _, f := range forms {
				if containsWord(v, f) {
					return s.label + " " + v
				}
			}
		}
	}
	return ""
}

func containsWord(s, word string) bool {
	lower := asciiLower(s)
	for i := 0; ; {
		j := strings.Index(lower[i:], word)
		if j < 0 {
			return false
		}
		start, end := i+j, i+j+len(word)
		if (start == 0 || !isAlnum(lower[start-1])) && (end == len(s) || !isAlnum(lower[end]) || s[end] >= 'A' && s[end] <= 'Z') {
			return true
		}
		i = start + 1
	}
}

func isAlnum(b byte) bool {
	return isLetter(b) || b >= '0' && b <= '9'
}

func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

func isLetter(b byte) bool {
	return b >= 'a' && b <= 'z'
}

func headerWordMatch(patterns, headers map[string]string) bool {
	for k, p := range patterns {
		v, ok := headers[strings.ToLower(k)]
		if !ok {
			continue
		}
		raw, _, _ := strings.Cut(p, `\;`)
		if raw == "" {
			return true
		}
		re, err := regexp.Compile("(?i)" + raw)
		if err != nil {
			return true
		}
		lower := asciiLower(v)
		for _, loc := range re.FindAllStringIndex(v, -1) {
			if (loc[0] == 0 || !isLetter(lower[loc[0]-1]) || loc[0] < loc[1] && !isLetter(lower[loc[0]])) &&
				(loc[1] == len(v) || !isLetter(lower[loc[1]]) || loc[0] < loc[1] && !isLetter(lower[loc[1]-1])) {
				return true
			}
		}
	}
	return false
}

func sameProduct(a, b string) bool {
	if alnum(a) == alnum(b) {
		return true
	}
	wa := strings.FieldsFunc(strings.ToLower(a), notWordRune)
	wb := strings.FieldsFunc(strings.ToLower(b), notWordRune)
	return coveredBy(wa, wb) || coveredBy(wb, wa)
}

func coveredBy(words, in []string) bool {
	if len(words) == 0 {
		return false
	}
	for _, w := range words {
		if !slices.ContainsFunc(in, func(x string) bool { return x == w || len(w) >= 4 && strings.HasPrefix(x, w) }) {
			return false
		}
	}
	return true
}

func notWordRune(r rune) bool {
	return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.')
}

func addHeuristics(res Result, hs []heuristic) Result {
	for _, hc := range hs {
		dup := false
		for i, t := range res.Technologies {
			if !sameProduct(t.Name, hc.tech.Name) {
				continue
			}
			dup = true
			if strings.EqualFold(t.Name, hc.tech.Name) || t.Source == SourceHeuristic && t.Version == "" {
				res.Technologies[i].Version = moreSpecific(t.Version, hc.tech.Version)
			}
		}
		if dup {
			continue
		}
		res.Technologies = append(res.Technologies, hc.tech)
		res.Findings = append(res.Findings, hc.finding)
	}
	return res
}

func pageOf(h *probe.HTTP) string {
	at := h.URL
	if n := len(h.RedirectChain); n > 0 {
		at = h.RedirectChain[n-1]
	}
	return at
}

func adminFindings(h *probe.HTTP, body []byte, matched []Finding) []Finding {
	if slices.ContainsFunc(matched, func(f Finding) bool { return f.Kind == KindAdminPanel }) {
		return nil
	}
	at := pageOf(h)
	path := at
	if u, err := url.Parse(at); err == nil {
		path = u.Path
	}
	switch {
	case installerTitle.MatchString(h.Title):
		return []Finding{{SignatureID: installerID, Kind: KindAdminPanel, Name: "Unfinished installation", Confidence: genericAdminConf, Evidence: evidence("installer page at " + at + ", title: " + h.Title)}}
	case installerPathRe.MatchString(path):
		return []Finding{{SignatureID: installerID, Kind: KindAdminPanel, Name: "Unfinished installation", Confidence: genericAdminConf, Evidence: evidence("installer page at " + at)}}
	}
	if m := setupFlagRe.Find(body); m != nil {
		return []Finding{{SignatureID: installerID, Kind: KindAdminPanel, Name: "Unfinished installation", Confidence: genericAdminConf, Evidence: evidence("setup not completed (" + string(m) + ") at " + at)}}
	}
	if hasLoginForm(body) {
		return []Finding{{SignatureID: loginFormID, Kind: KindAdminPanel, Name: "Login form", Confidence: genericAdminConf, Evidence: evidence("form with a password input at " + at)}}
	}
	if m := adminWordRe.FindString(h.Title); m != "" {
		return []Finding{{SignatureID: managementID, Kind: KindAdminPanel, Name: "Management interface", Confidence: genericAdminConf, Evidence: evidence("title " + h.Title + " at " + at)}}
	}
	if adminWordRe.MatchString(path) {
		return []Finding{{SignatureID: managementID, Kind: KindAdminPanel, Name: "Management interface", Confidence: genericAdminConf, Evidence: evidence("page " + at)}}
	}
	return nil
}

func alnum(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, strings.ToLower(s))
}
