package detect

import (
	"context"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"asi/internal/probe"
)

type selfDescribedCase struct {
	name    string
	url     string
	title   string
	headers map[string]string
	cookies []string
	body    string
	admin   bool
	want    string
	conf    int
	ev      string
}

func runSelfDescribed(t *testing.T, c selfDescribedCase, fetched ...*probe.Response) []heuristic {
	t.Helper()
	headers := c.headers
	if headers == nil {
		headers = map[string]string{}
	}
	u := c.url
	if u == "" {
		u = "http://192.0.2.7/"
	}
	h := &probe.HTTP{Scheme: "http", URL: u, StatusCode: 200, Title: c.title, Headers: headers}
	for _, n := range c.cookies {
		h.Cookies = append(h.Cookies, probe.Cookie{Name: n})
	}
	return slices.DeleteFunc(heuristics(h, []byte(c.body), c.admin, fetched...), func(hc heuristic) bool {
		return hc.finding.SignatureID == heuristicHeaderID
	})
}

func checkSelfDescribed(t *testing.T, c selfDescribedCase, got []heuristic) {
	t.Helper()
	if c.want == "" {
		if len(got) != 0 {
			t.Fatalf("heuristics = %+v, want none", got)
		}
		return
	}
	if len(got) != 1 {
		t.Fatalf("heuristics = %+v, want one %q", got, c.want)
	}
	hc := got[0]
	if name := strings.TrimSpace(hc.tech.Name + " " + hc.tech.Version); name != c.want {
		t.Errorf("technology = %q, want %q", name, c.want)
	}
	if hc.tech.Source != SourceHeuristic || hc.tech.Confidence != c.conf || hc.finding.Confidence != c.conf || hc.finding.Kind != "technology" {
		t.Errorf("heuristic %+v, want source heuristic and confidence %d", hc, c.conf)
	}
	if !strings.Contains(hc.finding.Evidence, c.ev) {
		t.Errorf("evidence = %q, want it to contain %q", hc.finding.Evidence, c.ev)
	}
}

// REQ-SIGNATURES-021: application metadata and corroborated page titles on synthetic pages of invented products.
func TestSelfDescribedProduct(t *testing.T) {
	cases := []selfDescribedCase{
		{name: "application-name", body: `<meta name="application-name" content="Gravelin">`, want: "Gravelin", conf: 40, ev: `meta name="application-name" "Gravelin"`},
		{name: "og:site_name with a generic word", body: `<meta property="og:site_name" content="Wrenfield Docs">`, want: "Wrenfield Docs", conf: 40, ev: `meta property="og:site_name"`},
		{name: "apple-mobile-web-app-title with version", body: `<meta name="apple-mobile-web-app-title" content="Pomander 3.1">`, want: "Pomander 3.1", conf: 40, ev: "apple-mobile-web-app-title"},
		{name: "metadata wins over the title", title: "Overview - Stellbrook", body: `<meta name="application-name" content="Stellbrook"><script src="/stellbrook.js"></script>`, want: "Stellbrook", conf: 40, ev: "application-name"},
		{name: "asset path script", title: "Quorvel", body: `<script src="/static/js/quorvel.min.js?v=12"></script>`, want: "Quorvel", conf: 30, ev: "page title, corroborated by asset path /static/js/quorvel.min.js"},
		{name: "asset path link, two words hyphenated", title: "Brindle Hub", body: `<link rel="stylesheet" href="/assets/brindle-hub.css">`, want: "Brindle Hub", conf: 30, ev: "asset path /assets/brindle-hub.css"},
		{name: "asset path img, words joined", title: "Tarn Wick", body: `<img src="/img/tarnwick-logo.png">`, want: "Tarn Wick", conf: 30, ev: "asset path /img/tarnwick-logo.png"},
		{name: "cookie name", title: "Velmora | Overview", cookies: []string{"velmora_session"}, want: "Velmora", conf: 30, ev: "page title, corroborated by cookie velmora_session"},
		{name: "header name", title: "Oskvane", headers: map[string]string{"x-oskvane-node": "eu-1"}, want: "Oskvane", conf: 30, ev: "header x-oskvane-node"},
		{name: "header value", title: "Plinth Relay", headers: map[string]string{"via": "1.1 plinth-relay"}, want: "Plinth Relay", conf: 30, ev: "header"},
		{name: "element id", title: "Mossgate", body: `<div id="mossgate-root"></div>`, want: "Mossgate", conf: 30, ev: "element id/class mossgate-root"},
		{name: "element class", title: "Kestrine Mail", body: `<body class="theme-dark kestrine-mail">`, want: "Kestrine Mail", conf: 30, ev: "element id/class kestrine-mail"},
		{name: "JS global on window", title: "Driftlock", body: `<script>window.__DRIFTLOCK_CONFIG__ = {"a":1}</script>`, want: "Driftlock", conf: 30, ev: "JS global __DRIFTLOCK_CONFIG__"},
		{name: "JS global declared", title: "Ambergrid", body: `<script>var ambergridApp = {};</script>`, want: "Ambergrid", conf: 30, ev: "JS global ambergridApp"},
		{name: "application metadata too long to name it", title: "Halvard Notes", body: `<meta name="application-name" content="Halvard Notes Server Edition">`, want: "Halvard Notes", conf: 30, ev: "application metadata"},
		{name: "explicit version next to the name", title: "Quillon 4.2.1 · Home", body: `<script src="/quillon/app.js"></script>`, want: "Quillon 4.2.1", conf: 30, ev: "asset path /quillon/app.js"},
		{name: "trailing by vendor dropped", title: "Larkspur Board by Fennic Labs", body: `<script src="/static/larkspur-board/main.js"></script>`, want: "Larkspur Board", conf: 30, ev: "asset path"},
		{name: "em dash", title: "Corvane — Overview", cookies: []string{"corvane-sid"}, want: "Corvane", conf: 30, ev: "cookie corvane-sid"},
		{name: "double colon", title: "Status :: Pellucid", body: `<main id="pellucid"></main>`, want: "Pellucid", conf: 30, ev: "element id/class pellucid"},
		{name: "colon", title: "Home: Fernwold", body: `<script src="/js/fernwold.js"></script>`, want: "Fernwold", conf: 30, ev: "asset path"},
		{name: "admin page keeps confidence 30", title: "Hexmoor", body: `<script src="/hexmoor.js"></script><form><input type="password"></form>`, admin: true, want: "Hexmoor", conf: 30, ev: "page title, corroborated by asset path /hexmoor.js"},

		{name: "ordinary page name in a body class", title: "Contact Us | Harbor Supply", body: `<body class="page contact-us"><div id="contact-form"></div>`},
		{name: "ordinary page name in an id", title: "About Us - Harbor Supply", body: `<section id="about-us"></section><script src="/js/about.js"></script>`},
		{name: "ordinary page name in an asset path", title: "Careers · Harbor Supply", body: `<link rel="stylesheet" href="/css/careers.css">`},
		{name: "lab: Campus Blog", title: "Campus Blog", body: `<h1>Campus Blog</h1><footer>Proudly powered by WordPress</footer>`},
		{name: "lab: Campus Portal", title: "Campus Portal", body: `<h1>Campus Portal</h1>`},
		{name: "lab: [STAGING] Rekrutacja", title: "[STAGING] Rekrutacja", headers: map[string]string{"x-environment": "staging"}, body: `<h1>Rekrutacja (staging)</h1><script src="/rekrutacja/app.js"></script>`},
		{name: "lab: Intranet v1", title: "Intranet v1", body: `<link href="/intranet/v1.css">Intranet`},
		{name: "lab: Admin Panel - Sign in", title: "Admin Panel - Sign in", cookies: []string{"PHPSESSID"}, body: `<link href="/admin/panel.css"><form><input type="password"></form>`, admin: true},
		{name: "lab: NETCAM Web Client", title: "NETCAM Web Client", body: `<link rel="icon" href="/favicon.ico"><div id="live-view">Live view</div>`},
		{name: "lab: Host 10.x", title: "Host 10.x", body: `<script src="/host/10.x.js"></script>`},
		{name: "blog title matched only in body text", title: "Hollin Grove", body: `<h1>Hollin Grove</h1><p>News from Hollin Grove and hollin grove events.</p><a href="/about">hollingrove</a>`},
		{name: "default web server page", title: "Apache2 Debian Default Page: It works", headers: map[string]string{"server": "Apache/2.4.62 (Debian)"}, body: `<link href="/icons/openlogo-75.png"><div class="page_header">It works!</div>`},
		{name: "default IIS page", title: "IIS Windows Server", headers: map[string]string{"server": "Microsoft-IIS/10.0"}, body: `<img src="iisstart.png" alt="IIS">`},
		{name: "title equal to the host name", url: "http://brackenfold/", title: "brackenfold", cookies: []string{"brackenfold_sid"}, body: `<script src="/brackenfold.js"></script>`},
		{name: "title is a host name", title: "srv01.example.org", body: `<script src="/srv01.example.org.js"></script>`},
		{name: "title is an address", title: "192.0.2.7", body: `<script src="/192.0.2.7.js"></script>`},
		{name: "host name only in a header", title: "Ravelin", headers: map[string]string{"content-security-policy": "default-src 'self' https://cdn.ravelin.example"}},
		{name: "name inside a longer word", title: "Vant", body: `<script src="/static/vantage.js"></script>`},
		{name: "sentence", title: "Zorvik is starting.", body: `<script src="/zorvik.js"></script>`},
		{name: "four words", title: "Grand Old Ferry Line", body: `<script src="/grand-old-ferry-line.js"></script>`},
		{name: "generic metadata", body: `<meta name="application-name" content="Dashboard"><meta property="og:site_name" content="Home">`},
		{name: "long og:site_name", body: `<meta property="og:site_name" content="Daily News From The Campus">`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			checkSelfDescribed(t, c, runSelfDescribed(t, c))
		})
	}
}

// REQ-SIGNATURES-021: a manifest counts only when it was already fetched; detection never requests it.
func TestManifestNameOnlyWhenFetched(t *testing.T) {
	c := selfDescribedCase{body: `<link rel="manifest" href="/app.webmanifest">`}
	manifest, _ := json.Marshal(map[string]string{"name": "Orrisdale Board", "short_name": "Orrisdale"})
	if got := runSelfDescribed(t, c); len(got) != 0 {
		t.Fatalf("heuristics without a fetched manifest = %+v, want none", got)
	}
	other := &probe.Response{URL: "http://192.0.2.7/other.json", StatusCode: 200, Body: manifest}
	if got := runSelfDescribed(t, c, other); len(got) != 0 {
		t.Fatalf("heuristics with another response = %+v, want none", got)
	}
	fetched := &probe.Response{URL: "http://192.0.2.7/app.webmanifest", StatusCode: 200, Body: manifest}
	got := runSelfDescribed(t, c, fetched)
	if names := techNamesOf(got); !slices.Equal(names, []string{"Orrisdale Board", "Orrisdale"}) {
		t.Fatalf("technologies = %v, want the manifest name and short_name", names)
	}
	if !strings.Contains(got[0].finding.Evidence, "manifest /app.webmanifest name") || got[0].tech.Confidence != 40 {
		t.Errorf("heuristic %+v, want confidence 40 and the manifest named in the evidence", got[0])
	}

	f := &fixtureFetcher{responses: map[string]*probe.Response{"/": {URL: "http://192.0.2.7/", StatusCode: 200, Body: []byte(c.body), Headers: map[string]string{}}}}
	noNetwork(t)
	set := packSet(t)
	h := &probe.HTTP{Scheme: "http", URL: "http://192.0.2.7/", StatusCode: 200, Headers: map[string]string{}}
	set.withNotable(set.detect(context.Background(), f, h), h, []byte(c.body))
	for _, p := range f.calls {
		if strings.Contains(p, "manifest") {
			t.Errorf("detection requested %s", p)
		}
	}
}

func techNamesOf(hs []heuristic) []string {
	var out []string
	for _, hc := range hs {
		out = append(out, hc.tech.Name)
	}
	return out
}

// REQ-SIGNATURES-021: the corroborated title is only used when no other source named a product.
func TestCorroboratedTitleOnlyWithoutNamedProduct(t *testing.T) {
	body := []byte(`<script src="/static/quorvel.js"></script>`)
	h := &probe.HTTP{Scheme: "http", URL: "http://192.0.2.7/", StatusCode: 200, Title: "Quorvel", Headers: map[string]string{"server": "nginx"}}
	set := packSet(t)
	res := set.withNotable(Result{Technologies: []Technology{{Name: "nginx", Category: "web-server", Confidence: 90, Source: SourceBuiltin}}}, h, body)
	i := slices.IndexFunc(res.Technologies, func(t Technology) bool { return t.Name == "Quorvel" })
	if i < 0 || res.Technologies[i].Source != SourceHeuristic || res.Technologies[i].Confidence != 30 {
		t.Fatalf("technologies = %+v, want Quorvel from the heuristic with confidence 30", res.Technologies)
	}
	if !slices.ContainsFunc(res.Findings, func(f Finding) bool {
		return f.SignatureID == heuristicTitleCorrID && f.Name == "Quorvel" && f.Confidence == 30 && strings.HasPrefix(f.Evidence, "page title, corroborated by ")
	}) {
		t.Errorf("findings = %+v, want the labelled heuristic finding", res.Findings)
	}
	res = set.withNotable(Result{Technologies: []Technology{{Name: "Zentara", Category: "cms", Confidence: 90, Source: "signature:zentara"}}}, h, body)
	if got := techNames(res.Technologies); slices.Contains(got, "Quorvel") {
		t.Errorf("technologies = %v, want no title product next to a named one", got)
	}
}

// REQ-SIGNATURES-020: a dataset header pattern found inside a longer word ("bun" in "ubuntu") is not evidence.
func TestDatasetHeaderMatchInsideWord(t *testing.T) {
	f, h := loadPackFixture(t, filepath.Join(packFixtureDir, "wordpress"))
	h.Headers["x-powered-by"] = "PHP/7.2.24-0ubuntu0.18.04.17"
	body := f.responses["/"].Body
	w, err := fingerprints()
	if err != nil {
		t.Fatal(err)
	}
	in := map[string][]string{}
	for k, v := range h.Headers {
		in[k] = []string{v}
	}
	if _, ok := w.FingerprintWithInfo(in, body)["bun"]; !ok {
		t.Fatalf("dataset no longer reports Bun for this page; the regression input needs updating")
	}
	got := techNames(Wappalyzer(h.Headers, nil, body))
	if slices.Contains(got, "bun") {
		t.Errorf("technologies = %v, want no bun from 'ubuntu'", got)
	}
	if !slices.Contains(got, "PHP") || !slices.Contains(got, "Ubuntu") {
		t.Errorf("technologies = %v, want PHP and Ubuntu from the same header", got)
	}
	if got := techNames(Wappalyzer(map[string]string{"x-powered-by": "Bun"}, nil, nil)); !slices.Equal(got, []string{"bun"}) {
		t.Errorf("technologies for x-powered-by: Bun = %v, want bun", got)
	}
	if got := techNames(Wappalyzer(map[string]string{"x-powered-by": "Express"}, nil, nil)); !slices.Contains(got, "Node.js") {
		t.Errorf("technologies for x-powered-by: Express = %v, want the implied Node.js kept", got)
	}
	res := runPackFixtureNotable(t, "wordpress")
	if got := techNames(res.Technologies); slices.Contains(got, "bun") {
		t.Errorf("wordpress fixture technologies = %v, want no bun", got)
	}
}

// REQ-SIGNATURES-021: bytes a scanned host controls never crash the matching helpers.
func TestSelfDescribedHostileBytes(t *testing.T) {
	for _, v := range []string{"\xffquorvelx", strings.Repeat("K", 10) + "quorvel", "İİquorvel\xff"} {
		h := &probe.HTTP{Scheme: "http", URL: "http://192.0.2.7/", StatusCode: 200, Title: "Quorvel", Headers: map[string]string{"server": v, "x-powered-by": v}, Cookies: []probe.Cookie{{Name: v}}}
		heuristics(h, []byte(`<div class="`+v+`" id="`+v+`"></div><script src="/`+v+`.js"></script>`), false)
		Wappalyzer(map[string]string{"server": strings.Repeat("K", 10) + "nginx", "x-powered-by": v}, nil, nil)
	}
}

// REQ-SIGNATURES-021: an admin-panel finding does not change the corroborated title's confidence.
func TestCorroboratedTitleOnAdminPage(t *testing.T) {
	body := []byte(`<script src="/static/hexmoor.js"></script><form><input type="password" name="p"></form>`)
	h := &probe.HTTP{Scheme: "http", URL: "http://192.0.2.7/", StatusCode: 200, Title: "Hexmoor", Headers: map[string]string{}}
	res := packSet(t).withNotable(Result{}, h, body)
	if !slices.ContainsFunc(res.Findings, func(f Finding) bool { return f.Kind == KindAdminPanel }) {
		t.Fatalf("findings = %+v, want an admin-panel finding", res.Findings)
	}
	i := slices.IndexFunc(res.Technologies, func(t Technology) bool { return t.Name == "Hexmoor" })
	if i < 0 || res.Technologies[i].Confidence != 30 || res.Technologies[i].Source != SourceHeuristic {
		t.Errorf("technologies = %+v, want Hexmoor from the heuristic with confidence 30", res.Technologies)
	}
}
