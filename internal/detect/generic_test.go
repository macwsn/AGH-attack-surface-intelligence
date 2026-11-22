package detect

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"

	"asi/internal/probe"
)

const holdoutDir = "testdata/holdout"

type failingTransport struct{ t *testing.T }

func (f failingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	f.t.Errorf("network request during detection: %s %s", r.Method, r.URL)
	return nil, errors.New("network disabled in test")
}

func noNetwork(t *testing.T) {
	t.Helper()
	prevTransport, prevResolver := http.DefaultTransport, net.DefaultResolver
	http.DefaultTransport = failingTransport{t}
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		t.Errorf("DNS lookup during detection")
		return nil, errors.New("network disabled in test")
	}}
	t.Cleanup(func() { http.DefaultTransport, net.DefaultResolver = prevTransport, prevResolver })
}

func runHoldout(t *testing.T, product string) Result {
	t.Helper()
	f, h := loadPackFixture(t, filepath.Join(holdoutDir, product))
	set := packSet(t)
	return set.withNotable(set.detect(context.Background(), f, h), h, f.responses["/"].Body)
}

func techNames(techs []Technology, sources ...string) []string {
	var out []string
	for _, t := range techs {
		if len(sources) == 0 || slices.Contains(sources, t.Source) {
			out = append(out, t.Name)
		}
	}
	slices.Sort(out)
	return out
}

// REQ-SIGNATURES-020
func TestWappalyzerOfflineOnFetchedResponse(t *testing.T) {
	noNetwork(t)
	if _, err := wappalyzer.New(); err != nil {
		t.Fatalf("wappalyzer.New without network: %v", err)
	}
	headers := map[string]string{"server": "MiniServ/1.910"}
	body := []byte(`<html><head><title>Login to Webmin</title></head><body><form action="/session_login.cgi"><input type="password" name="pass"></form></body></html>`)
	got := Wappalyzer(headers, nil, body)
	i := slices.IndexFunc(got, func(t Technology) bool { return t.Name == "Webmin" })
	if i < 0 {
		t.Fatalf("technologies = %+v, want Webmin from the wappalyzer fingerprints", got)
	}
	for _, tc := range got {
		if tc.Source != SourceWappalyzer || tc.Confidence != 60 {
			t.Errorf("technology %+v, want source wappalyzer and confidence 60", tc)
		}
	}
	if c := got[slices.IndexFunc(got, func(t Technology) bool { return t.Name == "MiniServ" })]; c.Version != "1.910" || c.Category != "web-server" {
		t.Errorf("MiniServ = %+v, want version 1.910, category web-server", c)
	}
	res := runHoldout(t, "gogs")
	if i := slices.IndexFunc(res.Technologies, func(t Technology) bool { return t.Name == "Gogs" }); i < 0 || res.Technologies[i].Source != SourceWappalyzer || res.Technologies[i].Category != "development-tool" {
		t.Errorf("gogs technologies = %+v, want Gogs from wappalyzer mapped to development-tool", res.Technologies)
	}
}

// REQ-SIGNATURES-020
func TestWappalyzerMergedByExistingRules(t *testing.T) {
	h := &probe.HTTP{Scheme: "http", URL: "http://192.0.2.1/", StatusCode: 200, Headers: map[string]string{"server": "nginx/1.25.3"}}
	res := packSet(t).withNotable(Result{Technologies: []Technology{{Name: "nginx", Category: "web-server", Confidence: 90, Source: "builtin"}}}, h, nil)
	if n := countName(res.Technologies, "nginx"); n != 1 {
		t.Fatalf("nginx entries = %d, want one merged (%+v)", n, res.Technologies)
	}
	i := slices.IndexFunc(res.Technologies, func(t Technology) bool { return t.Name == "nginx" })
	if got := res.Technologies[i]; got.Confidence != 90 || got.Source != "builtin" || got.Version != "1.25.3" {
		t.Errorf("nginx = %+v, want the builtin entry (confidence 90) with the version 1.25.3", got)
	}
}

// REQ-SIGNATURES-021
func TestHeuristics(t *testing.T) {
	cases := []struct {
		name    string
		title   string
		headers map[string]string
		body    string
		admin   bool
		want    []string
	}{
		{"installer title", "Installation - Gogs", nil, "", false, []string{"Gogs"}},
		{"sign in title", "Sign in - Acme Vault", nil, "", false, []string{"Acme Vault"}},
		{"login to title", "Login to Webmin", nil, "", false, []string{"Webmin"}},
		{"console title", "Openfire Admin Console", nil, "", false, []string{"Openfire"}},
		{"admin title", "Solr Admin", nil, "", false, []string{"Solr"}},
		{"welcome title", "Welcome to Zorbix!", nil, "", false, []string{"Zorbix"}},
		{"dashboard title with version", "Fluxo 2.3 Dashboard", nil, "", false, []string{"Fluxo 2.3"}},
		{"bare title on an admin page", "Metabase", nil, `<script>window._metabaseBootstrap = {}</script>`, true, []string{"Metabase"}},
		{"bare title named in an asset path", "Zorbix", nil, `<link href="/static/zorbix.css">`, true, []string{"Zorbix"}},
		{"bare title only in visible text", "Zorbix", nil, `<h1>Zorbix</h1><form><input type="password"></form>`, true, nil},
		{"polish login", "Logowanie", nil, `<h1>Logowanie</h1><link href="/css/logowanie.css">`, true, nil},
		{"polish sign in", "Zaloguj", nil, `<a href="/zaloguj/">Zaloguj</a>`, true, nil},
		{"german login", "Anmelden", nil, `<form action="/anmelden/">`, true, nil},
		{"french login", "Connexion", nil, `<form action="/connexion/">`, true, nil},
		{"logon", "Logon", nil, `<form action="/logon.do">`, true, nil},
		{"webmail", "Webmail", nil, `<script src="/webmail/app.js">`, true, nil},
		{"vpn", "VPN", nil, `<script src="/vpn/app.js">`, true, nil},
		{"helpdesk", "Helpdesk", nil, `<script src="/helpdesk/app.js">`, true, nil},
		{"wiki", "Wiki", nil, `<script src="/wiki/app.js">`, true, nil},
		{"extranet", "Extranet", nil, `<script src="/extranet/app.js">`, true, nil},
		{"sign in to continue", "Sign in to continue", nil, "", false, nil},
		{"zaloguj sie", "Zaloguj się", nil, "", true, nil},
		{"generic version header", "", map[string]string{"x-runtime-version": "8.0.1", "x-build-version": "1.2.3", "x-content-version": "2.0", "x-schema-version": "3.1"}, "", false, nil},
		{"meta generator", "", nil, `<meta name="generator" content="Hugo 0.92.1">`, false, []string{"Hugo 0.92.1"}},
		{"x-powered-by", "", map[string]string{"x-powered-by": "Express/4.18.2"}, "", false, []string{"Express 4.18.2"}},
		{"server tokens", "", map[string]string{"server": "CouchDB/3.2.1 (Erlang OTP/23)"}, "", false, []string{"CouchDB 3.2.1"}},
		{"version header", "", map[string]string{"x-influxdb-version": "1.6.6"}, "", false, []string{"Influxdb 1.6.6"}},
		{"login", "Login", nil, "", true, nil},
		{"dashboard", "Dashboard", nil, "", true, nil},
		{"home", "Home", nil, "", true, nil},
		{"index of", "Index of /", nil, "", true, nil},
		{"sign in", "Sign in", nil, "", true, nil},
		{"admin login", "Admin Login", nil, "", true, nil},
		{"welcome to nginx", "Welcome to nginx!", nil, "", false, []string{"nginx"}},
		{"generic console", "Web Console", nil, "", false, nil},
		{"generic welcome", "Welcome to the Intranet", nil, "", false, nil},
		{"bare title on an ordinary page", "Metabase", nil, "", false, nil},
		{"two-word title", "Campus Portal", nil, "", true, nil},
		{"server without version", "", map[string]string{"server": "nginx"}, "", false, nil},
		{"version header of a generic word", "", map[string]string{"x-api-version": "2.0"}, "", false, nil},
		{"empty generator", "", nil, `<meta name="generator" content="">`, false, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			headers := c.headers
			if headers == nil {
				headers = map[string]string{}
			}
			h := &probe.HTTP{Scheme: "http", URL: "http://192.0.2.1/", StatusCode: 200, Title: c.title, Headers: headers}
			conf := map[string]int{"bare title on an admin page": 30, "bare title named in an asset path": 30}[c.name]
			if conf == 0 {
				conf = 40
			}
			var got []string
			for _, hc := range heuristics(h, []byte(c.body), c.admin) {
				if hc.tech.Source != SourceHeuristic || hc.tech.Confidence != conf || hc.finding.Evidence == "" || hc.finding.Confidence != conf {
					t.Errorf("heuristic %+v, want source heuristic, confidence %d and evidence", hc, conf)
				}
				got = append(got, strings.TrimSpace(hc.tech.Name+" "+hc.tech.Version))
			}
			if !slices.Equal(got, c.want) {
				t.Errorf("heuristics = %q, want %q", got, c.want)
			}
		})
	}
}

// REQ-SIGNATURES-021
func TestHeuristicDoesNotDuplicateKnownProduct(t *testing.T) {
	h := &probe.HTTP{Scheme: "http", URL: "http://192.0.2.1/", StatusCode: 200, Title: "Grafana", Headers: map[string]string{}}
	res := addHeuristics(Result{Technologies: []Technology{{Name: "Grafana", Version: "8.2.0", Confidence: 90, Source: "signature:builtin-grafana"}}}, heuristics(h, nil, true))
	if got := techNames(res.Technologies); !slices.Equal(got, []string{"Grafana"}) {
		t.Errorf("technologies = %v, want only the signature's Grafana", got)
	}
}

// REQ-SIGNATURES-022
func TestGenericAdminPanel(t *testing.T) {
	cases := []struct {
		name, url, title, body string
		redirect               []string
		matched                []Finding
		want                   string
	}{
		{"password on root", "http://192.0.2.1/", "Acme", `<form><input type="password"></form>`, nil, nil, loginFormID},
		{"password on redirect target", "http://192.0.2.1/", "", `<form><input type="password"></form>`, []string{"http://192.0.2.1/auth/"}, nil, loginFormID},
		{"title console", "http://192.0.2.1/", "Fluxo Console", `<p>hi</p>`, nil, nil, managementID},
		{"path manager", "http://192.0.2.1/", "", ``, []string{"http://192.0.2.1/manager/html"}, nil, managementID},
		{"installer title", "http://192.0.2.1/", "Setup Wizard - Acme", ``, nil, nil, installerID},
		{"installer path", "http://192.0.2.1/", "Acme", ``, []string{"http://192.0.2.1/install/"}, nil, installerID},
		{"specific signature flagged it", "http://192.0.2.1/", "Admin Console", `<form><input type="password"></form>`, nil, []Finding{{SignatureID: "builtin-grafana-login", Kind: KindAdminPanel}}, ""},
		{"ordinary page", "http://192.0.2.1/", "Campus Blog", `<form><input type="search"></form>`, nil, nil, ""},
		{"admin word inside another word", "http://192.0.2.1/", "Badminton Club", ``, nil, nil, ""},
		{"setup token in boot data", "http://192.0.2.1/", "Acme", `<script>window.boot = {"setup-token":"0d7ba2c9"}</script>`, nil, nil, installerID},
		{"setup token cleared", "http://192.0.2.1/", "Acme", `<script>window.boot = {"setup-token":null}</script>`, nil, nil, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := &probe.HTTP{Scheme: "http", URL: c.url, StatusCode: 200, Title: c.title, Headers: map[string]string{}, RedirectChain: c.redirect}
			got := adminFindings(h, []byte(c.body), c.matched)
			if c.want == "" {
				if len(got) != 0 {
					t.Errorf("findings = %+v, want none", got)
				}
				return
			}
			if len(got) != 1 || got[0].SignatureID != c.want || got[0].Kind != KindAdminPanel || got[0].Confidence != 50 || got[0].Evidence == "" {
				t.Fatalf("findings = %+v, want one %s admin-panel finding with confidence 50", got, c.want)
			}
		})
	}
}

// REQ-SIGNATURES-022
func TestGenericAdminPanelOnHoldout(t *testing.T) {
	want := map[string]struct{ id, name string }{
		"webmin":           {loginFormID, "Login form"},
		"metabase":         {installerID, "Unfinished installation"},
		"openfire-console": {loginFormID, "Login form"},
		"solr":             {managementID, "Management interface"},
		"gogs":             {installerID, "Unfinished installation"},
	}
	for product, w := range want {
		t.Run(product, func(t *testing.T) {
			res := runHoldout(t, product)
			var admin []Finding
			for _, f := range res.Findings {
				if f.Kind == KindAdminPanel {
					admin = append(admin, f)
				}
			}
			if len(admin) != 1 || admin[0].SignatureID != w.id || admin[0].Name != w.name || admin[0].Confidence != 50 {
				t.Errorf("admin-panel findings = %+v, want one %s %q", admin, w.id, w.name)
			}
		})
	}
}

func TestHoldoutRecognisedWithoutFalseTechnologies(t *testing.T) {
	want := map[string]struct {
		product string
		techs   []string
	}{
		"airflow":          {"Airflow", []string{"Bootstrap", "Python", "gunicorn"}},
		"couchdb":          {"CouchDB", []string{"CouchDB", "Erlang"}},
		"gogs":             {"Gogs", []string{"Clipboard.js", "Go", "Gogs", "Macaron", "Semantic UI", "jQuery"}},
		"influxdb":         {"Influxdb", []string{"Influxdb"}},
		"metabase":         {"Metabase", []string{"Java", "Jetty", "Metabase"}},
		"nacos":            {"Nacos", nil},
		"nexus":            {"Nexus Repository", []string{"Nexus Repository"}},
		"openfire":         {"Openfire", nil},
		"openfire-console": {"Openfire", []string{"Bootstrap", "Java", "Openfire"}},
		"solr":             {"Solr", []string{"AngularJS", "Chosen", "D3", "Highlight.js", "Solr", "jQuery", "jQuery UI", "timeago"}},
		"superset":         {"Superset", []string{"Python", "gunicorn"}},
		"webmin":           {"Webmin", []string{"MiniServ", "Webmin"}},
	}
	products := packFixtureProductsIn(t, holdoutDir)
	if len(products) != len(want) {
		t.Fatalf("holdout fixtures = %v, want %v", products, want)
	}
	recognised, captured, capturedRecognised := 0, 0, 0
	for _, p := range products {
		res := runHoldout(t, p)
		if got := techNames(res.Technologies); !slices.Equal(got, want[p].techs) {
			t.Errorf("%s: technologies = %v, want %v", p, got, want[p].techs)
		}
		if strings.Contains(p, "-") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(holdoutDir, p, "source.txt"))
		if err != nil {
			t.Fatal(err)
		}
		hit := slices.Contains(techNames(res.Technologies), want[p].product)
		if strings.HasPrefix(string(src), "captured") {
			captured++
			if hit {
				capturedRecognised++
			}
		}
		if hit {
			recognised++
		}
	}
	t.Logf("root pages: recognised %d of 11 services, %d of the %d captured", recognised, capturedRecognised, captured)
	if captured != 8 || capturedRecognised < 6 {
		t.Errorf("recognised %d of %d real captures, want at least 6 of 8 (written fixtures are not counted)", capturedRecognised, captured)
	}
}

func TestGenericSourcesOnPackFixtures(t *testing.T) {
	want := map[string][]string{
		"activemq":            {"Java", "Jetty"},
		"activemq-console":    {"Java", "Jetty"},
		"brother-printer":     {"debut"},
		"dahua":               {"jQuery"},
		"drupal":              {"Debian"},
		"drupal-8":            {"Debian", "Modernizr", "jQuery"},
		"dvwa":                {"Debian"},
		"gitea":               {"Go"},
		"gitlab":              {"Ruby on Rails", "Vue.js"},
		"httpbin":             {"Python", "React", "Swagger UI", "gunicorn", "jQuery"},
		"httpd-2.4.49":        {"UNIX"},
		"jenkins":             {"Java", "Jetty"},
		"jenkins-2.441":       {"Java", "Jetty"},
		"joomla":              {"Debian", "jQuery"},
		"kibana":              {"Node.js"},
		"nginx-proxy-manager": {"OpenResty", "nginx"},
		"phpmyadmin":          {"Bootstrap", "Debian", "jQuery", "jQuery Migrate", "jQuery UI"},
		"phpmyadmin-4.8":      {"Debian", "jQuery"},
		"portainer":           {"AngularJS"},
		"proxmox":             {"pve-api-daemon"},
		"rabbitmq":            {"Bootstrap", "Cowboy", "Erlang", "jQuery"},
		"roundcube":           {"Debian", "PHP"},
		"tomcat-8.0":          {"Apache-Coyote", "Java"},
		"wordpress":           {"Debian"},
		"wordpress-4.7":       {"Debian", "jQuery", "jQuery Migrate"},
	}
	for _, p := range packFixtureProducts(t) {
		res := runPackFixtureNotable(t, p)
		if got := techNames(res.Technologies, SourceWappalyzer, SourceHeuristic); !slices.Equal(got, want[p]) {
			t.Errorf("%s: wappalyzer and heuristic technologies = %v, want %v", p, got, want[p])
		}
	}
}

func TestGenericSourcesOnLabServices(t *testing.T) {
	want := map[string][]string{"drupal": {"PHP"}, "wp": {"PHP"}}
	confs, err := filepath.Glob(filepath.Join(labServicesDir, "*", "default.conf"))
	if err != nil || len(confs) == 0 {
		t.Fatalf("lab services = %v, %v", confs, err)
	}
	for _, conf := range confs {
		name := filepath.Base(filepath.Dir(conf))
		s := parseLabService(t, filepath.Join(labServicesDir, name))
		root := s.response(t, "/")
		h := &probe.HTTP{Scheme: "http", URL: root.URL, StatusCode: root.StatusCode, Title: root.Title, Headers: root.Headers, Cookies: root.Cookies, RedirectChain: root.RedirectChain}
		res := packSet(t).withNotable(runPackOnLabService(t, name), h, root.Body)
		if got := techNames(res.Technologies, SourceWappalyzer, SourceHeuristic); !slices.Equal(got, want[name]) {
			t.Errorf("%s: wappalyzer and heuristic technologies = %v, want %v", name, got, want[name])
		}
	}
}
