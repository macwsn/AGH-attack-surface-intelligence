package detect

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"asi/internal/probe"
)

func packSet(t *testing.T) *Set {
	t.Helper()
	return &Set{Signatures: mustPack(t)}
}

func notableIDs(res Result, kind string) []string {
	var ids []string
	for _, f := range res.Findings {
		if f.Kind == kind {
			ids = append(ids, f.SignatureID)
		}
	}
	slices.Sort(ids)
	return ids
}

func TestNotableHeaders(t *testing.T) {
	cases := []struct {
		header, value string
		want          []string
	}{
		{"x-powered-by", "PHP/5.6.30", []string{"builtin-header-x-powered-by"}},
		{"x-powered-by", "ASP.NET", nil},
		{"x-powered-by", "Express", nil},
		{"x-aspnet-version", "4.0.30319", []string{"builtin-header-x-aspnet-version"}},
		{"x-aspnetmvc-version", "5.2", []string{"builtin-header-x-aspnetmvc-version"}},
		{"x-generator", "Drupal 10 (https://www.drupal.org)", []string{"builtin-header-x-generator"}},
		{"x-generator", "Drupal", nil},
		{"server", "Apache/2.4.25 (Debian)", []string{"builtin-header-server"}},
		{"server", "Microsoft-IIS/10.0", []string{"builtin-header-server"}},
		{"server", "nginx", nil},
		{"server", "cloudflare", nil},
		{"x-debug-token", "a1b2c3", []string{"builtin-header-x-debug-token"}},
		{"x-debug-token-link", "http://shop.example/_profiler/a1b2c3", []string{"builtin-header-x-debug-token-link"}},
		{"x-environment", "staging", []string{"builtin-header-x-environment"}},
		{"x-backend-server", "app-03", []string{"builtin-header-x-backend-server"}},
		{"x-served-by", "cache-fra-1234-FRA", []string{"builtin-header-x-served-by"}},
		{"via", "1.1 app01.corp.internal", []string{"builtin-header-via"}},
		{"via", "1.1 10.0.3.7:8080", []string{"builtin-header-via"}},
		{"via", "1.1 varnish (Varnish/6.0)", nil},
		{"via", "1.1 google", nil},
		{"strict-transport-security", "max-age=1", nil},
		{"content-type", "text/html", nil},
	}
	for _, c := range cases {
		t.Run(c.header+"="+c.value, func(t *testing.T) {
			h := &probe.HTTP{Scheme: "http", URL: "http://192.0.2.1/", StatusCode: 200, Headers: map[string]string{c.header: c.value}}
			res := packSet(t).DetectRecorded(h)
			got := notableIDs(res, KindInterestingHeader)
			if !slices.Equal(got, c.want) {
				t.Fatalf("interesting-header findings = %v, want %v (%+v)", got, c.want, res.Findings)
			}
			for _, f := range res.Findings {
				if f.Kind != KindInterestingHeader {
					continue
				}
				name := notableHeaders[slices.IndexFunc(notableHeaders, func(r headerRule) bool { return r.id == f.SignatureID })].header
				if !strings.HasPrefix(f.Evidence, name+": ") || f.Confidence == 0 || f.Name == "" {
					t.Errorf("finding %+v: evidence must quote the header name", f)
				}
				if strings.HasPrefix(c.header, "x-debug-token") {
					if strings.Contains(f.Evidence, "a1b2c3") {
						t.Errorf("evidence %q leaks the debug token", f.Evidence)
					}
				} else if !strings.Contains(f.Evidence, c.value) {
					t.Errorf("evidence %q does not quote the value %q", f.Evidence, c.value)
				}
			}
		})
	}
}

func TestNotableHeadersMissingSecurityHeadersAreNotFindings(t *testing.T) {
	h := &probe.HTTP{Scheme: "https", URL: "https://192.0.2.1/", StatusCode: 200, Headers: map[string]string{"server": "nginx", "content-type": "text/html"}}
	if res := packSet(t).DetectRecorded(h); len(res.Findings) != 0 {
		t.Errorf("findings = %+v, want none for a response without security headers", res.Findings)
	}
}

func TestNotableOnlyWithBuiltinPack(t *testing.T) {
	h := &probe.HTTP{Scheme: "https", URL: "https://192.0.2.1/", Headers: map[string]string{"x-powered-by": "PHP/5.6.30"}, Cookies: []probe.Cookie{{Name: "PHPSESSID"}}}
	for _, set := range []*Set{nil, {}} {
		if res := set.DetectRecorded(h); len(res.Findings) != 0 {
			t.Errorf("set without the built-in pack: findings = %+v, want none", res.Findings)
		}
	}
}

func TestNotableCookies(t *testing.T) {
	type tech struct{ name, category string }
	cases := []struct {
		name    string
		scheme  string
		cookies []probe.Cookie
		want    []string
		techs   []tech
	}{
		{"php session without flags over http", "http", []probe.Cookie{{Name: "PHPSESSID"}}, []string{"builtin-cookie-no-httponly", "builtin-cookie-stack"}, []tech{{"PHP", "programming-language"}}},
		{"php session without flags over https", "https", []probe.Cookie{{Name: "PHPSESSID"}}, []string{"builtin-cookie-no-httponly", "builtin-cookie-no-secure", "builtin-cookie-stack"}, []tech{{"PHP", "programming-language"}}},
		{"hardened session over https", "https", []probe.Cookie{{Name: "session", HTTPOnly: true, Secure: true}}, nil, nil},
		{"generic session without httponly", "https", []probe.Cookie{{Name: "app_session", Secure: true}}, []string{"builtin-cookie-no-httponly"}, nil},
		{"jsessionid", "http", []probe.Cookie{{Name: "JSESSIONID", HTTPOnly: true}}, []string{"builtin-cookie-stack"}, []tech{{"Java", "programming-language"}}},
		{"jenkins jsessionid", "http", []probe.Cookie{{Name: "JSESSIONID.4c1f6d2e", HTTPOnly: true}}, []string{"builtin-cookie-stack"}, []tech{{"Java", "programming-language"}}},
		{"asp.net", "http", []probe.Cookie{{Name: "ASP.NET_SessionId", HTTPOnly: true}}, []string{"builtin-cookie-stack"}, []tech{{"ASP.NET", "web-framework"}}},
		{"laravel", "http", []probe.Cookie{{Name: "laravel_session", HTTPOnly: true}}, []string{"builtin-cookie-stack"}, []tech{{"Laravel", "web-framework"}}},
		{"express", "http", []probe.Cookie{{Name: "connect.sid", HTTPOnly: true}}, []string{"builtin-cookie-stack"}, []tech{{"Express", "web-framework"}}},
		{"phpmyadmin", "http", []probe.Cookie{{Name: "phpMyAdmin", HTTPOnly: true}, {Name: "pma_lang", HTTPOnly: true}}, []string{"builtin-cookie-stack"}, []tech{{"phpMyAdmin", "database-admin"}}},
		{"wordpress test cookie", "http", []probe.Cookie{{Name: "wordpress_test_cookie"}}, []string{"builtin-cookie-stack"}, []tech{{"WordPress", "cms"}}},
		{"wordpress logged in", "http", []probe.Cookie{{Name: "wordpress_logged_in_0123456789abcdef0123456789abcdef"}}, []string{"builtin-cookie-no-httponly", "builtin-cookie-stack"}, []tech{{"WordPress", "cms"}}},
		{"non-session cookie", "https", []probe.Cookie{{Name: "pma_lang"}, {Name: "security"}}, nil, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := &probe.HTTP{Scheme: c.scheme, URL: c.scheme + "://192.0.2.1/", StatusCode: 200, Headers: map[string]string{}, Cookies: c.cookies}
			res := packSet(t).DetectRecorded(h)
			if got := notableIDs(res, KindInterestingCookie); !slices.Equal(got, c.want) {
				t.Fatalf("interesting-cookie findings = %v, want %v (%+v)", got, c.want, res.Findings)
			}
			for _, f := range res.Findings {
				if !slices.ContainsFunc(c.cookies, func(ck probe.Cookie) bool { return strings.Contains(f.Evidence, ck.Name) }) {
					t.Errorf("finding %+v: evidence names no cookie", f)
				}
			}
			var got []tech
			for _, tc := range res.Technologies {
				got = append(got, tech{tc.Name, tc.Category})
				if tc.Confidence > 60 || tc.Source != SourceBuiltin {
					t.Errorf("technology %+v, want a low-confidence %s technology", tc, SourceBuiltin)
				}
			}
			if !slices.Equal(got, c.techs) {
				t.Errorf("technologies = %v, want %v", got, c.techs)
			}
		})
	}
}

func TestNotableCookieValuesNeverInEvidence(t *testing.T) {
	sess, _ := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "secret-session-value"})
		http.SetCookie(w, &http.Cookie{Name: "laravel_session", Value: "secret-laravel-value"})
		w.Header().Set("X-Debug-Token", "secret-debug-token")
		fmt.Fprint(w, `<title>x</title>`)
	})
	res := packSet(t).Detect(context.Background(), sess)
	if got := notableIDs(res, KindInterestingCookie); !slices.Equal(got, []string{"builtin-cookie-no-httponly", "builtin-cookie-stack"}) {
		t.Fatalf("interesting-cookie findings = %v (%+v)", got, res.Findings)
	}
	for _, f := range res.Findings {
		if strings.Contains(f.Evidence, "secret") {
			t.Errorf("evidence %q leaks a cookie or token value", f.Evidence)
		}
	}
}

func TestNotableLoginForm(t *testing.T) {
	cases := []struct {
		name, body string
		admin      []Finding
		want       bool
	}{
		{"password in form", `<form action="login.php" method="post"><input type="text" name="u"><input type="password" name="p"></form>`, nil, true},
		{"uppercase type", `<FORM><INPUT TYPE="Password" name=p></FORM>`, nil, true},
		{"password outside form", `<input type="password"><form><input type="text"></form>`, nil, false},
		{"form without password", `<form><input type="search" name="q"></form>`, nil, false},
		{"no body", ``, nil, false},
		{"specific admin panel matched", `<form><input type="password"></form>`, []Finding{{SignatureID: "builtin-grafana-login", Kind: KindAdminPanel}}, false},
		{"only a technology matched", `<form><input type="password"></form>`, []Finding{{SignatureID: "builtin-dvwa", Kind: "technology"}}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := &probe.HTTP{Scheme: "http", URL: "http://192.0.2.1/login.php", StatusCode: 200, Headers: map[string]string{}}
			res := packSet(t).withNotable(Result{Findings: c.admin}, h, []byte(c.body))
			i := slices.IndexFunc(res.Findings, func(f Finding) bool { return f.SignatureID == loginFormID })
			if (i >= 0) != c.want {
				t.Fatalf("login form finding = %v, want %v (%+v)", i >= 0, c.want, res.Findings)
			}
			if i >= 0 {
				f := res.Findings[i]
				if f.Kind != KindAdminPanel || f.Name != "Login form" || f.Confidence != 50 || !strings.Contains(f.Evidence, "http://192.0.2.1/login.php") {
					t.Errorf("login form finding = %+v", f)
				}
			}
		})
	}
}

func runPackFixtureNotable(t *testing.T, product string) Result {
	t.Helper()
	f, h := loadPackFixture(t, filepath.Join(packFixtureDir, product))
	set := packSet(t)
	return set.withNotable(set.detect(context.Background(), f, h), h, f.responses["/"].Body)
}

func TestNotableOnPackFixtures(t *testing.T) {
	cases := []struct {
		dir       string
		loginForm bool
		cookies   []string
		headers   []string
	}{
		{"dvwa", true, []string{"builtin-cookie-no-httponly", "builtin-cookie-stack"}, []string{"builtin-header-server"}},
		{"phpmyadmin", false, []string{"builtin-cookie-stack"}, []string{"builtin-header-server", "builtin-header-x-powered-by"}},
		{"admin-login", false, nil, nil},
		{"grafana-8.2", false, nil, nil},
	}
	for _, c := range cases {
		t.Run(c.dir, func(t *testing.T) {
			res := runPackFixtureNotable(t, c.dir)
			if got := slices.ContainsFunc(res.Findings, func(f Finding) bool { return f.SignatureID == loginFormID }); got != c.loginForm {
				t.Errorf("login form finding = %v, want %v (%+v)", got, c.loginForm, res.Findings)
			}
			admin := 0
			for _, f := range res.Findings {
				if f.Kind == KindAdminPanel {
					admin++
				}
			}
			if c.dir == "admin-login" && admin != 1 {
				t.Errorf("admin-panel findings = %d, want exactly one (%+v)", admin, res.Findings)
			}
			if got := notableIDs(res, KindInterestingCookie); !slices.Equal(got, c.cookies) {
				t.Errorf("interesting-cookie findings = %v, want %v", got, c.cookies)
			}
			if got := notableIDs(res, KindInterestingHeader); !slices.Equal(got, c.headers) {
				t.Errorf("interesting-header findings = %v, want %v", got, c.headers)
			}
		})
	}
}

func TestOutdatedEvidenceAndOncePerService(t *testing.T) {
	techs := []Technology{{Name: "Apache", Version: "2.4.25", Confidence: 90}, {Name: "apache", Version: "2.4.25", Confidence: 60}, {Name: "PHP", Version: "5.6.30", Confidence: 90}}
	got := Outdated(techs)
	var ids []string
	for _, f := range got {
		ids = append(ids, f.SignatureID)
		if strings.Contains(strings.ToLower(f.Evidence), "latest") || !strings.Contains(f.Evidence, "minimum supported version") || !strings.Contains(f.Evidence, "checked 2026-") {
			t.Errorf("evidence %q must name the minimum and the date the table was checked, never the latest release", f.Evidence)
		}
	}
	if !slices.Equal(ids, []string{"outdated-apache", "outdated-php"}) {
		t.Errorf("outdated findings = %v, want outdated-apache and outdated-php once each", ids)
	}
}

func TestServiceTechnologiesRabbitMQ(t *testing.T) {
	cases := []struct {
		service, product, version, want string
	}{
		{"amqp", "RabbitMQ", "3.8.9", "3.8.9"},
		{"amqp", "RabbitMQ", "", ""},
		{"amqps", "RabbitMQ", "3.12.13", "3.12.13"},
	}
	for _, c := range cases {
		got := ServiceTechnologies(c.service, c.product, c.version)
		if len(got) != 1 || got[0].Name != "RabbitMQ" || got[0].Version != c.want || got[0].Category != "message-broker" {
			t.Errorf("ServiceTechnologies(%q, %q, %q) = %+v, want RabbitMQ %q", c.service, c.product, c.version, got, c.want)
		}
	}
}

func TestNotableOnLabServices(t *testing.T) {
	want := map[string][]string{
		"admin":   {"builtin-cookie-stack", "builtin-header-x-powered-by"},
		"drupal":  {"builtin-header-x-generator"},
		"staging": {"builtin-header-x-debug-token", "builtin-header-x-environment"},
		"wp":      {"builtin-cookie-stack"},
	}
	confs, err := filepath.Glob(filepath.Join(labServicesDir, "*", "default.conf"))
	if err != nil || len(confs) == 0 {
		t.Fatalf("lab services = %v, %v", confs, err)
	}
	for _, conf := range confs {
		name := filepath.Base(filepath.Dir(conf))
		t.Run(name, func(t *testing.T) {
			s := parseLabService(t, filepath.Join(labServicesDir, name))
			root := s.response(t, "/")
			h := &probe.HTTP{Scheme: "http", URL: root.URL, StatusCode: root.StatusCode, Headers: root.Headers, Cookies: root.Cookies}
			set := packSet(t)
			res := set.withNotable(runPackOnLabService(t, name), h, root.Body)
			var got []string
			for _, f := range res.Findings {
				if strings.HasPrefix(f.SignatureID, "builtin-header-") || strings.HasPrefix(f.SignatureID, "builtin-cookie-") || f.SignatureID == loginFormID {
					got = append(got, f.SignatureID)
				}
			}
			slices.Sort(got)
			if !slices.Equal(got, want[name]) {
				t.Errorf("notable findings = %v, want %v (%+v)", got, want[name], res.Findings)
			}
		})
	}
}
