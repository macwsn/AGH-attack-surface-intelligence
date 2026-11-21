package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"asi/internal/version"
)

type seen struct {
	Method, Host, Path, UA string
}

type recorder struct {
	mu   sync.Mutex
	reqs []seen
}

func (r *recorder) wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.reqs = append(r.reqs, seen{req.Method, req.Host, req.URL.Path, req.UserAgent()})
		r.mu.Unlock()
		h.ServeHTTP(w, req)
	})
}

func (r *recorder) paths() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, s := range r.reqs {
		out = append(out, s.Path)
	}
	return out
}

func (r *recorder) check(t *testing.T) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.reqs) == 0 {
		t.Fatal("server saw no requests")
	}
	for _, s := range r.reqs {
		if s.Method != http.MethodGet && s.Method != http.MethodHead {
			t.Errorf("method %s sent to %s", s.Method, s.Path)
		}
		if s.UA != "asi-discovery/"+version.Version {
			t.Errorf("user agent %q", s.UA)
		}
	}
}

func hostPort(t *testing.T, rawURL string) (string, int) {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	p, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	return u.Hostname(), p
}

func start(t *testing.T, h http.Handler) (*httptest.Server, *recorder, string, int) {
	t.Helper()
	rec := &recorder{}
	srv := httptest.NewServer(rec.wrap(h))
	t.Cleanup(srv.Close)
	addr, port := hostPort(t, srv.URL)
	return srv, rec, addr, port
}

var favicon = []byte("ASI-LAB-CAMERA-FAVICON-v1\n")

func site() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, "/admin/login", http.StatusFound)
	})
	mux.HandleFunc("/admin/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/7.4.3")
		w.Header().Add("X-Multi", "a")
		w.Header().Add("X-Multi", "b")
		http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "secretsession0001", Path: "/", HttpOnly: true})
		http.SetCookie(w, &http.Cookie{Name: "pref", Value: "secretpref", Secure: true, SameSite: http.SameSiteStrictMode})
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><head><title>\n  Admin Panel &amp; Sign&nbsp;in\t</title></head><body>login</body></html>")
	})
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) { w.Write(favicon) })
	return mux
}

func TestProbePlainHTTP(t *testing.T) {
	_, rec, addr, port := start(t, site())
	s, err := Probe(context.Background(), addr, port, false, "")
	if err != nil {
		t.Fatal(err)
	}
	base := fmt.Sprintf("http://%s:%d/", addr, port)
	h := s.HTTP
	if h.Scheme != "http" || h.URL != base || h.StatusCode != 200 {
		t.Errorf("scheme/url/status = %q %q %d", h.Scheme, h.URL, h.StatusCode)
	}
	if h.Title != "Admin Panel & Sign in" {
		t.Errorf("title = %q", h.Title)
	}
	if h.Headers["x-powered-by"] != "PHP/7.4.3" || h.Headers["x-multi"] != "a, b" {
		t.Errorf("headers = %v", h.Headers)
	}
	for k := range h.Headers {
		if k != strings.ToLower(k) {
			t.Errorf("header %q not lower-cased", k)
		}
	}
	if _, ok := h.Headers["set-cookie"]; ok {
		t.Error("set-cookie header kept (carries cookie values)")
	}
	wantCookies := []Cookie{
		{Name: "PHPSESSID", HTTPOnly: true},
		{Name: "pref", Secure: true, SameSite: "Strict"},
	}
	if !reflect.DeepEqual(h.Cookies, wantCookies) {
		t.Errorf("cookies = %+v", h.Cookies)
	}
	if want := []string{base + "admin/login"}; !reflect.DeepEqual(h.RedirectChain, want) {
		t.Errorf("redirect_chain = %v", h.RedirectChain)
	}
	if h.TLS != nil {
		t.Errorf("tls on plain http = %+v", h.TLS)
	}
	sum := sha256.Sum256(favicon)
	if h.FaviconSHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("favicon_sha256 = %s", h.FaviconSHA256)
	}
	if h.FaviconMMH3 != 1918245699 {
		t.Errorf("favicon_mmh3 = %d", h.FaviconMMH3)
	}
	out, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"secretsession0001", "secretpref"} {
		if strings.Contains(string(out), secret) {
			t.Errorf("cookie value %q leaked into %s", secret, out)
		}
	}
	for _, key := range []string{`"scheme"`, `"url"`, `"status_code"`, `"title"`, `"headers"`, `"cookies"`, `"redirect_chain"`, `"favicon_sha256"`, `"favicon_mmh3"`, `"http_only"`, `"same_site"`} {
		if !strings.Contains(string(out), key) {
			t.Errorf("export lacks %s: %s", key, out)
		}
	}
	rec.check(t)
}

func TestProbeTLS(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewTLSServer(rec.wrap(site()))
	defer srv.Close()
	addr, port := hostPort(t, srv.URL)
	s, err := Probe(context.Background(), addr, port, true, "")
	if err != nil {
		t.Fatal(err)
	}
	h := s.HTTP
	if h.Scheme != "https" || h.URL != fmt.Sprintf("https://%s:%d/", addr, port) || h.StatusCode != 200 || h.Title == "" {
		t.Errorf("scheme/url/status/title = %q %q %d %q", h.Scheme, h.URL, h.StatusCode, h.Title)
	}
	cert := srv.Certificate()
	sum := sha256.Sum256(cert.Raw)
	want := &TLS{
		SubjectCN:  cert.Subject.CommonName,
		IssuerCN:   cert.Issuer.CommonName,
		SANs:       []string{"*.example.com", "127.0.0.1", "::1", "example.com"},
		NotBefore:  cert.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:   cert.NotAfter.UTC().Format(time.RFC3339),
		SHA256:     hex.EncodeToString(sum[:]),
		SelfSigned: true,
	}
	if !reflect.DeepEqual(h.TLS, want) {
		t.Errorf("tls = %+v, want %+v", h.TLS, want)
	}
	if len(h.RedirectChain) != 1 || h.FaviconSHA256 == "" {
		t.Errorf("redirect_chain=%v favicon=%q", h.RedirectChain, h.FaviconSHA256)
	}
	rec.check(t)
}

func TestProbeTLSExpiredCAIssuedCert(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Lab CA"},
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(48 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	notAfter := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "old.lab"},
		NotBefore: notAfter.Add(-24 * time.Hour), NotAfter: notAfter,
		DNSNames: []string{"old.lab"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<title>old</title>")
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey}}}
	srv.StartTLS()
	defer srv.Close()
	addr, port := hostPort(t, srv.URL)
	s, err := Probe(context.Background(), addr, port, true, "")
	if err != nil {
		t.Fatalf("expired cert must still be fetched: %v", err)
	}
	got := s.HTTP.TLS
	if got == nil || got.SubjectCN != "old.lab" || got.IssuerCN != "Lab CA" || got.SelfSigned {
		t.Fatalf("tls = %+v", got)
	}
	if got.NotAfter != notAfter.Format(time.RFC3339) || !reflect.DeepEqual(got.SANs, []string{"127.0.0.1", "old.lab"}) {
		t.Errorf("not_after/sans = %s %v", got.NotAfter, got.SANs)
	}
	if s.HTTP.Title != "old" {
		t.Errorf("title = %q", s.HTTP.Title)
	}
}

func TestProbeRedirectCap(t *testing.T) {
	_, rec, addr, port := start(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/favicon.ico" {
			http.NotFound(w, r)
			return
		}
		n, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/r"))
		http.Redirect(w, r, fmt.Sprintf("/r%d", n+1), http.StatusMovedPermanently)
	}))
	s, err := Probe(context.Background(), addr, port, false, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.HTTP.RedirectChain) != MaxRedirects || s.HTTP.StatusCode != http.StatusMovedPermanently {
		t.Errorf("chain=%v status=%d", s.HTTP.RedirectChain, s.HTTP.StatusCode)
	}
	if want := []string{"/", "/r1", "/r2", "/r3", "/r4", "/r5", "/favicon.ico"}; !reflect.DeepEqual(rec.paths(), want) {
		t.Errorf("requests = %v, want %v", rec.paths(), want)
	}
}

func TestProbeCrossHostRedirectNotFetched(t *testing.T) {
	for _, target := range []string{"http://evil.example:%d/x", "http://%s:1/x", "ftp://%s/x"} {
		t.Run(target, func(t *testing.T) {
			var loc string
			_, rec, addr, port := start(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/" {
					http.Redirect(w, r, loc, http.StatusFound)
				}
			}))
			switch {
			case strings.Contains(target, "evil"):
				loc = fmt.Sprintf(target, port)
			default:
				loc = fmt.Sprintf(target, addr)
			}
			s, err := Probe(context.Background(), addr, port, false, "")
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(s.HTTP.RedirectChain, []string{loc}) || s.HTTP.StatusCode != http.StatusFound {
				t.Errorf("chain=%v status=%d", s.HTTP.RedirectChain, s.HTTP.StatusCode)
			}
			for _, r := range rec.reqs {
				if r.Path == "/x" || strings.Contains(r.Host, "evil") {
					t.Errorf("cross-host target fetched: %+v", r)
				}
			}
		})
	}
}

func TestProbeHostnameRedirectFollowed(t *testing.T) {
	var port int
	_, rec, addr, p := start(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, fmt.Sprintf("http://INTRANET.lab:%d/home", port), http.StatusFound)
		case "/home":
			http.Redirect(w, r, fmt.Sprintf("http://127.0.0.1:%d/end", port), http.StatusFound)
		case "/end":
			fmt.Fprint(w, "<title>End</title>")
		}
	}))
	port = p
	s, err := Probe(context.Background(), addr, port, false, "intranet.lab")
	if err != nil {
		t.Fatal(err)
	}
	if s.HTTP.URL != fmt.Sprintf("http://intranet.lab:%d/", port) || s.HTTP.Title != "End" || len(s.HTTP.RedirectChain) != 2 {
		t.Errorf("url=%s title=%q chain=%v", s.HTTP.URL, s.HTTP.Title, s.HTTP.RedirectChain)
	}
	if rec.reqs[0].Host != fmt.Sprintf("intranet.lab:%d", port) {
		t.Errorf("first request host = %q", rec.reqs[0].Host)
	}
}

func TestProbeBodyLimit(t *testing.T) {
	big := strings.Repeat("a", 3*MaxBodyBytes)
	_, _, addr, port := start(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, big) }))
	s, err := Probe(context.Background(), addr, port, false, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Body) != MaxBodyBytes {
		t.Errorf("body read %d bytes", len(s.Body))
	}
}

func TestProbeTimeout(t *testing.T) {
	release := make(chan struct{})
	_, _, addr, port := start(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer close(release)
	begin := time.Now()
	_, err := (&Prober{Timeout: 200 * time.Millisecond}).Probe(context.Background(), addr, port, false, "")
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v", err)
	}
	if d := time.Since(begin); d > 3*time.Second {
		t.Errorf("timeout took %s", d)
	}
}

func TestProbeConnectionRefused(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	addr, port := hostPort(t, srv.URL)
	srv.Close()
	if _, err := Probe(context.Background(), addr, port, false, ""); err == nil {
		t.Fatal("expected error")
	}
}

func TestProbeNoFavicon(t *testing.T) {
	_, _, addr, port := start(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, "no title here")
	}))
	s, err := Probe(context.Background(), addr, port, false, "")
	if err != nil {
		t.Fatal(err)
	}
	if s.HTTP.FaviconSHA256 != "" || s.HTTP.FaviconMMH3 != 0 || s.HTTP.Title != "" {
		t.Errorf("favicon=%q mmh3=%d title=%q", s.HTTP.FaviconSHA256, s.HTTP.FaviconMMH3, s.HTTP.Title)
	}
	out, _ := json.Marshal(s.HTTP)
	if !strings.Contains(string(out), `"redirect_chain":[]`) {
		t.Errorf("redirect_chain not an empty list: %s", out)
	}
}

func TestTitle(t *testing.T) {
	cases := []struct {
		name, contentType string
		body              []byte
		want              string
	}{
		{"missing", "text/html", []byte("<html><body>hi</body></html>"), ""},
		{"empty", "text/html", []byte("<title></title>"), ""},
		{"whitespace", "text/html", []byte("<title>\n\t  Campus \r\n  Blog  </title>"), "Campus Blog"},
		{"entities", "text/html", []byte("<title>Tom &amp; Jerry &lt;3 &#8211; &eacute;</title>"), "Tom & Jerry <3 – é"},
		{"upper case tag", "text/html", []byte("<HTML><HEAD><TITLE>Printer Status</TITLE>"), "Printer Status"},
		{"header charset", "text/html; charset=iso-8859-2", []byte("<title>G\xea\xb6</title>"), "Gęś"},
		{"meta charset", "text/html", []byte(`<meta charset="windows-1250"><title>G` + "\xea\x9c" + `</title>`), "Gęś"},
		{"meta http-equiv", "", []byte(`<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-2"><title>G` + "\xea\xb6" + `</title>`), "Gęś"},
		{"utf-8 default", "text/html", []byte("<title>Zażółć</title>"), "Zażółć"},
		{"not html", "application/json", []byte(`{"a":1}`), ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Title(c.body, c.contentType); got != c.want {
				t.Errorf("Title = %q, want %q", got, c.want)
			}
		})
	}
}

func TestTitleFromServerCharset(t *testing.T) {
	_, _, addr, port := start(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=ISO-8859-2")
		w.Write([]byte("<title>G\xea\xb6</title>"))
	}))
	s, err := Probe(context.Background(), addr, port, false, "")
	if err != nil {
		t.Fatal(err)
	}
	if s.HTTP.Title != "Gęś" {
		t.Errorf("title = %q", s.HTTP.Title)
	}
}

func TestFaviconHash(t *testing.T) {
	if got := mmh3([]byte("hello")); got != 613153351 {
		t.Errorf("mmh3(hello) = %d", got)
	}
	if got := FaviconHash(favicon); got != 1918245699 {
		t.Errorf("FaviconHash(short) = %d", got)
	}
	var long []byte
	for i := 0; i < 3; i++ {
		for b := 0; b < 256; b++ {
			long = append(long, byte(b))
		}
	}
	if got := FaviconHash(long); got != 1836528006 {
		t.Errorf("FaviconHash(multi-line) = %d", got)
	}
}

func TestFetch(t *testing.T) {
	_, rec, addr, port := start(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, "<title>Home</title>")
		case "/old":
			http.Redirect(w, r, "/new", http.StatusFound)
		case "/new":
			w.Header().Set("X-Page", "new")
			fmt.Fprint(w, "<title>New</title>")
		default:
			http.NotFound(w, r)
		}
	}))
	s, err := Probe(context.Background(), addr, port, false, "")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	root, err := s.Fetch(ctx, "/")
	if err != nil || root.Title != "Home" {
		t.Fatalf("Fetch(/) = %+v, %v", root, err)
	}
	r, err := s.Fetch(ctx, "/old")
	if err != nil || r.StatusCode != 200 || r.Title != "New" || r.Headers["x-page"] != "new" || len(r.RedirectChain) != 1 {
		t.Fatalf("Fetch(/old) = %+v, %v", r, err)
	}
	again, err := s.Fetch(ctx, "/old")
	if err != nil || again != r {
		t.Errorf("Fetch(/old) not cached: %v", err)
	}
	for i := 1; i <= 4; i++ {
		if _, err := s.Fetch(ctx, fmt.Sprintf("/p%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	before := len(rec.paths())
	if _, err := s.Fetch(ctx, "/p5"); !errors.Is(err, ErrRequestLimit) {
		t.Errorf("sixth extra path: err = %v", err)
	}
	if _, err := s.Fetch(ctx, "/p1"); err != nil {
		t.Errorf("cached path after cap: %v", err)
	}
	if after := len(rec.paths()); after != before {
		t.Errorf("requests sent after cap: %v", rec.paths()[before:])
	}
	for _, bad := range []string{"relative", "//evil.example/x", "/a?b=1", "/a#frag"} {
		if _, err := s.Fetch(ctx, bad); err == nil || errors.Is(err, ErrRequestLimit) {
			t.Errorf("Fetch(%q) err = %v", bad, err)
		}
	}
	rec.check(t)
}
