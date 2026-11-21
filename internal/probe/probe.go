package probe

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
	"golang.org/x/net/html/charset"

	"asi/internal/version"
)

const (
	MaxRedirects     = 5
	MaxExtraRequests = 5
	MaxBodyBytes     = 1 << 20
	DefaultTimeout   = 10 * time.Second
)

const UserAgent = "asi-discovery/" + version.Version

var ErrRequestLimit = errors.New("probe: extra request limit reached")

type HTTP struct {
	Scheme        string            `json:"scheme"`
	URL           string            `json:"url"`
	StatusCode    int               `json:"status_code"`
	Title         string            `json:"title"`
	Headers       map[string]string `json:"headers"`
	Cookies       []Cookie          `json:"cookies"`
	RedirectChain []string          `json:"redirect_chain"`
	TLS           *TLS              `json:"tls,omitempty"`
	FaviconSHA256 string            `json:"favicon_sha256"`
	FaviconMMH3   int32             `json:"favicon_mmh3"`
}

type Cookie struct {
	Name     string `json:"name"`
	HTTPOnly bool   `json:"http_only"`
	Secure   bool   `json:"secure"`
	SameSite string `json:"same_site"`
}

type TLS struct {
	SubjectCN  string   `json:"subject_cn"`
	IssuerCN   string   `json:"issuer_cn"`
	SANs       []string `json:"sans"`
	NotBefore  string   `json:"not_before"`
	NotAfter   string   `json:"not_after"`
	SHA256     string   `json:"sha256"`
	SelfSigned bool     `json:"self_signed"`
}

type Response struct {
	URL           string
	StatusCode    int
	Title         string
	Headers       map[string]string
	Cookies       []Cookie
	RedirectChain []string
	Body          []byte
	tls           *tls.ConnectionState
}

type Prober struct {
	Timeout   time.Duration
	Transport func(target string) http.RoundTripper
}

type Session struct {
	HTTP HTTP
	Body []byte

	client  *http.Client
	base    *url.URL
	hosts   []string
	port    string
	timeout time.Duration

	mu    sync.Mutex
	cache map[string]*Response
	extra int
}

func Probe(ctx context.Context, address string, port int, useTLS bool, hostname string) (*Session, error) {
	return (&Prober{}).Probe(ctx, address, port, useTLS, hostname)
}

func (p *Prober) Probe(ctx context.Context, address string, port int, useTLS bool, hostname string) (*Session, error) {
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	host := address
	if hostname != "" {
		host = hostname
	}
	portStr := strconv.Itoa(port)
	base := &url.URL{Scheme: scheme, Host: urlHost(host, portStr, scheme), Path: "/"}
	target := net.JoinHostPort(address, portStr)
	var transport http.RoundTripper
	if p.Transport != nil {
		transport = p.Transport(target)
	} else {
		transport = NewTransport(target, timeout)
	}
	s := &Session{
		client: &http.Client{
			Transport:     transport,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		base:    base,
		hosts:   []string{strings.ToLower(address), strings.ToLower(hostname)},
		port:    portStr,
		timeout: timeout,
		cache:   map[string]*Response{},
	}

	root, err := s.get(ctx, base)
	if err != nil {
		return nil, fmt.Errorf("probe %s: %w", base, err)
	}
	s.cache["/"] = root
	s.Body = root.Body
	s.HTTP = HTTP{
		Scheme:        scheme,
		URL:           base.String(),
		StatusCode:    root.StatusCode,
		Title:         root.Title,
		Headers:       root.Headers,
		Cookies:       root.Cookies,
		RedirectChain: root.RedirectChain,
	}
	if root.tls != nil && len(root.tls.PeerCertificates) > 0 {
		s.HTTP.TLS = certInfo(root.tls.PeerCertificates[0])
	}

	fav, err := s.get(ctx, base.ResolveReference(&url.URL{Path: "/favicon.ico"}))
	if err == nil && fav.StatusCode == http.StatusOK && len(fav.Body) > 0 {
		sum := sha256.Sum256(fav.Body)
		s.HTTP.FaviconSHA256 = hex.EncodeToString(sum[:])
		s.HTTP.FaviconMMH3 = FaviconHash(fav.Body)
	}
	return s, nil
}

func NewTransport(target string, timeout time.Duration) *http.Transport {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	dialer := &net.Dialer{Timeout: timeout}
	return &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, target)
		},
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
	}
}

func (s *Session) Fetch(ctx context.Context, path string) (*Response, error) {
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.ContainsAny(path, "?#") {
		return nil, fmt.Errorf("probe: path %q is not a literal absolute path", path)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.cache[path]; ok {
		return r, nil
	}
	if s.extra >= MaxExtraRequests {
		return nil, ErrRequestLimit
	}
	s.extra++
	r, err := s.get(ctx, s.base.ResolveReference(&url.URL{Path: path}))
	if err != nil {
		return nil, fmt.Errorf("probe fetch %s: %w", path, err)
	}
	s.cache[path] = r
	return r, nil
}

func (s *Session) get(ctx context.Context, u *url.URL) (*Response, error) {
	chain := []string{}
	var first *tls.ConnectionState
	for {
		r, loc, err := s.once(ctx, u)
		if err != nil {
			return nil, err
		}
		if first == nil {
			first = r.tls
		}
		if loc == nil || len(chain) >= MaxRedirects {
			r.RedirectChain = chain
			r.tls = first
			return r, nil
		}
		chain = append(chain, loc.String())
		if !s.allowed(loc) {
			r.RedirectChain = chain
			r.tls = first
			return r, nil
		}
		u = loc
	}
}

func (s *Session) allowed(u *url.URL) bool {
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	port := u.Port()
	if port == "" {
		port = defaultPort(u.Scheme)
	}
	if port != s.port {
		return false
	}
	h := strings.ToLower(u.Hostname())
	for _, a := range s.hosts {
		if a != "" && h == a {
			return true
		}
	}
	return false
}

func (s *Session) once(ctx context.Context, u *url.URL) (*Response, *url.URL, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", UserAgent)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes))
	if err != nil {
		return nil, nil, fmt.Errorf("read body: %w", err)
	}
	r := &Response{
		URL:        u.String(),
		StatusCode: resp.StatusCode,
		Title:      Title(body, resp.Header.Get("Content-Type")),
		Headers:    headers(resp.Header),
		Cookies:    cookies(resp.Cookies()),
		Body:       body,
		tls:        resp.TLS,
	}
	var loc *url.URL
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		if l, err := resp.Location(); err == nil {
			loc = l
		}
	}
	return r, loc, nil
}

func Title(body []byte, contentType string) string {
	rd, err := charset.NewReader(bytes.NewReader(body), contentType)
	if err != nil {
		rd = bytes.NewReader(body)
	}
	z := html.NewTokenizer(rd)
	for {
		switch z.Next() {
		case html.ErrorToken:
			return ""
		case html.StartTagToken:
			name, _ := z.TagName()
			if string(name) != "title" {
				continue
			}
			if z.Next() != html.TextToken {
				return ""
			}
			return strings.Join(strings.Fields(string(z.Text())), " ")
		}
	}
}

func FaviconHash(data []byte) int32 {
	enc := base64.StdEncoding.EncodeToString(data)
	var b strings.Builder
	for len(enc) > 76 {
		b.WriteString(enc[:76])
		b.WriteByte('\n')
		enc = enc[76:]
	}
	if enc != "" {
		b.WriteString(enc)
		b.WriteByte('\n')
	}
	return mmh3([]byte(b.String()))
}

func mmh3(data []byte) int32 {
	const c1, c2 = 0xcc9e2d51, 0x1b873593
	var h uint32
	n := len(data)
	for i := 0; i+4 <= n; i += 4 {
		k := binary.LittleEndian.Uint32(data[i:])
		k *= c1
		k = bits.RotateLeft32(k, 15)
		k *= c2
		h ^= k
		h = bits.RotateLeft32(h, 13)
		h = h*5 + 0xe6546b64
	}
	tail := data[n&^3:]
	var k uint32
	switch len(tail) {
	case 3:
		k ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k ^= uint32(tail[0])
		k *= c1
		k = bits.RotateLeft32(k, 15)
		k *= c2
		h ^= k
	}
	h ^= uint32(n)
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return int32(h)
}

func headers(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for name, values := range h {
		name = strings.ToLower(name)
		if name == "set-cookie" {
			continue
		}
		out[name] = strings.Join(values, ", ")
	}
	return out
}

func cookies(cs []*http.Cookie) []Cookie {
	out := make([]Cookie, 0, len(cs))
	for _, c := range cs {
		ss := ""
		switch c.SameSite {
		case http.SameSiteLaxMode:
			ss = "Lax"
		case http.SameSiteStrictMode:
			ss = "Strict"
		case http.SameSiteNoneMode:
			ss = "None"
		}
		out = append(out, Cookie{Name: c.Name, HTTPOnly: c.HttpOnly, Secure: c.Secure, SameSite: ss})
	}
	return out
}

func certInfo(c *x509.Certificate) *TLS {
	sans := append([]string{}, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		sans = append(sans, ip.String())
	}
	sort.Strings(sans)
	sum := sha256.Sum256(c.Raw)
	return &TLS{
		SubjectCN:  c.Subject.CommonName,
		IssuerCN:   c.Issuer.CommonName,
		SANs:       sans,
		NotBefore:  c.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:   c.NotAfter.UTC().Format(time.RFC3339),
		SHA256:     hex.EncodeToString(sum[:]),
		SelfSigned: bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil,
	}
}

func urlHost(host, port, scheme string) string {
	if port == defaultPort(scheme) {
		if strings.Contains(host, ":") {
			return "[" + host + "]"
		}
		return host
	}
	return net.JoinHostPort(host, port)
}

func defaultPort(scheme string) string {
	if scheme == "https" {
		return "443"
	}
	return "80"
}
