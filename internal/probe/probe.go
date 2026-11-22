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
	"net/http/httptrace"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/net/html"
	"golang.org/x/net/html/charset"
	"golang.org/x/net/http/httpguts"

	"asi/internal/version"
)

const (
	MaxRedirects     = 5
	MaxExtraRequests = 5
	MaxBodyBytes     = 1 << 20
	DefaultTimeout   = 10 * time.Second
	MaxTitleRunes    = 512
	MaxCookieRunes   = 256
	maxRecordedBytes = 64 << 10
)

const truncated = "…"

const UserAgent = "asi-discovery/" + version.Version

var ErrRequestLimit = errors.New("probe: extra request limit reached")

type HTTP struct {
	Scheme          string            `json:"scheme"`
	URL             string            `json:"url"`
	StatusCode      int               `json:"status_code"`
	Title           string            `json:"title"`
	Headers         map[string]string `json:"headers"`
	Cookies         []Cookie          `json:"cookies"`
	RedirectChain   []string          `json:"redirect_chain"`
	TLS             *TLS              `json:"tls,omitempty"`
	FaviconSHA256   string            `json:"favicon_sha256"`
	FaviconMMH3     int32             `json:"favicon_mmh3"`
	FaviconUnstable bool              `json:"favicon_unstable,omitempty"`
	TTFBMS          int64             `json:"ttfb_ms,omitempty"`
	ResponseMS      int64             `json:"response_time_ms,omitempty"`
	Error           string            `json:"error,omitempty"`
}

const (
	ErrorTimeout      = "timeout"
	ErrorTLSHandshake = "tls handshake failed"
	ErrorRequest      = "request failed"
)

var ErrTLSHandshake = errors.New("tls handshake failed")

type TimeoutError struct {
	HTTP HTTP
	err  error
}

func (e *TimeoutError) Error() string { return "timeout: " + e.err.Error() }

func (e *TimeoutError) Unwrap() error { return e.err }

type FailedError struct {
	HTTP HTTP
	err  error
}

func (e *FailedError) Error() string { return e.HTTP.Error + ": " + e.err.Error() }

func (e *FailedError) Unwrap() error { return e.err }

func Observed(err error) (HTTP, bool) {
	var te *TimeoutError
	if errors.As(err, &te) {
		return te.HTTP, true
	}
	var fe *FailedError
	if errors.As(err, &fe) {
		return fe.HTTP, true
	}
	return HTTP{}, false
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
	ttfb, total   time.Duration
}

type Prober struct {
	Timeout         time.Duration
	Transport       func(target string) http.RoundTripper
	PreviousFavicon func(address string, port int) string
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
	base := baseURL(address, port, useTLS, hostname)
	scheme := base.Scheme
	portStr := strconv.Itoa(port)
	target := net.JoinHostPort(address, portStr)
	var transport http.RoundTripper
	if p.Transport != nil {
		transport = Recording(p.Transport(target))
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

	begin := time.Now()
	root, err := s.get(ctx, http.MethodGet, base)
	if err != nil {
		if ctx.Err() == nil {
			h := HTTP{
				Scheme:        scheme,
				URL:           base.String(),
				Headers:       map[string]string{},
				Cookies:       []Cookie{},
				RedirectChain: []string{},
				ResponseMS:    millis(time.Since(begin)),
			}
			if root != nil {
				h.StatusCode, h.Title, h.Headers, h.Cookies, h.RedirectChain = root.StatusCode, root.Title, root.Headers, root.Cookies, root.RedirectChain
				h.TTFBMS = millis(root.ttfb)
				if root.tls != nil && len(root.tls.PeerCertificates) > 0 {
					h.TLS = certInfo(root.tls.PeerCertificates[0])
				}
			}
			if isTimeout(err) {
				h.Error = ErrorTimeout
				err = &TimeoutError{err: err, HTTP: h}
			} else {
				h.Error = failure(err)
				err = &FailedError{err: err, HTTP: h}
			}
		}
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
		TTFBMS:        millis(root.ttfb),
		ResponseMS:    millis(root.total),
	}
	if root.tls != nil && len(root.tls.PeerCertificates) > 0 {
		s.HTTP.TLS = certInfo(root.tls.PeerCertificates[0])
	}

	favURL := base.ResolveReference(&url.URL{Path: "/favicon.ico"})
	fav, err := s.get(ctx, http.MethodGet, favURL)
	if err == nil && fav.StatusCode == http.StatusOK && len(fav.Body) > 0 {
		sum := sha256.Sum256(fav.Body)
		s.HTTP.FaviconSHA256 = hex.EncodeToString(sum[:])
		s.HTTP.FaviconMMH3 = FaviconHash(fav.Body)
		if prev := p.previousFavicon(address, port); prev != "" && prev != s.HTTP.FaviconSHA256 {
			s.HTTP.FaviconUnstable = !s.sameAgain(ctx, favURL, fav.Body)
		}
	}
	return s, nil
}

func (s *Session) sameAgain(ctx context.Context, u *url.URL, body []byte) bool {
	s.mu.Lock()
	if s.extra >= MaxExtraRequests {
		s.mu.Unlock()
		return false
	}
	s.extra++
	s.mu.Unlock()
	again, err := s.get(ctx, http.MethodGet, u)
	return err == nil && again.StatusCode == http.StatusOK && bytes.Equal(again.Body, body)
}

func FailedHTTP(address string, port int, useTLS bool, hostname string, err error) HTTP {
	u := baseURL(address, port, useTLS, hostname)
	msg := ErrorRequest
	switch {
	case isTimeout(err):
		msg = ErrorTimeout
	case errors.Is(err, ErrTLSHandshake):
		msg = ErrorTLSHandshake
	}
	return HTTP{Scheme: u.Scheme, URL: u.String(), Headers: map[string]string{}, Cookies: []Cookie{}, RedirectChain: []string{}, Error: msg}
}

func baseURL(address string, port int, useTLS bool, hostname string) *url.URL {
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	host := address
	if hostname != "" {
		host = hostname
	}
	return &url.URL{Scheme: scheme, Host: urlHost(host, strconv.Itoa(port), scheme), Path: "/"}
}

func NewTransport(target string, timeout time.Duration) *http.Transport {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	dialer := &net.Dialer{Timeout: timeout}
	return &http.Transport{
		DialContext: recordingDial(func(ctx context.Context, network, _ string) (net.Conn, error) {
			c, err := dialer.DialContext(ctx, network, target)
			if err != nil {
				return nil, err
			}
			return &sniffConn{Conn: c}, nil
		}),
		DialTLSContext: recordingDial(func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := dialer.DialContext(ctx, network, target)
			if err != nil {
				return nil, err
			}
			cfg := &tls.Config{InsecureSkipVerify: true}
			if host, _, err := net.SplitHostPort(addr); err == nil && net.ParseIP(host) == nil {
				cfg.ServerName = host
			}
			tc := tls.Client(c, cfg)
			if err := tc.HandshakeContext(ctx); err != nil {
				c.Close()
				return nil, fmt.Errorf("%w: %w", ErrTLSHandshake, err)
			}
			return tc, nil
		}),
		DisableKeepAlives: true,
	}
}

var ErrTLSReply = errors.New("server answered plain HTTP with a TLS record")

type sniffConn struct {
	net.Conn
	read bool
}

func (c *sniffConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if !c.read && n > 0 {
		c.read = true
		if (b[0] == 0x15 || b[0] == 0x16) && (n == 1 || b[1] == 0x03) {
			return 0, ErrTLSReply
		}
	}
	return n, err
}

func (s *Session) Fetch(ctx context.Context, path string) (*Response, error) {
	return s.fetch(ctx, http.MethodGet, path)
}

func (s *Session) Head(ctx context.Context, path string) (*Response, error) {
	return s.fetch(ctx, http.MethodHead, path)
}

func (s *Session) fetch(ctx context.Context, method, path string) (*Response, error) {
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.ContainsAny(path, "?#") {
		return nil, fmt.Errorf("probe: path %q is not a literal absolute path", path)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := path
	if method != http.MethodGet {
		key = method + " " + path
	}
	if r, ok := s.cache[key]; ok {
		return r, nil
	}
	if s.extra >= MaxExtraRequests {
		return nil, ErrRequestLimit
	}
	s.extra++
	r, err := s.get(ctx, method, s.base.ResolveReference(&url.URL{Path: path}))
	if err != nil {
		return nil, fmt.Errorf("probe fetch %s %s: %w", method, path, err)
	}
	s.cache[key] = r
	return r, nil
}

func (s *Session) get(ctx context.Context, method string, u *url.URL) (*Response, error) {
	chain := []string{}
	var first *Response
	var total time.Duration
	for {
		r, loc, err := s.once(ctx, method, u)
		if r == nil {
			return nil, err
		}
		if first == nil {
			first = r
		}
		total += r.total
		if err != nil {
			r.RedirectChain = chain
			r.tls, r.ttfb, r.total = first.tls, first.ttfb, total
			return r, err
		}
		if loc == nil || len(chain) >= MaxRedirects {
			r.RedirectChain = chain
			r.tls, r.ttfb, r.total = first.tls, first.ttfb, total
			return r, nil
		}
		chain = append(chain, loc.String())
		if !s.allowed(loc) {
			r.RedirectChain = chain
			r.tls, r.ttfb, r.total = first.tls, first.ttfb, total
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

func (s *Session) once(ctx context.Context, method string, u *url.URL) (*Response, *url.URL, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	t0 := time.Now()
	var dialed, firstByte atomic.Int64
	since := func() int64 { return int64(time.Since(t0)) + 1 }
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GetConn:              func(string) { dialed.CompareAndSwap(0, since()) },
		GotFirstResponseByte: func() { firstByte.CompareAndSwap(0, since()) },
	})
	req, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", UserAgent)
	rec := &headRecorder{}
	if u.Scheme == "http" {
		req = req.WithContext(context.WithValue(ctx, headKey{}, rec))
	}
	resp, err := s.client.Do(req)
	if err != nil {
		err = fmt.Errorf("request: %w", err)
		if code, hdr, ok := rec.head(); ok {
			begin := max(dialed.Load(), 1)
			return &Response{
				URL:        u.String(),
				StatusCode: code,
				Headers:    headers(hdr),
				Cookies:    cookies((&http.Response{Header: hdr}).Cookies()),
				Body:       []byte{},
				ttfb:       time.Duration(firstByte.Load() - begin),
				total:      time.Duration(since() - begin),
			}, nil, &stageError{stage: "headers", err: err}
		}
		return nil, nil, err
	}
	firstByte.CompareAndSwap(0, since())
	defer resp.Body.Close()
	body, bodyErr := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes))
	end := since()
	begin := max(dialed.Load(), 1)
	r := &Response{
		URL:        u.String(),
		StatusCode: resp.StatusCode,
		Title:      capRunes(Title(body, resp.Header.Get("Content-Type")), MaxTitleRunes),
		Headers:    headers(resp.Header),
		Cookies:    cookies(resp.Cookies()),
		Body:       body,
		tls:        resp.TLS,
		ttfb:       time.Duration(firstByte.Load() - begin),
		total:      time.Duration(end - begin),
	}
	if bodyErr != nil {
		return r, nil, &stageError{stage: "read body", err: bodyErr}
	}
	var loc *url.URL
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		if l, err := resp.Location(); err == nil {
			loc = l
		}
	}
	return r, loc, nil
}

func capRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n-utf8.RuneCountInString(truncated)]) + truncated
}

type stageError struct {
	stage string
	err   error
}

func (e *stageError) Error() string { return e.stage + ": " + e.err.Error() }

func (e *stageError) Unwrap() error { return e.err }

func failure(err error) string {
	stage := ""
	var se *stageError
	if errors.As(err, &se) {
		stage = se.stage + ": "
	}
	var msg string
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		msg = "connection refused"
	case errors.Is(err, syscall.ECONNRESET):
		msg = "connection reset"
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		msg = "host unreachable"
	case errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.EOF):
		msg = "connection closed"
	default:
		inner := err
		if se != nil {
			inner = se.err
		}
		var ue *url.Error
		if errors.As(inner, &ue) {
			inner = ue.Err
		}
		msg = strings.Join(strings.Fields(inner.Error()), " ")
	}
	return capRunes(stage+msg, 256)
}

type headKey struct{}

type headRecorder struct {
	mu  sync.Mutex
	buf []byte
}

func (r *headRecorder) Write(p []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf = append(r.buf, p[:min(len(p), maxRecordedBytes-len(r.buf))]...)
}

func (r *headRecorder) head() (int, http.Header, bool) {
	r.mu.Lock()
	raw := string(r.buf)
	r.mu.Unlock()
	head, _, _ := strings.Cut(raw, "\r\n\r\n")
	lines := strings.Split(head, "\n")
	proto, rest, _ := strings.Cut(strings.TrimSuffix(lines[0], "\r"), " ")
	code, err := strconv.Atoi(strings.SplitN(rest, " ", 2)[0])
	if !strings.HasPrefix(proto, "HTTP/1.") || err != nil || code < 100 || code > 999 {
		return 0, nil, false
	}
	hdr := http.Header{}
	for _, line := range lines[1:] {
		name, value, ok := strings.Cut(strings.TrimSuffix(line, "\r"), ":")
		value = strings.TrimSpace(value)
		if ok && httpguts.ValidHeaderFieldName(name) && httpguts.ValidHeaderFieldValue(value) {
			hdr.Add(name, value)
		}
	}
	return code, hdr, true
}

type recordingConn struct {
	net.Conn
	rec *headRecorder
}

func (c recordingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.rec.Write(p[:n])
	return n, err
}

type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

func recordingDial(dial dialFunc) dialFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := dial(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		if _, wrapped := c.(recordingConn); wrapped {
			return c, nil
		}
		if rec, ok := ctx.Value(headKey{}).(*headRecorder); ok {
			return recordingConn{Conn: c, rec: rec}, nil
		}
		return c, nil
	}
}

func Recording(rt http.RoundTripper) http.RoundTripper {
	t, ok := rt.(*http.Transport)
	if !ok {
		return rt
	}
	t = t.Clone()
	dial := t.DialContext
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	t.DialContext = recordingDial(dial)
	return t
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.Is(err, context.DeadlineExceeded) || errors.As(err, &ne) && ne.Timeout()
}

func TLSReply(err error) bool {
	return errors.Is(err, ErrTLSReply)
}

func millis(d time.Duration) int64 {
	if d <= 0 {
		return 0
	}
	return int64((d + time.Millisecond - 1) / time.Millisecond)
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
		out = append(out, Cookie{Name: capRunes(c.Name, MaxCookieRunes), HTTPOnly: c.HttpOnly, Secure: c.Secure, SameSite: ss})
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

func (p *Prober) previousFavicon(address string, port int) string {
	if p.PreviousFavicon == nil {
		return ""
	}
	return p.PreviousFavicon(address, port)
}
