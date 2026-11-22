package detect

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"

	"asi/internal/probe"
)

const (
	packFixtureDir  = "testdata/pack"
	packFixtureBase = "http://fixture.test/"
	packRootFile    = "root.http"
	packFaviconFile = "favicon.ico"
	packMaxPaths    = 3
)

var packProducts = map[string][]string{
	"pack/lab-agh.yaml": {"WordPress", "phpMyAdmin", "Adminer", "DVWA", "Gitea", "RabbitMQ", "Traefik", "Nginx Proxy Manager", "httpbin", "Toxiproxy"},
	"pack/common.yaml + pack/devices.yaml": {
		"Grafana", "Jenkins", "GitLab", "Apache Tomcat", "Kibana", "Portainer", "MinIO", "Prometheus", "Keycloak",
		"Joomla", "Drupal", "Roundcube", "Zabbix", "Proxmox VE", "pfSense", "Synology DSM", "MikroTik RouterOS",
		"Hikvision", "Dahua", "HP Printer", "Brother Printer",
	},
}

func mustPack(t *testing.T) []Signature {
	t.Helper()
	sigs, err := Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	return sigs
}

func packFileSignatures(t *testing.T, group string) []Signature {
	t.Helper()
	var out []Signature
	for _, f := range strings.Split(group, " + ") {
		data, err := packFS.ReadFile(f)
		if err != nil {
			t.Fatalf("read embedded %s: %v", f, err)
		}
		out = append(out, mustParse(t, string(data))...)
	}
	return out
}

func TestPackLoads(t *testing.T) {
	sigs := mustPack(t)
	ids := map[string]bool{}
	for _, s := range sigs {
		if !strings.HasPrefix(s.ID, "builtin-") {
			t.Errorf("signature %q: id does not start with builtin-", s.ID)
		}
		if ids[s.ID] {
			t.Errorf("signature %q defined twice", s.ID)
		}
		ids[s.ID] = true
		if s.Method != "GET" && s.Method != "HEAD" {
			t.Errorf("signature %q: method %q", s.ID, s.Method)
		}
	}
	for group, products := range packProducts {
		fileSigs := packFileSignatures(t, group)
		if len(fileSigs) == 0 {
			t.Logf("%s is empty: product coverage not checked yet", group)
			continue
		}
		for _, p := range products {
			if !slices.ContainsFunc(sigs, func(s Signature) bool { return strings.EqualFold(s.Name, p) }) {
				t.Errorf("no pack signature named %q (%s)", p, group)
			}
		}
	}
}

func TestPackRejectsUnsafeOrForeignIDs(t *testing.T) {
	sig := func(id, request string) string {
		return "- {id: " + id + ", name: X, kind: technology, confidence: 50, request: {" + request + "}, match: {all: [{type: status, value: \"200\"}]}}\n"
	}
	cases := []struct {
		name  string
		files map[string]string
		rule  string
	}{
		{"post", map[string]string{"pack/a.yaml": sig("builtin-a", "method: POST")}, RuleMethod},
		{"query", map[string]string{"pack/a.yaml": sig("builtin-a", "path: \"/x?y=1\"")}, RulePath},
		{"credentials", map[string]string{"pack/a.yaml": sig("builtin-a", "password: x")}, RuleCredentials},
		{"prefix", map[string]string{"pack/a.yaml": sig("wordpress-generator", "path: /")}, RuleSchema},
		{"duplicate across files", map[string]string{"pack/a.yaml": sig("builtin-a", "path: /"), "pack/b.yaml": sig("builtin-a", "path: /")}, RuleDuplicateID},
		{"too many paths", map[string]string{
			"pack/a.yaml": sig("builtin-1", "path: /1") + sig("builtin-2", "path: /2") + sig("builtin-3", "path: /3"),
			"pack/b.yaml": sig("builtin-4", "path: /4") + sig("builtin-5", "path: /5") + sig("builtin-6", "path: /6"),
		}, RuleExtraRequests},
	}
	for _, c := range cases {
		fsys := fstest.MapFS{}
		for name, data := range c.files {
			fsys[name] = &fstest.MapFile{Data: []byte(data)}
		}
		if _, err := loadPack(fsys); !isRule(err, c.rule) {
			t.Errorf("%s: err = %v, want rule %q", c.name, err, c.rule)
		}
	}
	good := fstest.MapFS{"pack/a.yaml": {Data: []byte(sig("builtin-a", "method: HEAD, path: /a"))}, "pack/b.yaml": {Data: []byte("[]\n")}, "pack/c.txt": {Data: []byte("ignored")}}
	if sigs, err := loadPack(good); err != nil || len(sigs) != 1 || sigs[0].Method != "HEAD" {
		t.Errorf("good pack = %+v, %v", sigs, err)
	}
	files, err := filepath.Glob("pack/*.yaml")
	if err != nil || len(files) == 0 {
		t.Fatalf("pack files on disk = %v, %v", files, err)
	}
	for _, f := range files {
		if _, err := packFS.ReadFile(f); err != nil {
			t.Errorf("%s is not embedded: %v", f, err)
		}
	}
}

func isRule(err error, rule string) bool {
	var re *RuleError
	return errors.As(err, &re) && re.Rule == rule
}

func TestPackExtraRequestsBudget(t *testing.T) {
	paths := map[string]bool{}
	for _, s := range mustPack(t) {
		if s.Path != "/" {
			paths[s.Path] = true
		}
	}
	if len(paths) > packMaxPaths {
		t.Errorf("pack uses %d extra request paths %v, at most %d allowed", len(paths), paths, packMaxPaths)
	}
}

func TestPackCombinesWithLabSignatures(t *testing.T) {
	lab, err := LoadDir("../../lab/signatures")
	if err != nil {
		t.Fatalf("LoadDir(lab/signatures): %v", err)
	}
	pack := mustPack(t)
	set, err := Combine(lab, pack)
	if err != nil {
		t.Fatalf("Combine(lab, Pack()): %v", err)
	}
	if got, want := len(set.Signatures), len(lab.Signatures)+len(pack); got != want {
		t.Errorf("combined %d signatures, want %d", got, want)
	}
}

func TestPackLeavesUserExtraRequestBudget(t *testing.T) {
	var src strings.Builder
	userPaths := []string{"/a", "/b", "/c", "/d"}
	for i, p := range userPaths {
		fmt.Fprintf(&src, "- {id: u%d, name: U%d, kind: custom, confidence: 1, request: {method: GET, path: '%s'}, match: {all: [{type: status, value: \"200\"}]}}\n", i, i, p)
	}
	user := mustParse(t, src.String())
	pack := mustPack(t)
	for _, tc := range []struct {
		name string
		sigs func() (*Set, error)
	}{
		{"pack first", func() (*Set, error) { return Combine(nil, append(slices.Clone(pack), user...)) }},
		{"directory plus pack", func() (*Set, error) { return Combine(&Set{Signatures: user}, pack) }},
	} {
		set, err := tc.sigs()
		if err != nil {
			t.Fatalf("%s: Combine: %v", tc.name, err)
		}
		ok := &probe.Response{StatusCode: 200, Headers: map[string]string{}}
		f := &fakeFetcher{responses: map[string]*probe.Response{"/": ok, "/a": ok, "/b": ok, "/c": ok, "/d": ok}}
		res := set.detect(context.Background(), f, &probe.HTTP{})
		if extra := len(f.calls) - 1; extra > probe.MaxExtraRequests {
			t.Errorf("%s: %d extra requests %v, at most %d", tc.name, extra, f.calls, probe.MaxExtraRequests)
		}
		for _, p := range userPaths {
			if !slices.Contains(f.calls, p) {
				t.Errorf("%s: user path %s not fetched; calls = %v", tc.name, p, f.calls)
			}
		}
		var ids []string
		for _, fd := range res.Findings {
			if !strings.HasPrefix(fd.SignatureID, PackIDPrefix) {
				ids = append(ids, fd.SignatureID)
			}
		}
		if !slices.Equal(ids, []string{"u0", "u1", "u2", "u3"}) {
			t.Errorf("%s: user findings = %v", tc.name, ids)
		}
	}
	five := mustParse(t, src.String()+"- {id: u4, name: U4, kind: custom, confidence: 1, request: {method: GET, path: /e}, match: {all: [{type: status, value: \"200\"}]}}\n")
	if _, err := Combine(&Set{Signatures: five}, pack); err != nil {
		t.Errorf("five user paths plus pack: %v", err)
	}
	sixth := mustParse(t, "- {id: u5, name: U5, kind: custom, confidence: 1, request: {method: GET, path: /f}, match: {all: [{type: status, value: \"200\"}]}}\n")
	if _, err := Combine(&Set{Signatures: five}, append(slices.Clone(pack), sixth...)); !isRule(err, RuleExtraRequests) {
		t.Errorf("six user paths: err = %v, want rule %q", err, RuleExtraRequests)
	}
}

func TestParseRejectsOutdatedKind(t *testing.T) {
	_, err := Parse([]byte("- {id: my-outdated, name: Old, kind: outdated, confidence: 50, match: {all: [{type: status, value: \"200\"}]}}\n"))
	if !isRule(err, RuleSchema) {
		t.Errorf("kind outdated: err = %v, want rule %q", err, RuleSchema)
	}
}

type fixtureFetcher struct {
	responses map[string]*probe.Response
	calls     []string
}

func (f *fixtureFetcher) Fetch(_ context.Context, path string) (*probe.Response, error) {
	f.calls = append(f.calls, path)
	if r, ok := f.responses[path]; ok {
		return r, nil
	}
	return nil, fmt.Errorf("fixture has no response for %s", path)
}

func fixtureFileName(path string) string {
	if path == "/" {
		return packRootFile
	}
	return strings.ReplaceAll(strings.TrimPrefix(path, "/"), "/", "__") + ".http"
}

func fixturePath(name string) string {
	if name == packRootFile {
		return "/"
	}
	return "/" + strings.ReplaceAll(strings.TrimSuffix(name, ".http"), "__", "/")
}

func packFixtureProducts(t *testing.T) []string {
	t.Helper()
	return packFixtureProductsIn(t, packFixtureDir)
}

func packFixtureProductsIn(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
			out = append(out, e.Name())
		}
	}
	return out
}

func loadPackFixture(t *testing.T, dir string) (*fixtureFetcher, *probe.HTTP) {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.http"))
	if err != nil {
		t.Fatal(err)
	}
	f := &fixtureFetcher{responses: map[string]*probe.Response{}}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		path := fixturePath(filepath.Base(file))
		r, err := parseRawResponses(packFixtureBase, path, data)
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		f.responses[path] = r
	}
	root := f.responses["/"]
	if root == nil {
		t.Fatalf("%s: missing %s", dir, packRootFile)
	}
	h := &probe.HTTP{
		Scheme:        "http",
		URL:           packFixtureBase,
		StatusCode:    root.StatusCode,
		Title:         root.Title,
		Headers:       root.Headers,
		Cookies:       root.Cookies,
		RedirectChain: root.RedirectChain,
	}
	if fav, err := os.ReadFile(filepath.Join(dir, packFaviconFile)); err == nil && len(fav) > 0 {
		sum := sha256.Sum256(fav)
		h.FaviconSHA256 = hex.EncodeToString(sum[:])
		h.FaviconMMH3 = probe.FaviconHash(fav)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return f, h
}

func runPackFixture(t *testing.T, product string) Result {
	t.Helper()
	f, h := loadPackFixture(t, filepath.Join(packFixtureDir, product))
	set := &Set{Signatures: mustPack(t)}
	return set.detect(context.Background(), f, h)
}

func parseRawResponses(base, path string, data []byte) (*probe.Response, error) {
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("parse base: %w", err)
	}
	u = u.ResolveReference(&url.URL{Path: path})
	br := bufio.NewReader(bytes.NewReader(data))
	tp := textproto.NewReader(br)
	chain := []string{}
	for {
		line, err := tp.ReadLine()
		for err == nil && strings.TrimSpace(line) == "" {
			line, err = tp.ReadLine()
		}
		if err != nil {
			return nil, fmt.Errorf("read status line: %w", err)
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.HasPrefix(fields[0], "HTTP/") {
			return nil, fmt.Errorf("bad status line %q", line)
		}
		code, err := strconv.Atoi(fields[1])
		if err != nil {
			return nil, fmt.Errorf("bad status code in %q: %w", line, err)
		}
		hdr, err := tp.ReadMIMEHeader()
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("read headers: %w", err)
		}
		header := http.Header(hdr)
		if loc := header.Get("Location"); code >= 300 && code < 400 && loc != "" && nextIsResponse(br) {
			next, err := u.Parse(loc)
			if err != nil {
				return nil, fmt.Errorf("bad location %q: %w", loc, err)
			}
			chain = append(chain, next.String())
			u = next
			continue
		}
		body, err := io.ReadAll(br)
		if err != nil {
			return nil, fmt.Errorf("read body: %w", err)
		}
		r := &probe.Response{
			URL:           u.String(),
			StatusCode:    code,
			Title:         probe.Title(body, header.Get("Content-Type")),
			Headers:       map[string]string{},
			RedirectChain: chain,
			Body:          body,
		}
		for name, values := range header {
			if name = strings.ToLower(name); name != "set-cookie" {
				r.Headers[name] = strings.Join(values, ", ")
			}
		}
		for _, c := range (&http.Response{Header: header}).Cookies() {
			ss := ""
			switch c.SameSite {
			case http.SameSiteLaxMode:
				ss = "Lax"
			case http.SameSiteStrictMode:
				ss = "Strict"
			case http.SameSiteNoneMode:
				ss = "None"
			}
			r.Cookies = append(r.Cookies, probe.Cookie{Name: c.Name, HTTPOnly: c.HttpOnly, Secure: c.Secure, SameSite: ss})
		}
		return r, nil
	}
}

func nextIsResponse(br *bufio.Reader) bool {
	for {
		b, err := br.Peek(1)
		if err != nil {
			return false
		}
		if b[0] != '\r' && b[0] != '\n' {
			break
		}
		if _, err := br.ReadByte(); err != nil {
			return false
		}
	}
	p, err := br.Peek(5)
	return err == nil && string(p) == "HTTP/"
}

func TestPackFixtureHarness(t *testing.T) {
	fav := []byte("\x00\x00\x01\x00fake-icon")
	dir := writeFiles(t, map[string]string{
		packRootFile: "HTTP/1.1 302 Found\r\nLocation: /wp-admin/install.php\r\n\r\n" +
			"HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\nContent-Type: text/html; charset=UTF-8\r\n" +
			"Set-Cookie: sid=1; HttpOnly; SameSite=Lax\r\nSet-Cookie: lang=en\r\n\r\n" +
			"<html><head><title>  Install\n Page </title></head><body>HTTP/1.1 in body</body></html>\n",
		fixtureFileName("/api/version"): "HTTP/2 404\ncontent-type: text/plain\n\nnot found\n",
		packFaviconFile:                 string(fav),
		"source.txt":                    "image: test\n",
	})
	f, h := loadPackFixture(t, dir)

	root := f.responses["/"]
	if root.StatusCode != 200 || root.Title != "Install Page" || root.URL != "http://fixture.test/wp-admin/install.php" {
		t.Errorf("root = %d %q %q", root.StatusCode, root.Title, root.URL)
	}
	if !slices.Equal(root.RedirectChain, []string{"http://fixture.test/wp-admin/install.php"}) {
		t.Errorf("redirect chain = %v", root.RedirectChain)
	}
	if root.Headers["server"] != "nginx/1.25.3" || root.Headers["set-cookie"] != "" {
		t.Errorf("headers = %v", root.Headers)
	}
	if len(root.Cookies) != 2 || root.Cookies[0] != (probe.Cookie{Name: "sid", HTTPOnly: true, SameSite: "Lax"}) || root.Cookies[1].Name != "lang" {
		t.Errorf("cookies = %+v", root.Cookies)
	}
	if !bytes.Contains(root.Body, []byte("HTTP/1.1 in body")) {
		t.Errorf("body = %q", root.Body)
	}
	if h.StatusCode != 200 || h.Title != "Install Page" || !slices.Equal(h.RedirectChain, root.RedirectChain) {
		t.Errorf("http = %+v", h)
	}
	sum := sha256.Sum256(fav)
	if h.FaviconSHA256 != hex.EncodeToString(sum[:]) || h.FaviconMMH3 != probe.FaviconHash(fav) {
		t.Errorf("favicon = %s %d", h.FaviconSHA256, h.FaviconMMH3)
	}
	if r := f.responses["/api/version"]; r == nil || r.StatusCode != 404 || r.Headers["content-type"] != "text/plain" {
		t.Errorf("/api/version = %+v", r)
	}
	if _, err := f.Fetch(context.Background(), "/missing"); err == nil {
		t.Error("Fetch(/missing) succeeded")
	}
	if got := fixturePath(fixtureFileName("/a/b.php")); got != "/a/b.php" {
		t.Errorf("file name round trip = %q", got)
	}

	set := &Set{Signatures: mustParse(t, "- {id: builtin-t, name: T, kind: technology, category: c, confidence: 90, request: {path: /api/version}, match: {all: [{type: status, value: \"404\"}]}}\n")}
	res := set.detect(context.Background(), f, h)
	if len(res.Findings) != 1 || res.Findings[0].SignatureID != "builtin-t" {
		t.Errorf("findings = %+v", res.Findings)
	}
	if !slices.ContainsFunc(res.Technologies, func(tc Technology) bool { return tc.Name == "nginx" && tc.Version == "1.25.3" }) {
		t.Errorf("technologies = %+v, want built-in nginx 1.25.3", res.Technologies)
	}
}

func TestPackFixturesLoad(t *testing.T) {
	for _, p := range packFixtureProducts(t) {
		t.Run(p, func(t *testing.T) {
			runPackFixture(t, p)
		})
	}
}
