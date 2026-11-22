package detect

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"asi/internal/probe"
)

const labServicesDir = "../../lab/services"

func resultNames(res Result) (techs, findings []string) {
	for _, tc := range res.Technologies {
		if !slices.Contains(techs, tc.Name) {
			techs = append(techs, tc.Name)
		}
	}
	for _, f := range res.Findings {
		if !slices.Contains(findings, f.SignatureID) {
			findings = append(findings, f.SignatureID)
		}
	}
	slices.Sort(techs)
	slices.Sort(findings)
	return techs, findings
}

func findingKinds(res Result) map[string]bool {
	kinds := map[string]bool{}
	for _, f := range res.Findings {
		kinds[f.Kind] = true
	}
	return kinds
}

func TestPackNoFalsePositives(t *testing.T) {
	want := map[string]struct{ techs, findings []string }{
		"admin-login":         {nil, []string{"builtin-admin-login"}},
		"adminer":             {[]string{"Adminer", "PHP"}, []string{"builtin-adminer", "builtin-adminer-login"}},
		"brother-printer":     {[]string{"Brother Printer"}, []string{"builtin-brother-printer", "builtin-brother-printer-iot"}},
		"dahua":               {[]string{"Dahua"}, []string{"builtin-dahua", "builtin-dahua-iot"}},
		"drupal":              {[]string{"Apache", "Drupal", "PHP"}, []string{"builtin-drupal"}},
		"dvwa":                {[]string{"Apache", "DVWA", "PHP"}, []string{"builtin-dvwa"}},
		"gitea":               {[]string{"Gitea"}, []string{"builtin-gitea"}},
		"gitlab":              {[]string{"GitLab", "nginx"}, []string{"builtin-gitlab"}},
		"grafana":             {[]string{"Grafana"}, []string{"builtin-grafana"}},
		"hikvision":           {[]string{"Hikvision"}, []string{"builtin-hikvision", "builtin-hikvision-iot"}},
		"hp-printer":          {[]string{"HP Printer"}, []string{"builtin-hp-printer", "builtin-hp-printer-iot"}},
		"httpbin":             {[]string{"httpbin"}, []string{"builtin-httpbin"}},
		"jenkins":             {[]string{"Jenkins"}, []string{"builtin-jenkins", "builtin-jenkins-admin"}},
		"joomla":              {[]string{"Apache", "Joomla", "PHP"}, []string{"builtin-joomla"}},
		"keycloak":            {[]string{"Keycloak"}, []string{"builtin-keycloak"}},
		"kibana":              {[]string{"Kibana"}, []string{"builtin-kibana"}},
		"mikrotik":            {[]string{"MikroTik RouterOS"}, []string{"builtin-mikrotik", "builtin-mikrotik-admin"}},
		"minio":               {[]string{"MinIO"}, []string{"builtin-minio"}},
		"nginx-proxy-manager": {[]string{"Nginx Proxy Manager"}, []string{"builtin-nginx-proxy-manager", "builtin-nginx-proxy-manager-ui"}},
		"pfsense":             {[]string{"PHP", "nginx", "pfSense"}, []string{"builtin-pfsense", "builtin-pfsense-admin"}},
		"phpmyadmin":          {[]string{"Apache", "PHP", "phpMyAdmin"}, []string{"builtin-phpmyadmin", "builtin-phpmyadmin-login"}},
		"portainer":           {[]string{"Portainer"}, []string{"builtin-portainer", "builtin-portainer-admin"}},
		"prometheus":          {[]string{"Prometheus"}, []string{"builtin-prometheus"}},
		"proxmox":             {[]string{"Proxmox VE"}, []string{"builtin-proxmox", "builtin-proxmox-admin"}},
		"rabbitmq":            {[]string{"RabbitMQ"}, []string{"builtin-rabbitmq-management", "builtin-rabbitmq-management-ui"}},
		"roundcube":           {[]string{"Apache", "Roundcube"}, []string{"builtin-roundcube"}},
		"synology":            {[]string{"Synology DSM", "nginx"}, []string{"builtin-synology-dsm", "builtin-synology-dsm-admin"}},
		"tomcat":              {[]string{"Apache Tomcat"}, []string{"builtin-tomcat"}},
		"toxiproxy":           {[]string{"Toxiproxy"}, []string{"builtin-toxiproxy"}},
		"traefik":             {[]string{"Traefik"}, []string{"builtin-traefik-api", "builtin-traefik-dashboard", "builtin-traefik-dashboard-ui"}},
		"wordpress":           {[]string{"Apache", "PHP", "WordPress"}, []string{"builtin-wordpress"}},
		"wordpress-4.7":       {[]string{"Apache", "PHP", "WordPress"}, []string{"builtin-wordpress-install"}},
		"zabbix":              {[]string{"Zabbix", "nginx"}, []string{"builtin-zabbix"}},
		"activemq":            {[]string{"ActiveMQ"}, []string{"builtin-activemq", "builtin-activemq-console"}},
		"activemq-console":    {[]string{"ActiveMQ"}, []string{"builtin-activemq", "builtin-activemq-console"}},
		"drupal-8":            {[]string{"Apache", "Drupal", "PHP"}, []string{"builtin-drupal"}},
		"elasticsearch-1.4":   {[]string{"Elasticsearch"}, []string{"builtin-elasticsearch"}},
		"grafana-8.2":         {[]string{"Grafana"}, []string{"builtin-grafana", "builtin-grafana-login"}},
		"httpd-2.4.49":        {[]string{"Apache"}, nil},
		"jenkins-2.441":       {[]string{"Jenkins"}, []string{"builtin-jenkins", "builtin-jenkins-admin"}},
		"phpmyadmin-4.8":      {[]string{"Apache", "PHP", "phpMyAdmin"}, []string{"builtin-phpmyadmin", "builtin-phpmyadmin-open"}},
		"tomcat-8.0":          {[]string{"Apache Tomcat"}, []string{"builtin-tomcat"}},
	}
	products := packFixtureProducts(t)
	for _, p := range products {
		t.Run(p, func(t *testing.T) {
			w, ok := want[p]
			if !ok {
				t.Fatalf("fixture %s has no expected technologies and findings in this test", p)
			}
			techs, findings := resultNames(runPackFixture(t, p))
			if !slices.Equal(techs, w.techs) {
				t.Errorf("technologies = %v, want %v", techs, w.techs)
			}
			if !slices.Equal(findings, w.findings) {
				t.Errorf("findings = %v, want %v", findings, w.findings)
			}
		})
	}
	for p := range want {
		if !slices.Contains(products, p) {
			t.Errorf("expected fixture %s is missing", p)
		}
	}
}

func TestPackAdminPanelAndIoTKinds(t *testing.T) {
	cases := []struct {
		dir        string
		admin, iot bool
	}{
		{"phpmyadmin", true, false},
		{"adminer", true, false},
		{"rabbitmq", true, false},
		{"traefik", true, false},
		{"nginx-proxy-manager", true, false},
		{"portainer", true, false},
		{"jenkins", true, false},
		{"admin-login", true, false},
		{"hikvision", false, true},
		{"dahua", false, true},
		{"hp-printer", false, true},
		{"brother-printer", false, true},
		{"wordpress", false, false},
		{"httpbin", false, false},
		{"gitea", false, false},
		{"prometheus", false, false},
	}
	for _, c := range cases {
		t.Run(c.dir, func(t *testing.T) {
			res := runPackFixture(t, c.dir)
			kinds := findingKinds(res)
			if kinds["admin-panel"] != c.admin {
				t.Errorf("admin-panel finding = %v, want %v (findings %+v)", kinds["admin-panel"], c.admin, res.Findings)
			}
			if kinds["iot"] != c.iot {
				t.Errorf("iot finding = %v, want %v (findings %+v)", kinds["iot"], c.iot, res.Findings)
			}
		})
	}
	admin := runPackFixture(t, "admin-login")
	if i := slices.IndexFunc(admin.Findings, func(f Finding) bool { return f.SignatureID == "builtin-admin-login" }); i < 0 || admin.Findings[i].Kind != "admin-panel" {
		t.Errorf("admin-login findings = %+v, want builtin-admin-login of kind admin-panel", admin.Findings)
	}
}

type labLocation struct {
	code    int
	target  string
	body    string
	headers [][2]string
}

type labService struct {
	dir       string
	headers   [][2]string
	locations map[string]*labLocation
}

var (
	labLocationRe = regexp.MustCompile(`^location\s+=\s+(\S+)\s*\{`)
	labHeaderRe   = regexp.MustCompile(`add_header\s+(\S+)\s+"((?:[^"\\]|\\.)*)"`)
	labReturnRe   = regexp.MustCompile(`return\s+(\d{3})\s+("(?:[^"\\]|\\.)*"|[^;\s]+)\s*;`)
)

func parseLabService(t *testing.T, dir string) *labService {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "default.conf"))
	if err != nil {
		t.Fatal(err)
	}
	s := &labService{dir: dir, locations: map[string]*labLocation{}}
	var loc *labLocation
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if m := labLocationRe.FindStringSubmatch(line); m != nil {
			loc = &labLocation{}
			s.locations[m[1]] = loc
		}
		for _, m := range labHeaderRe.FindAllStringSubmatch(line, -1) {
			h := [2]string{m[1], strings.ReplaceAll(m[2], `\"`, `"`)}
			if loc != nil {
				loc.headers = append(loc.headers, h)
			} else {
				s.headers = append(s.headers, h)
			}
		}
		if m := labReturnRe.FindStringSubmatch(line); m != nil && loc != nil {
			loc.code, _ = strconv.Atoi(m[1])
			if strings.HasPrefix(m[2], `"`) {
				loc.body = strings.ReplaceAll(strings.Trim(m[2], `"`), `\"`, `"`)
			} else {
				loc.target = m[2]
			}
		}
		if loc != nil && strings.HasSuffix(line, "}") {
			loc = nil
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return s
}

const labNotFound = "<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>nginx</center></body></html>"

func (s *labService) raw(t *testing.T, path string) (string, string) {
	t.Helper()
	code, body, ctype := 404, labNotFound, "text/html"
	headers := s.headers
	if loc, ok := s.locations[path]; ok {
		if len(loc.headers) > 0 {
			headers = loc.headers
		}
		code, body = loc.code, loc.body
		if loc.target != "" {
			return "HTTP/1.1 " + strconv.Itoa(code) + " Redirect\r\nServer: nginx\r\nLocation: " + loc.target + "\r\n" + labHeaderLines(headers) + "\r\n", loc.target
		}
	} else {
		file := strings.TrimPrefix(path, "/")
		if strings.HasSuffix(path, "/") {
			file += "index.html"
		}
		if data, err := os.ReadFile(filepath.Join(s.dir, "html", filepath.FromSlash(file))); err == nil {
			code, body = 200, string(data)
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
	}
	return "HTTP/1.1 " + strconv.Itoa(code) + " Status\r\nServer: nginx\r\nContent-Type: " + ctype + "\r\n" + labHeaderLines(headers) + "\r\n" + body, ""
}

func labHeaderLines(headers [][2]string) string {
	var b strings.Builder
	for _, h := range headers {
		b.WriteString(h[0] + ": " + h[1] + "\r\n")
	}
	return b.String()
}

func (s *labService) response(t *testing.T, path string) *probe.Response {
	t.Helper()
	var raw strings.Builder
	for range 5 {
		part, next := s.raw(t, path)
		raw.WriteString(part)
		if next == "" {
			break
		}
		path = next
	}
	r, err := parseRawResponses(packFixtureBase, path, []byte(raw.String()))
	if err != nil {
		t.Fatalf("%s %s: %v", s.dir, path, err)
	}
	return r
}

func runPackOnLabService(t *testing.T, name string) Result {
	t.Helper()
	s := parseLabService(t, filepath.Join(labServicesDir, name))
	sigs := mustPack(t)
	f := &fixtureFetcher{responses: map[string]*probe.Response{"/": s.response(t, "/")}}
	for _, sig := range sigs {
		if _, ok := f.responses[sig.Path]; !ok {
			r, _ := s.raw(t, sig.Path)
			parsed, err := parseRawResponses(packFixtureBase, sig.Path, []byte(r))
			if err != nil {
				t.Fatal(err)
			}
			f.responses[sig.Path] = parsed
		}
	}
	root := f.responses["/"]
	h := &probe.HTTP{
		Scheme:        "http",
		URL:           packFixtureBase,
		StatusCode:    root.StatusCode,
		Title:         root.Title,
		Headers:       root.Headers,
		Cookies:       root.Cookies,
		RedirectChain: root.RedirectChain,
	}
	if fav, err := os.ReadFile(filepath.Join(s.dir, "html", packFaviconFile)); err == nil && len(fav) > 0 {
		sum := sha256.Sum256(fav)
		h.FaviconSHA256 = hex.EncodeToString(sum[:])
		h.FaviconMMH3 = probe.FaviconHash(fav)
	}
	return (&Set{Signatures: sigs}).detect(context.Background(), f, h)
}

func TestPackOnLabServices(t *testing.T) {
	want := map[string]struct{ techs, findings []string }{
		"wp":          {[]string{"WordPress", "nginx"}, []string{"builtin-wordpress"}},
		"drupal":      {[]string{"Drupal", "nginx"}, []string{"builtin-drupal"}},
		"admin":       {[]string{"PHP", "nginx"}, []string{"builtin-admin-login"}},
		"camera":      {[]string{"nginx"}, nil},
		"staging":     {[]string{"nginx"}, nil},
		"changing-v1": {[]string{"nginx"}, nil},
		"changing-v2": {[]string{"nginx"}, nil},
		"flap":        {[]string{"nginx"}, nil},
		"legacy":      {[]string{"nginx"}, nil},
		"newhost":     {[]string{"nginx"}, nil},
		"redirect":    {[]string{"nginx"}, nil},
	}
	confs, err := filepath.Glob(filepath.Join(labServicesDir, "*", "default.conf"))
	if err != nil || len(confs) == 0 {
		t.Fatalf("lab services = %v, %v", confs, err)
	}
	for _, conf := range confs {
		name := filepath.Base(filepath.Dir(conf))
		t.Run(name, func(t *testing.T) {
			w, ok := want[name]
			if !ok {
				t.Fatalf("lab service %s has no expected pack result in this test", name)
			}
			res := runPackOnLabService(t, name)
			techs, findings := resultNames(res)
			if !slices.Equal(techs, w.techs) {
				t.Errorf("technologies = %v, want %v", techs, w.techs)
			}
			if !slices.Equal(findings, w.findings) {
				t.Errorf("findings = %v, want %v (%+v)", findings, w.findings, res.Findings)
			}
			for _, tc := range res.Technologies {
				if tc.Name == "Hikvision" || tc.Name == "Dahua" {
					t.Errorf("technology %s on lab %s", tc.Name, name)
				}
			}
		})
	}
	admin := runPackOnLabService(t, "admin")
	if admin.Findings == nil || !findingKinds(admin)["admin-panel"] {
		t.Errorf("lab admin findings = %+v, want an admin-panel finding", admin.Findings)
	}
	if !slices.ContainsFunc(admin.Technologies, func(tc Technology) bool { return tc.Name == "PHP" && tc.Version == "7.4.3" }) {
		t.Errorf("lab admin technologies = %+v, want PHP 7.4.3", admin.Technologies)
	}
	if wp := runPackOnLabService(t, "wp"); !slices.ContainsFunc(wp.Technologies, func(tc Technology) bool { return tc.Name == "WordPress" && tc.Version == "6.4.2" }) {
		t.Errorf("lab wp technologies = %+v, want WordPress 6.4.2", wp.Technologies)
	}
}
