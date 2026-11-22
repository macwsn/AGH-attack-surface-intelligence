package detect

import (
	"regexp"
	"slices"
	"strings"

	"asi/internal/probe"
)

const (
	serviceConfidence = 80
	boundConfidence   = 60
)

type serviceRule struct {
	service, name, category string
	product                 *regexp.Regexp
	emptyProduct            bool
	version                 *regexp.Regexp
}

var (
	mariaDBVersion = regexp.MustCompile(`^(?:5\.5\.5-)?` + versionRe)
	exactVersion   = regexp.MustCompile(`^[0-9]`)
	versionBound   = regexp.MustCompile(`(?i)\bor (?:later|earlier|newer|older)\b|(?:^|\.)[x*](?:\.|\s|$)`)
	serviceRules   = []serviceRule{
		{service: "ftp", product: regexp.MustCompile(`(?i)\bvsftpd\b`), name: "vsftpd", category: "ftp-server"},
		{service: "ftp", product: regexp.MustCompile(`(?i)\bproftpd\b`), name: "ProFTPD", category: "ftp-server"},
		{service: "ftp", product: regexp.MustCompile(`(?i)\bpure-?ftpd\b`), name: "Pure-FTPd", category: "ftp-server"},
		{service: "ssh", product: regexp.MustCompile(`(?i)\bopenssh\b`), name: "OpenSSH", category: "ssh-server"},
		{service: "redis", product: regexp.MustCompile(`(?i)\bredis\b`), emptyProduct: true, name: "Redis", category: "database"},
		{service: "postgresql", product: regexp.MustCompile(`(?i)\bpostgresql\b`), emptyProduct: true, name: "PostgreSQL", category: "database"},
		{service: "mysql", product: regexp.MustCompile(`(?i)\bmariadb\b`), name: "MariaDB", category: "database", version: mariaDBVersion},
		{service: "mysql", product: regexp.MustCompile(`(?i)\bmysql\b`), name: "MySQL", category: "database"},
		{service: "apachemq", product: regexp.MustCompile(`(?i)\bactivemq\b`), name: "ActiveMQ", category: "message-broker"},
		{service: "amqp", product: regexp.MustCompile(`(?i)\brabbitmq\b`), name: "RabbitMQ", category: "message-broker"},
		{service: "amqps", product: regexp.MustCompile(`(?i)\brabbitmq\b`), name: "RabbitMQ", category: "message-broker"},
	}
	coyote         = regexp.MustCompile(`(?i)\bcoyote\b`)
	webServerRules = []serviceRule{
		{product: regexp.MustCompile(`(?i)\bnginx\b`), name: "nginx", category: "web-server"},
		{product: regexp.MustCompile(`(?i)^apache tomcat\b`), name: "Apache Tomcat", category: "application-server"},
		{product: regexp.MustCompile(`(?i)^apache httpd\b`), name: "Apache", category: "web-server"},
	}
)

type Service struct {
	Service, Product, Version string
	HTTP                      *probe.HTTP
	Stated                    bool
	Technologies              []Technology
	Findings                  []Finding
}

func (s *Set) DetectService(svc Service) Result {
	techs := slices.Clone(svc.Technologies)
	findings := slices.Clone(svc.Findings)
	if svc.HTTP != nil {
		res := s.DetectRecorded(svc.HTTP)
		techs = append(techs, res.Technologies...)
		findings = addFindings(findings, res.Findings)
	}
	if !svc.Stated {
		techs = append(techs, ServiceTechnologies(svc.Service, svc.Product, svc.Version)...)
		techs = append(techs, webServerTechnologies(svc.Product, svc.Version)...)
	}
	techs = Merge(techs)
	return Result{Technologies: techs, Findings: MergeFindings(addFindings(findings, Outdated(techs)))}
}

func addFindings(to, from []Finding) []Finding {
	for _, f := range from {
		if !slices.ContainsFunc(to, func(g Finding) bool { return g.SignatureID == f.SignatureID }) {
			to = append(to, f)
		}
	}
	return to
}

func webServerTechnologies(product, version string) []Technology {
	product = strings.TrimSpace(product)
	for _, rule := range webServerRules {
		if rule.product.MatchString(product) {
			v := exact(strings.TrimSpace(version))
			if coyote.MatchString(product) {
				v = ""
			}
			return []Technology{{Name: rule.name, Category: rule.category, Version: v, Confidence: serviceConfidence, Source: SourceBuiltin}}
		}
	}
	return nil
}

func exact(version string) string {
	v, _, _ := strings.Cut(version, " ")
	if !exactVersion.MatchString(v) || strings.Contains(version, " - ") {
		return ""
	}
	return v
}

func ServiceTechnologies(service, product, version string) []Technology {
	service = strings.ToLower(strings.TrimSpace(service))
	product = strings.TrimSpace(product)
	version = strings.TrimSpace(version)
	if service == "mysql" && strings.Contains(strings.ToLower(version), "mariadb") {
		product = "MariaDB"
	}
	for _, rule := range serviceRules {
		if rule.service != service {
			continue
		}
		if product == "" && !rule.emptyProduct || product != "" && !rule.product.MatchString(product) {
			continue
		}
		if versionBound.MatchString(version) {
			return []Technology{{Name: rule.name, Category: rule.category, Confidence: boundConfidence, Source: SourceBuiltin}}
		}
		v := exact(version)
		if rule.version != nil {
			v = ""
			if m := rule.version.FindStringSubmatch(version); m != nil {
				v = m[1]
			}
		}
		return []Technology{{Name: rule.name, Category: rule.category, Version: v, Confidence: serviceConfidence, Source: SourceBuiltin}}
	}
	return nil
}
