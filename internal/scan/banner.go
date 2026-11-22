package scan

import (
	"regexp"
	"strings"

	"asi/internal/scan/nmap"
)

var (
	genericProducts = map[string]bool{"advanced message queue protocol": true}
	bannerServices  = map[string]bool{"ftp": true, "ssh": true, "smtp": true, "pop3": true, "imap": true}
	bannerRules     = []struct {
		service, product string
		re               *regexp.Regexp
	}{
		{"ftp", "vsftpd", regexp.MustCompile(`\(vsFTPd (\d[-.\w]*)\)`)},
		{"ftp", "ProFTPD", regexp.MustCompile(`ProFTPD(?: (\d[.\w]*))?`)},
		{"ftp", "Pure-FTPd", regexp.MustCompile(`Pure-FTPd()`)},
		{"ssh", "OpenSSH", regexp.MustCompile(`^SSH-[\d.]+-OpenSSH_(\w[.\w]*)`)},
		{"smtp", "Postfix smtpd", regexp.MustCompile(`ESMTP Postfix()`)},
		{"smtp", "Exim smtpd", regexp.MustCompile(`ESMTP Exim(?: (\d[.\w]*))?`)},
		{"pop3", "Dovecot pop3d", regexp.MustCompile(`Dovecot()`)},
		{"imap", "Dovecot imapd", regexp.MustCompile(`Dovecot()`)},
		{"amqp", "RabbitMQ", regexp.MustCompile(`RabbitMQ(?: v?(\d[.\w]*))?`)},
	}
)

func identify(p nmap.Port) (product, version string) {
	product, version = p.Product, p.Version
	if genericProducts[strings.ToLower(product)] {
		product = ""
	}
	if product != "" {
		return product, version
	}
	if p.ScriptProduct != "" {
		return p.ScriptProduct, p.ScriptVersion
	}
	for _, rule := range bannerRules {
		if rule.service != strings.ToLower(p.Service) {
			continue
		}
		for _, text := range []string{p.Banner, p.ExtraInfo} {
			if m := rule.re.FindStringSubmatch(text); m != nil {
				if m[1] != "" {
					version = m[1]
				}
				return rule.product, version
			}
		}
	}
	return product, version
}

func needsStandard(p nmap.Port) bool {
	if product, _ := identify(p); product != "" {
		return false
	}
	return genericProducts[strings.ToLower(p.Product)] || bannerServices[strings.ToLower(p.Service)]
}
