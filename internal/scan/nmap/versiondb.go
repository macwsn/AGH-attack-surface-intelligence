package nmap

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

const serviceProbesFile = "nmap-service-probes"

func WriteLightProbes(dst io.Writer, src io.Reader) error {
	w := bufio.NewWriter(dst)
	sc := bufio.NewScanner(src)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	var soft []string
	flush := func() {
		for _, l := range soft {
			fmt.Fprintln(w, l)
		}
		soft = soft[:0]
	}
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "Probe "):
			flush()
			fmt.Fprintln(w, line)
		case strings.HasPrefix(line, "softmatch ") && !strings.HasPrefix(line, "softmatch ssl "):
			soft = append(soft, "match "+strings.TrimPrefix(line, "softmatch "))
		default:
			fmt.Fprintln(w, line)
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("read service probes: %w", err)
	}
	flush()
	return w.Flush()
}

func (r ExecRunner) serviceProbes() string {
	var dirs []string
	if d := os.Getenv("NMAPDIR"); d != "" {
		dirs = append(dirs, d)
	}
	path := r.Path
	if path == "" {
		path = "nmap"
	}
	if bin, err := exec.LookPath(path); err == nil {
		if real, err := filepath.EvalSymlinks(bin); err == nil {
			bin = real
		}
		dir := filepath.Dir(bin)
		dirs = append(dirs, filepath.Join(dir, "..", "share", "nmap"), dir)
	}
	for _, d := range dirs {
		p, err := filepath.Abs(filepath.Join(d, serviceProbesFile))
		if err != nil {
			continue
		}
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			return p
		}
	}
	return ""
}

func (r ExecRunner) LightProbes() (path string, cleanup func(), err error) {
	src := r.serviceProbes()
	if src == "" {
		return "", nil, fmt.Errorf("%s not found", serviceProbesFile)
	}
	in, err := os.Open(src)
	if err != nil {
		return "", nil, err
	}
	defer in.Close()
	out, err := os.CreateTemp("", "asi-"+serviceProbesFile+"-*")
	if err != nil {
		return "", nil, err
	}
	cleanup = func() { os.Remove(out.Name()) }
	if err := WriteLightProbes(out, in); err != nil {
		out.Close()
		cleanup()
		return "", nil, err
	}
	if err := out.Close(); err != nil {
		cleanup()
		return "", nil, err
	}
	if path, err = filepath.Abs(out.Name()); err != nil {
		cleanup()
		return "", nil, err
	}
	return path, cleanup, nil
}

type softMatch struct {
	service       string
	product       *regexp.Regexp
	version, info bool
}

var templateVar = regexp.MustCompile(`\$[0-9]+|\$[A-Z]\w*\([^)]*\)`)

func parseSoftMatches(src io.Reader) ([]softMatch, error) {
	sc := bufio.NewScanner(src)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	var out []softMatch
	for sc.Scan() {
		rest, ok := strings.CutPrefix(sc.Text(), "softmatch ")
		if !ok {
			continue
		}
		service, rest, _ := strings.Cut(rest, " ")
		if service == "ssl" || len(rest) < 2 || rest[0] != 'm' {
			continue
		}
		end := strings.IndexByte(rest[2:], rest[1])
		if end < 0 {
			continue
		}
		m := softMatch{service: service}
		product := ""
		for _, field := range templateFields(strings.TrimLeft(rest[end+3:], "is")) {
			switch field[0] {
			case 'p':
				product = field[2 : len(field)-1]
			case 'v':
				m.version = true
			case 'i':
				m.info = true
			}
		}
		var pat strings.Builder
		last := 0
		for _, loc := range templateVar.FindAllStringIndex(product, -1) {
			pat.WriteString(regexp.QuoteMeta(product[last:loc[0]]) + ".*")
			last = loc[1]
		}
		pat.WriteString(regexp.QuoteMeta(product[last:]))
		re, err := regexp.Compile("^" + pat.String() + "$")
		if err != nil {
			continue
		}
		m.product = re
		out = append(out, m)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read service probes: %w", err)
	}
	return out, nil
}

func templateFields(s string) []string {
	var out []string
	for s = strings.TrimSpace(s); len(s) > 2; s = strings.TrimSpace(s) {
		if strings.HasPrefix(s, "cpe:") {
			s = s[3:]
		}
		if len(s) < 3 {
			break
		}
		end := strings.IndexByte(s[2:], s[1])
		if end < 0 {
			break
		}
		out = append(out, s[:end+3])
		s = strings.TrimLeft(s[end+3:], "a")
	}
	return out
}

func (m softMatch) matches(p Port) bool {
	return p.Service == m.service && m.product.MatchString(p.Product) && (m.version || p.Version == "") && (m.info || p.ExtraInfo == "")
}

func MarkSoft(hosts []Host, src io.Reader) error {
	soft, err := parseSoftMatches(src)
	if err != nil {
		return err
	}
	for i := range hosts {
		for j := range hosts[i].Ports {
			p := &hosts[i].Ports[j]
			if p.State != "open" || p.Guessed {
				continue
			}
			for _, m := range soft {
				if m.matches(*p) {
					p.Soft = true
					break
				}
			}
		}
	}
	return nil
}

func (r ExecRunner) markSoft(hosts []Host) {
	src := r.serviceProbes()
	if src == "" {
		return
	}
	in, err := os.Open(src)
	if err != nil {
		return
	}
	defer in.Close()
	MarkSoft(hosts, in)
}
