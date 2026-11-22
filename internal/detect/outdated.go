package detect

import (
	_ "embed"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

const KindOutdated = "outdated"

//go:embed outdated.yaml
var outdatedYAML []byte

type OutdatedEntry struct {
	Name    string `yaml:"name"`
	Minimum string `yaml:"minimum"`
	Latest  string `yaml:"latest"`
	Checked string `yaml:"checked"`
}

var (
	leadingVersion = regexp.MustCompile(`^` + versionRe)
	nonAlnum       = regexp.MustCompile(`[^a-z0-9]+`)
	checkedDate    = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
	outdatedTable  = sync.OnceValues(func() ([]OutdatedEntry, error) { return ParseOutdated(outdatedYAML) })
)

func ParseOutdated(data []byte) ([]OutdatedEntry, error) {
	var entries []OutdatedEntry
	if err := yaml.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("outdated table: %w", err)
	}
	seen := map[string]bool{}
	for _, e := range entries {
		key := strings.ToLower(e.Name)
		if e.Name == "" || seen[key] {
			return nil, fmt.Errorf("outdated table: entry %q: name is empty or repeated", e.Name)
		}
		seen[key] = true
		if numericVersion(e.Minimum) == nil || numericVersion(e.Latest) == nil {
			return nil, fmt.Errorf("outdated table: entry %q: minimum and latest must be numeric versions", e.Name)
		}
		if compareVersions(numericVersion(e.Latest), numericVersion(e.Minimum)) < 0 {
			return nil, fmt.Errorf("outdated table: entry %q: latest is lower than minimum", e.Name)
		}
		if !checkedDate.MatchString(e.Checked) {
			return nil, fmt.Errorf("outdated table: entry %q: checked must be the date the minimum was checked (YYYY-MM-DD)", e.Name)
		}
	}
	return entries, nil
}

func Outdated(techs []Technology) []Finding {
	table, err := outdatedTable()
	if err != nil {
		return nil
	}
	var out []Finding
	seen := map[string]bool{}
	for _, t := range techs {
		v := numericVersion(t.Version)
		if v == nil {
			continue
		}
		for _, e := range table {
			minimum := numericVersion(e.Minimum)
			if !strings.EqualFold(e.Name, t.Name) || compareVersions(v, minimum[:min(len(v), len(minimum))]) >= 0 {
				continue
			}
			id := "outdated-" + strings.Trim(nonAlnum.ReplaceAllString(strings.ToLower(e.Name), "-"), "-")
			if seen[id] {
				break
			}
			seen[id] = true
			out = append(out, Finding{
				SignatureID: id,
				Kind:        KindOutdated,
				Name:        "Outdated " + e.Name,
				Version:     t.Version,
				Confidence:  t.Confidence,
				Evidence:    evidence(fmt.Sprintf("%s %s is older than the minimum supported version %s (support table checked %s)", e.Name, t.Version, e.Minimum, e.Checked)),
			})
			break
		}
	}
	return out
}

func IsOutdated(name, version string) bool {
	return len(Outdated([]Technology{{Name: strings.TrimSpace(name), Version: version}})) > 0
}

func numericVersion(s string) []int {
	m := leadingVersion.FindString(strings.TrimSpace(s))
	if m == "" {
		return nil
	}
	parts := strings.Split(m, ".")
	out := make([]int, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil
		}
		out[i] = n
	}
	return out
}

func compareVersions(a, b []int) int {
	for i := range max(len(a), len(b)) {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}
