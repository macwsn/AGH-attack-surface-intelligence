package detect

import (
	"embed"
	"fmt"
	"io/fs"
	"strings"
)

const PackIDPrefix = "builtin-"

//go:embed pack/*.yaml
var packFS embed.FS

func Pack() ([]Signature, error) {
	return loadPack(packFS)
}

func loadPack(fsys fs.FS) ([]Signature, error) {
	files, err := fs.Glob(fsys, "pack/*.yaml")
	if err != nil {
		return nil, fmt.Errorf("list built-in signatures: %w", err)
	}
	var all []Signature
	seen := map[string]string{}
	for _, f := range files {
		data, err := fs.ReadFile(fsys, f)
		if err != nil {
			return nil, fmt.Errorf("read built-in signatures: %w", err)
		}
		sigs, err := Parse(data)
		if err != nil {
			return nil, fmt.Errorf("built-in %s: %w", f, err)
		}
		for _, s := range sigs {
			if !strings.HasPrefix(s.ID, PackIDPrefix) {
				return nil, fmt.Errorf("built-in %s: %w", f, &RuleError{ID: s.ID, Rule: RuleSchema, Detail: "built-in signature ids start with " + PackIDPrefix})
			}
			if prev, ok := seen[s.ID]; ok {
				return nil, fmt.Errorf("built-in %s: %w", f, &RuleError{ID: s.ID, Rule: RuleDuplicateID, Detail: "already defined in " + prev})
			}
			seen[s.ID] = f
		}
		all = append(all, sigs...)
	}
	if err := checkExtraRequests(all); err != nil {
		return nil, fmt.Errorf("built-in signatures: %w", err)
	}
	for i := range all {
		all[i].builtin = true
	}
	return all, nil
}
