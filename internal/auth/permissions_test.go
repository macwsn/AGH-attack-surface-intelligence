package auth

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func declaredPermissions(t *testing.T) []Permission {
	t.Helper()
	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var perms []Permission
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			vs, ok := n.(*ast.ValueSpec)
			if !ok || vs.Type == nil {
				return true
			}
			if id, ok := vs.Type.(*ast.Ident); !ok || id.Name != "Permission" {
				return true
			}
			for _, v := range vs.Values {
				if lit, ok := v.(*ast.BasicLit); ok {
					s, err := strconv.Unquote(lit.Value)
					if err != nil {
						t.Fatal(err)
					}
					perms = append(perms, Permission(s))
				}
			}
			return true
		})
	}
	return perms
}

func TestEveryPermissionHasDescription(t *testing.T) {
	declared := declaredPermissions(t)
	if len(declared) < len(AllPermissions) {
		t.Fatalf("found %d declared permissions, AllPermissions has %d", len(declared), len(AllPermissions))
	}
	for _, p := range append(declared, AllPermissions...) {
		d := p.Description()
		if d == "" {
			t.Errorf("permission %q has no description", p)
			continue
		}
		if !strings.HasSuffix(d, ".") || strings.Count(d, ". ") > 0 || strings.ToUpper(d[:1]) != d[:1] {
			t.Errorf("description of %q is not one sentence: %q", p, d)
		}
	}
	if len(PermissionDescriptions) != len(AllPermissions) {
		t.Errorf("%d descriptions for %d permissions", len(PermissionDescriptions), len(AllPermissions))
	}
}
