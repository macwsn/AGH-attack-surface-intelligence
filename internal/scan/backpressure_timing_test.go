package scan_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// REQ-SCAN-007
func TestSlowStoreBlocksWorkersDoesNotDependOnWallClock(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "scale_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var body *ast.BlockStmt
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == "TestSlowStoreBlocksWorkers" {
			body = fn.Body
		}
	}
	if body == nil {
		t.Fatal("TestSlowStoreBlocksWorkers not found in scale_test.go")
	}
	var problems []string
	scanners, withTransport := 0, 0
	ast.Inspect(body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CallExpr:
			switch fun := n.Fun.(type) {
			case *ast.Ident:
				if fun.Name == "waitFor" {
					problems = append(problems, "polls with waitFor and its 5 s wall-clock deadline")
				}
			case *ast.SelectorExpr:
				if x, ok := fun.X.(*ast.Ident); ok && x.Name == "time" && (fun.Sel.Name == "Sleep" || fun.Sel.Name == "After") {
					problems = append(problems, "waits with time."+fun.Sel.Name)
				}
			}
		case *ast.CompositeLit:
			if sel, ok := n.Type.(*ast.SelectorExpr); ok && sel.Sel.Name == "Scanner" {
				scanners++
				for _, e := range n.Elts {
					if kv, ok := e.(*ast.KeyValueExpr); ok {
						if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "Transport" {
							withTransport++
						}
					}
				}
			}
		}
		return true
	})
	if scanners > withTransport {
		problems = append(problems, "builds a scan.Scanner without a Transport, so HTTP probes dial real addresses with a 10 s timeout")
	}
	if len(problems) > 0 {
		t.Fatalf("TestSlowStoreBlocksWorkers depends on wall-clock timing: %s", strings.Join(problems, "; "))
	}
}
