package diff

import (
	"fmt"
	"maps"
	"testing"
)

const adminerCSP = "script-src 'self' 'unsafe-inline' 'nonce-%s' 'strict-dynamic'; connect-src 'self'; frame-src https://www.adminer.org; object-src 'none'; base-uri 'none'; form-action 'self'"

func TestPerRequestHeaderTokensAreNotAChange(t *testing.T) {
	const addr = "172.30.0.18"
	runs := []map[string]string{
		{
			"content-security-policy": fmt.Sprintf(adminerCSP, "bD9hZmI3NjQ1ZTkxYzM4YQ=="),
			"x-csrf-token":            "4f0c2d7e9a1b3c5d7e9f1a2b3c4d5e6f",
		},
		{
			"content-security-policy": fmt.Sprintf(adminerCSP, "Nzg5YWJjZGVmMDEyMzQ1Ng=="),
			"x-csrf-token":            "a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4",
		},
		{
			"content-security-policy": "default-src 'self'; script-src 'self' 'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='",
			"x-csrf-token":            "a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4",
		},
		{
			"content-security-policy": "default-src 'self'; script-src 'self' 'sha256-RFWPLDbv2BY+rCkDzsE+0fr8ylGr2R2faWMhq4lfEQc='",
			"x-csrf-token":            "a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4",
		},
	}
	pairs := [][2]int{{0, 1}, {2, 3}}
	for _, p := range pairs {
		from, to := webSvc(80, active), webSvc(80, active)
		from.HTTP.Headers = maps.Clone(from.HTTP.Headers)
		to.HTTP.Headers = maps.Clone(to.HTTP.Headers)
		maps.Copy(from.HTTP.Headers, runs[p[0]])
		maps.Copy(to.HTTP.Headers, runs[p[1]])
		d := Compute(export("r1", host(addr, active, from)), export("r2", host(addr, active, to)), Options{})
		for _, c := range d.Changes {
			t.Errorf("runs %d->%d: per-request token produced %s %+v", p[0], p[1], c.Type, c.Fields)
		}
	}

	from, to := webSvc(80, active), webSvc(80, active)
	from.HTTP.Headers = maps.Clone(from.HTTP.Headers)
	to.HTTP.Headers = maps.Clone(to.HTTP.Headers)
	from.HTTP.Headers["content-security-policy"] = fmt.Sprintf(adminerCSP, "bD9hZmI3NjQ1ZTkxYzM4YQ==")
	to.HTTP.Headers["content-security-policy"] = fmt.Sprintf(adminerCSP, "Nzg5YWJjZGVmMDEyMzQ1Ng==") + "; img-src *"
	d := Compute(export("r1", host(addr, active, from)), export("r2", host(addr, active, to)), Options{})
	if len(d.Changes) != 1 || d.Changes[0].Type != ServiceChanged || len(d.Changes[0].Fields) != 1 || d.Changes[0].Fields[0].Field != "http.headers.content-security-policy" {
		t.Errorf("a real CSP change must still be reported, got %+v", d.Changes)
	}
}
