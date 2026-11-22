//go:build integration

package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"asi/internal/auth"
	"asi/internal/inventory"
	"asi/internal/probe"
)

const (
	scriptPayload    = `<script>alert(1)</script>`
	attributePayload = `"><script>alert(2)</script><a x="`
	quotePayload     = `' onmouseover='alert(3)`
)

var rawPayloads = []string{"<script>alert(", `"><script`, `' onmouseover='alert(3)`, `onmouseover='alert`}

// REQ-WEB-024
func TestAllOutputIsEscaped(t *testing.T) {
	const host = "10.6.0.1"
	site := newInventorySite(t, func(ctx context.Context, inv *inventory.Inventory) {
		run, err := inv.CreateRun(ctx, inventory.RunSpec{Name: "x1"})
		if err != nil {
			t.Fatal(err)
		}
		svc := inventory.ServiceResult{Port: 443, Protocol: "tcp", State: "open", Service: "http", Product: attributePayload,
			HTTP: &probe.HTTP{Scheme: "https", URL: "https://10.6.0.1/" + quotePayload, StatusCode: 200, Title: scriptPayload,
				Headers:       map[string]string{"x-evil": attributePayload, "server": scriptPayload},
				Cookies:       []probe.Cookie{{Name: quotePayload}},
				RedirectChain: []string{"https://10.6.0.1/" + scriptPayload},
				TLS:           &probe.TLS{SubjectCN: scriptPayload, IssuerCN: attributePayload, SelfSigned: true}},
			Technologies: []inventory.Technology{{Name: scriptPayload, Version: attributePayload, Confidence: 90, Source: quotePayload}},
			Findings: []inventory.Finding{{SignatureID: "admin-panel-sig", Kind: "admin-panel", Name: scriptPayload,
				Version: quotePayload, Confidence: 80, Evidence: attributePayload}},
		}
		if err := inv.RecordGroup(ctx, run.ID, inventory.GroupResult{Index: 0, Hosts: []inventory.HostResult{
			{Address: host, Hostnames: []string{"evil.example"}, Services: []inventory.ServiceResult{svc}}}}); err != nil {
			t.Fatal(err)
		}
		if err := inv.UpdateHostUserFields(ctx, host, inventory.HostUserFields{Tags: []string{scriptPayload, quotePayload},
			Notes: scriptPayload + attributePayload, DisplayName: attributePayload, Owner: quotePayload,
			Criticality: scriptPayload, StatusOverride: ""}); err != nil {
			t.Fatal(err)
		}
	})

	pages := map[string]string{
		"dashboard":            "/",
		"hosts":                "/hosts/",
		"hosts, query payload": "/hosts/?q=" + url.QueryEscape(scriptPayload),
		"hosts, attr payload":  "/hosts/?q=" + url.QueryEscape(attributePayload) + "&tag=" + url.QueryEscape(quotePayload),
		"hosts, tag filter":    "/hosts/?tag=" + url.QueryEscape(scriptPayload),
		"host page":            "/hosts/" + host,
		"404 with payload":     "/hosts/" + url.PathEscape(scriptPayload),
	}
	for _, role := range []string{auth.RoleViewer, auth.RoleOperator} {
		for name, path := range pages {
			resp, body := get(t, site.clients[role], site.url+path)
			if resp.StatusCode >= 500 {
				t.Errorf("%s %s = %d", role, name, resp.StatusCode)
			}
			for _, raw := range rawPayloads {
				if strings.Contains(body, raw) {
					i := strings.Index(body, raw)
					t.Errorf("%s %s contains the unescaped %q: …%s…", role, name, raw, body[max(0, i-80):min(len(body), i+80)])
				}
			}
			checkPageIsSafe(t, role+" "+name, body)
		}
	}

	_, page := get(t, site.clients[auth.RoleOperator], site.url+"/hosts/"+host)
	for _, want := range []string{"&lt;script&gt;alert(1)&lt;/script&gt;", "&#34;&gt;&lt;script&gt;alert(2)&lt;/script&gt;",
		"&#39; onmouseover=&#39;alert(3)"} {
		if !strings.Contains(page, want) {
			t.Errorf("host page lacks the escaped payload %q, so the test does not prove the data was rendered", want)
		}
	}
	_, list := get(t, site.clients[auth.RoleViewer], site.url+"/hosts/?tag="+url.QueryEscape(scriptPayload))
	if got := listedHosts(list); strings.Join(got, " ") != host {
		t.Errorf("tag filter with the payload = %v, want the host", got)
	}
	_, dash := get(t, site.clients[auth.RoleViewer], site.url+"/")
	if !strings.Contains(dash, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Errorf("dashboard does not render the payload finding name, so the test does not cover it")
	}

	form := editForm()
	form.Set("notes", scriptPayload)
	form.Set("owner", strings.Repeat("o", 201)+attributePayload)
	rec := postForm(site.handler, "/hosts/"+host, form, site.cookies[auth.RoleOperator], site.csrf[auth.RoleOperator])
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid form = %d, want 422", rec.Code)
	}
	for _, raw := range rawPayloads {
		if strings.Contains(rec.Body.String(), raw) {
			t.Errorf("re-rendered form contains the unescaped %q", raw)
		}
	}
}
