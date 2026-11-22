package web

import (
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"asi/internal/auth"
	"asi/internal/detect"
)

func guidedValues(conds ...detect.Condition) url.Values {
	v := url.Values{auth.CSRFFormField: {"csrf-alice"}, "mode": {"form"}, "f_name": {"Nginx"}, "f_kind": {"technology"},
		"f_confidence": {"80"}, "f_group": {"all"}, "address": {"10.0.0.5"}, "port": {"80"}, "protocol": {"tcp"}}
	for _, c := range conds {
		v.Add("c_matcher", c.Matcher)
		v.Add("c_name", c.Name)
		v.Add("c_value", c.Value)
	}
	return v
}

var conditionRE = regexp.MustCompile(`<div class="condition">`)

func generatedYAML(t *testing.T, page string) string {
	t.Helper()
	m := regexp.MustCompile(`(?s)<div class="body" id="signature-yaml">.*?<textarea form="signature" name="source" rows="16" readonly>(.*?)</textarea>`).FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("page has no generated YAML:\n%s", page)
	}
	return html.UnescapeString(m[1])
}

// REQ-SIGNATURES-023
func TestSignatureFormRendersGuidedForm(t *testing.T) {
	r, fa := newTestRouter(t)
	rec := do(r, http.MethodGet, "/signatures/new", nil, fa.session(t, "alice"))
	page := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /signatures/new = %d", rec.Code)
	}
	for _, want := range []string{
		`<a href="/signatures/new" aria-current="page">Form</a>`, `<a href="/signatures/new?view=yaml">Edit as YAML</a>`,
		`hx-post="/signatures/form" hx-trigger="change" hx-target="#signature-yaml"`,
		`<select name="c_matcher"><option selected>header</option><option>cookie</option><option>title</option><option>body</option><option>status</option><option>favicon</option></select>`,
		`name="add" value="1" formaction="/signatures/form"`, `name="remove" value="0" formaction="/signatures/form"`,
		`formaction="/signatures/test"`, "Test against stored data", `formaction="/signatures/hunt"`, "Hunt in history",
		`name="f_version"`, `name="f_path"`, `<option value="any">Any condition is enough</option>`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("new signature page lacks %q", want)
		}
	}
	kinds := regexp.MustCompile(`(?s)<select name="f_kind">(.*?)</select>`).FindStringSubmatch(page)
	if kinds == nil {
		t.Fatal("no kind select")
	}
	var got []string
	for _, m := range regexp.MustCompile(`<option[^>]*>([^<]*)</option>`).FindAllStringSubmatch(kinds[1], -1) {
		got = append(got, m[1])
	}
	if strings.Join(got, ",") != strings.Join(detect.Kinds, ",") {
		t.Errorf("kind options = %v, want %v", got, detect.Kinds)
	}
	if regexp.MustCompile(`style\s*=`).MatchString(page) || regexp.MustCompile(`<script>|<script [^s]|\son[a-z]+=`).MatchString(page) {
		t.Error("signature form has inline styles or scripts")
	}
	yaml := do(r, http.MethodGet, "/signatures/new?view=yaml", nil, fa.session(t, "alice")).Body.String()
	if !strings.Contains(yaml, `<textarea name="source" rows="16" required>`) || strings.Contains(yaml, `name="mode"`) ||
		!strings.Contains(yaml, `aria-current="page">Edit as YAML</a>`) {
		t.Error("the YAML tab does not show the raw editor")
	}
}

// REQ-SIGNATURES-023
func TestSignatureFormAddAndRemoveCondition(t *testing.T) {
	r, fa := newTestRouter(t)
	alice := fa.session(t, "alice")
	v := guidedValues(detect.Condition{Matcher: "header", Name: "Server", Value: "nginx"})
	v.Set("add", "1")
	rec := do(r, http.MethodPost, "/signatures/form", v, alice)
	page := rec.Body.String()
	if rec.Code != http.StatusOK || len(conditionRE.FindAllString(page, -1)) != 2 {
		t.Fatalf("add condition = %d with %d conditions", rec.Code, len(conditionRE.FindAllString(page, -1)))
	}
	if !strings.Contains(page, `name="c_value" value="nginx"`) || !strings.Contains(page, `name="f_name" value="Nginx"`) {
		t.Error("adding a condition lost the entered values")
	}

	v = guidedValues(detect.Condition{Matcher: "header", Name: "Server", Value: "nginx"}, detect.Condition{Matcher: "status", Value: "200"})
	v.Set("remove", "0")
	page = do(r, http.MethodPost, "/signatures/form", v, alice).Body.String()
	if n := len(conditionRE.FindAllString(page, -1)); n != 1 || strings.Contains(page, `value="nginx"`) {
		t.Fatalf("remove left %d conditions", n)
	}
	sig, err := detect.ParseOne([]byte(generatedYAML(t, page)))
	if err != nil || len(sig.All) != 1 || sig.All[0].Type != "status" || sig.All[0].Value != "200" {
		t.Fatalf("generated YAML after remove parses to %+v, %v", sig, err)
	}

	v = guidedValues(detect.Condition{Matcher: "title", Value: "(?i)grafana"})
	v.Set("view", "yaml")
	page = do(r, http.MethodPost, "/signatures/form", v, alice).Body.String()
	src := regexp.MustCompile(`(?s)<textarea name="source" rows="16" required>(.*?)</textarea>`).FindStringSubmatch(page)
	if src == nil || !strings.Contains(html.UnescapeString(src[1]), "type: title_regex") {
		t.Fatalf("Edit this YAML does not open the generated YAML in the YAML tab:\n%s", page)
	}
}

// REQ-SIGNATURES-025
func TestSignatureFormShowsRuleNextToField(t *testing.T) {
	r, fa := newTestRouter(t)
	alice := fa.session(t, "alice")
	ok := detect.Condition{Matcher: "status", Value: "200"}
	for name, tc := range map[string]struct {
		values url.Values
		label  string
		id     string
		text   string
	}{
		"invalid regex": {guidedValues(ok, detect.Condition{Matcher: "body", Value: "(["}), "Value", "problem-condition-1", detect.RuleRegex},
		"bad favicon":   {guidedValues(detect.Condition{Matcher: "favicon", Value: "abc"}), "Value", "problem-condition-0", "favicon_mmh3"},
		"bad status":    {guidedValues(detect.Condition{Matcher: "status", Value: "ok"}), "Value", "problem-condition-0", "status value"},
		"unsafe path":   {with(guidedValues(ok), "f_path", "/login?next=/"), "Request path", "problem-request", detect.RulePath},
		"missing name":  {with(guidedValues(ok), "f_name", " "), "Name", "problem-name", "name is required"},
		"bad version":   {with(with(guidedValues(ok), "f_version_from", "title"), "f_version", "v("), "Version pattern", "problem-version", detect.RuleRegex},
	} {
		for _, action := range []string{"/signatures/test", "/signatures/hunt"} {
			rec := do(r, http.MethodPost, action, tc.values, alice)
			page := rec.Body.String()
			if rec.Code != http.StatusUnprocessableEntity {
				t.Errorf("%s %s = %d, want 422", name, action, rec.Code)
				continue
			}
			field := regexp.MustCompile(`<label class="field[^"]*"><span>` + regexp.QuoteMeta(tc.label) +
				`</span>(?:<input|<select)[^>]*aria-invalid="true" aria-describedby="` + tc.id + `"[^>]*>(?:<span class="hint">[^<]*</span>)?<span class="problem" id="` + tc.id + `">([^<]*)</span></label>`).FindStringSubmatch(page)
			if field == nil || !strings.Contains(html.UnescapeString(field[1]), tc.text) {
				t.Errorf("%s %s: the problem %q is not in the %s field:\n%s", name, action, tc.text, tc.label, page)
			}
			if n := strings.Count(page, `class="problem"`); n != 1 {
				t.Errorf("%s %s: %d field problems, want 1", name, action, n)
			}
		}
	}
}

func with(v url.Values, key, value string) url.Values {
	v.Set(key, value)
	return v
}
