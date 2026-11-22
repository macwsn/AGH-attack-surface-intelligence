package detect

import (
	"errors"
	"strings"
	"testing"
)

func formWith(conds ...Condition) Form {
	return Form{Name: "Nginx Server", Kind: "technology", Confidence: "80", Conditions: conds}
}

// REQ-SIGNATURES-023
func TestFormYAMLRoundTripPerMatcher(t *testing.T) {
	sha := strings.Repeat("aB", 32)
	for name, tc := range map[string]struct {
		cond Condition
		want Matcher
	}{
		"header":         {Condition{"header", "Server", "nginx/([0-9.]+)"}, Matcher{Type: "header", Name: "server", Value: "nginx/([0-9.]+)"}},
		"cookie":         {Condition{"cookie", "^JSESSIONID$", ""}, Matcher{Type: "cookie", Name: "^JSESSIONID$"}},
		"title":          {Condition{"title", "", "(?i)welcome to nginx"}, Matcher{Type: "title_regex", Value: "(?i)welcome to nginx"}},
		"body":           {Condition{"body", "", "<h1>nginx</h1>"}, Matcher{Type: "body_regex", Value: "<h1>nginx</h1>"}},
		"status":         {Condition{"status", "", " 200 "}, Matcher{Type: "status", Value: "200"}},
		"favicon sha256": {Condition{"favicon", "", sha}, Matcher{Type: "favicon_sha256", Value: strings.ToLower(sha)}},
		"favicon mmh3":   {Condition{"favicon", "", "-1234567"}, Matcher{Type: "favicon_mmh3", Value: "-1234567"}},
	} {
		for _, anyOf := range []bool{false, true} {
			f := formWith(tc.cond)
			f.Any = anyOf
			src, err := f.YAML()
			if err != nil {
				t.Fatal(err)
			}
			sig, err := ParseOne(src)
			if err != nil {
				t.Fatalf("%s: ParseOne(%s) = %v", name, src, err)
			}
			got := sig.All
			if anyOf {
				got = sig.Any
			}
			if sig.ID != "nginx-server" || sig.Name != "Nginx Server" || sig.Kind != "technology" || sig.Confidence != 80 ||
				len(got) != 1 || !sameMatcher(got[0], tc.want) {
				t.Errorf("%s any=%v: parsed %+v from\n%s", name, anyOf, sig, src)
			}
			back, ok := FormOf(src)
			if !ok {
				t.Errorf("%s: the form cannot represent its own YAML:\n%s", name, src)
			}
			again, _ := back.YAML()
			if string(again) != string(src) {
				t.Errorf("%s: YAML changed after a round trip:\n%s\nvs\n%s", name, src, again)
			}
		}
	}
}

// REQ-SIGNATURES-023
func TestFormYAMLFullSignature(t *testing.T) {
	f := Form{ID: "nginx-status", Name: "Nginx", Kind: "technology", Category: "web-server", Confidence: "90", Any: true,
		Conditions:  []Condition{{"header", "Server", "nginx"}, {"status", "", "200"}},
		VersionFrom: "header", VersionName: "Server", Version: `nginx/([0-9.]+)`, Path: "/status"}
	src, err := f.YAML()
	if err != nil {
		t.Fatal(err)
	}
	want := `- id: nginx-status
  name: Nginx
  kind: technology
  category: web-server
  confidence: 90
  request:
    path: /status
  match:
    any:
      - type: header
        name: Server
        value: nginx
      - type: status
        value: "200"
  version:
    type: header
    name: Server
    value: nginx/([0-9.]+)
    group: 1
`
	if string(src) != want {
		t.Fatalf("YAML =\n%s\nwant\n%s", src, want)
	}
	sig, err := ParseOne(src)
	if err != nil {
		t.Fatal(err)
	}
	if sig.Path != "/status" || sig.Method != "GET" || len(sig.Any) != 2 || sig.Version == nil || sig.Version.Group != 1 || sig.Category != "web-server" {
		t.Fatalf("parsed %+v", sig)
	}
	if back, ok := FormOf(src); !ok || back.Path != "/status" || back.VersionFrom != "header" || !back.Any || len(back.Conditions) != 2 {
		t.Fatalf("FormOf = %+v, %v", back, ok)
	}
}

// REQ-SIGNATURES-024
func TestFormOfRejectsWhatItCannotShow(t *testing.T) {
	base := "- id: x\n  name: X\n  kind: custom\n  confidence: 50\n"
	for name, src := range map[string]string{
		"all and any":     base + "  match:\n    all: [{type: status, value: 200}]\n    any: [{type: title_regex, value: a}]\n",
		"HEAD":            base + "  request: {method: HEAD}\n  match:\n    all: [{type: status, value: 200}]\n",
		"cookie value":    base + "  match:\n    all: [{type: cookie, name: sid, value: x}]\n",
		"condition group": base + "  match:\n    all: [{type: title_regex, value: 'a(b)', group: 1}]\n",
		"version group 0": base + "  match:\n    all: [{type: status, value: 200}]\n  version: {type: title_regex, value: 'v(1)', group: 0}\n",
		"invalid":         base + "  match: {}\n",
		"two signatures":  base + "  match:\n    all: [{type: status, value: 200}]\n" + strings.ReplaceAll(base, "id: x", "id: y"),
	} {
		if _, ok := FormOf([]byte(src)); ok {
			t.Errorf("%s: FormOf accepted\n%s", name, src)
		}
	}
	explicitGET := base + "  request: {method: GET, path: /}\n  match:\n    all: [{type: status, value: 200}]\n"
	if f, ok := FormOf([]byte(explicitGET)); !ok || f.Path != "" {
		t.Errorf("an explicit GET / is representable: %+v %v", f, ok)
	}
}

// REQ-SIGNATURES-025
func TestRuleErrorNamesTheField(t *testing.T) {
	ok := Condition{"status", "", "200"}
	for name, tc := range map[string]struct {
		form  Form
		field string
		rule  string
	}{
		"missing name":   {Form{ID: "x", Kind: "custom", Confidence: "50", Conditions: []Condition{ok}}, FieldName, RuleSchema},
		"bad id":         {Form{ID: "X Y", Name: "x", Kind: "custom", Confidence: "50", Conditions: []Condition{ok}}, FieldID, RuleSchema},
		"bad kind":       {Form{Name: "x", Kind: "nope", Confidence: "50", Conditions: []Condition{ok}}, FieldKind, RuleSchema},
		"bad confidence": {Form{Name: "x", Kind: "custom", Confidence: "x", Conditions: []Condition{ok}}, FieldConfidence, RuleSchema},
		"unsafe path":    {Form{Name: "x", Kind: "custom", Confidence: "50", Conditions: []Condition{ok}, Path: "/a?b=1"}, FieldRequest, RulePath},
		"no condition":   {Form{Name: "x", Kind: "custom", Confidence: "50"}, FieldMatch, RuleSchema},
		"invalid regex":  {formWith(ok, Condition{"title", "", "("}), ConditionField("all", 1), RuleRegex},
		"bad status":     {formWith(Condition{"status", "", "ok"}), ConditionField("all", 0), RuleSchema},
		"bad favicon":    {formWith(Condition{"favicon", "", "abc"}), ConditionField("all", 0), RuleSchema},
		"header no name": {formWith(Condition{"header", "", "x"}), ConditionField("all", 0), RuleSchema},
		"any group":      {Form{Name: "x", Kind: "custom", Confidence: "50", Any: true, Conditions: []Condition{ok, {"body", "", "["}}}, ConditionField("any", 1), RuleRegex},
		"version regex":  {Form{Name: "x", Kind: "custom", Confidence: "50", Conditions: []Condition{ok}, VersionFrom: "title", Version: "("}, FieldVersion, RuleRegex},
		"version source": {Form{Name: "x", Kind: "custom", Confidence: "50", Conditions: []Condition{ok}, VersionFrom: "status", Version: "1"}, FieldVersion, RuleSchema},
	} {
		src, err := tc.form.YAML()
		if err != nil {
			t.Fatal(err)
		}
		_, err = ParseOne(src)
		var re *RuleError
		if !errors.As(err, &re) || re.Field != tc.field || re.Rule != tc.rule {
			t.Errorf("%s: err = %#v, want field %q rule %q", name, err, tc.field, tc.rule)
		}
	}
}
