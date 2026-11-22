package defectdojo

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func choicesService(t *testing.T, st Settings, answer func(r *http.Request) (int, string)) (*Service, *[]*http.Request) {
	t.Helper()
	var seen []*http.Request
	doer := doerFunc(func(r *http.Request) (*http.Response, error) {
		seen = append(seen, r)
		status, body := answer(r)
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
	})
	return &Service{Store: &memStore{s: st}, HTTP: doer}, &seen
}

func TestChoicesListProductsAndEngagementsWithGET(t *testing.T) {
	st := Settings{BaseURL: "https://dojo.example/sub", Token: testToken, ProductID: 2, EngagementID: 3}
	svc, seen := choicesService(t, st, func(r *http.Request) (int, string) {
		q := r.URL.Query()
		switch {
		case r.URL.Path == "/sub/api/v2/products/" && q.Get("offset") == "0":
			return 200, `{"count": 3, "results": [{"id": 7, "name": "web"}, {"id": 2, "name": "AGH network"}]}`
		case r.URL.Path == "/sub/api/v2/products/" && q.Get("offset") == "2":
			return 200, `{"count": 3, "results": [{"id": 9, "name": "Lab"}]}`
		case r.URL.Path == "/sub/api/v2/engagements/" && q.Get("product") == "7":
			return 200, `{"count": 1, "results": [{"id": 11, "name": "Weekly", "product": 7}]}`
		}
		return 404, `{"detail": "Not found."}`
	})
	ch, err := svc.Choices(context.Background(), 7)
	if err != nil {
		t.Fatalf("Choices: %v", err)
	}
	if got := fmt.Sprint(ch.Products); got != "[{2 AGH network} {9 Lab} {7 web}]" {
		t.Errorf("products = %s", got)
	}
	if got := fmt.Sprint(ch.Engagements); got != "[{11 Weekly}]" {
		t.Errorf("engagements = %s", got)
	}
	if len(*seen) != 3 {
		t.Fatalf("%d requests, want 3", len(*seen))
	}
	for _, r := range *seen {
		if r.Method != http.MethodGet || r.URL.Scheme != "https" || r.URL.Host != "dojo.example" || !strings.HasPrefix(r.URL.Path, "/sub/api/v2/") ||
			r.Header.Get("Authorization") != "Token "+testToken || r.URL.Query().Get("limit") == "" {
			t.Errorf("request %s %s auth %q: want GET to the configured base URL with the token", r.Method, r.URL, r.Header.Get("Authorization"))
		}
	}
}

func TestChoicesUseSavedProductAndReportErrorsWithoutToken(t *testing.T) {
	st := Settings{BaseURL: "https://dojo.example", Token: testToken, ProductID: 2, EngagementID: 3}
	svc, seen := choicesService(t, st, func(r *http.Request) (int, string) {
		if r.URL.Path == "/api/v2/products/" {
			return 200, `{"count": 1, "results": [{"id": 2, "name": "AGH"}]}`
		}
		return 403, `{"detail": "bad token ` + testToken + `"}`
	})
	_, err := svc.Choices(context.Background(), 0)
	if err == nil || !strings.Contains(err.Error(), "GET /api/v2/engagements/") || !strings.Contains(err.Error(), "token was rejected") ||
		strings.Contains(err.Error(), testToken) {
		t.Fatalf("Choices error = %v", err)
	}
	if last := (*seen)[len(*seen)-1]; last.URL.Query().Get("product") != "2" {
		t.Errorf("engagements asked for product %q, want the saved 2", last.URL.Query().Get("product"))
	}

	svc, seen = choicesService(t, Settings{}, func(*http.Request) (int, string) { return 200, `{}` })
	if _, err := svc.Choices(context.Background(), 0); err != ErrNotConfigured || len(*seen) != 0 {
		t.Fatalf("unconfigured Choices = %v after %d requests", err, len(*seen))
	}
}
