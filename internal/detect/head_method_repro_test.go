package detect

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"asi/internal/probe"
)

func TestReproSignatureWithMethodHEADIsSentAsHEAD(t *testing.T) {
	var mu sync.Mutex
	methods := map[string][]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		methods[r.URL.Path] = append(methods[r.URL.Path], r.Method)
		mu.Unlock()
		if r.URL.Path == "/favicon.ico" {
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portStr)
	sess, err := probe.Probe(context.Background(), host, port, false, "")
	if err != nil {
		t.Fatal(err)
	}
	sigs := mustParse(t, "- {id: h, name: H, kind: custom, confidence: 1, request: {method: HEAD, path: /h}, match: {all: [{type: status, value: 200}]}}\n"+
		"- {id: g, name: G, kind: custom, confidence: 1, request: {method: GET, path: /g}, match: {all: [{type: status, value: 200}]}}\n")
	res := (&Set{Signatures: sigs}).Detect(context.Background(), sess)
	mu.Lock()
	defer mu.Unlock()
	if got := methods["/h"]; len(got) != 1 || got[0] != http.MethodHead {
		t.Errorf("request methods for HEAD signature path /h = %v, want [HEAD]", got)
	}
	if got := methods["/g"]; len(got) != 1 || got[0] != http.MethodGet {
		t.Errorf("request methods for GET signature path /g = %v, want [GET]", got)
	}
	if len(res.Findings) != 2 {
		t.Errorf("findings = %+v, want h and g", res.Findings)
	}
}

func TestHeadAndGetSignaturesOnOnePathAreSentWithTheirOwnMethods(t *testing.T) {
	var mu sync.Mutex
	methods := map[string][]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		methods[r.URL.Path] = append(methods[r.URL.Path], r.Method)
		mu.Unlock()
		if r.URL.Path == "/favicon.ico" {
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portStr)
	sess, err := probe.Probe(context.Background(), host, port, false, "")
	if err != nil {
		t.Fatal(err)
	}
	sigs := mustParse(t, "- {id: h, name: H, kind: custom, confidence: 1, request: {method: HEAD, path: /x}, match: {all: [{type: status, value: 200}]}}\n"+
		"- {id: g, name: G, kind: custom, confidence: 1, request: {method: GET, path: /x}, match: {all: [{type: status, value: 200}]}}\n"+
		"- {id: h2, name: H2, kind: custom, confidence: 1, request: {method: HEAD, path: /x}, match: {all: [{type: status, value: 200}]}}\n")
	res := (&Set{Signatures: sigs}).Detect(context.Background(), sess)
	mu.Lock()
	defer mu.Unlock()
	if got := methods["/x"]; len(got) != 2 || got[0] != http.MethodHead || got[1] != http.MethodGet {
		t.Errorf("request methods for /x = %v, want [HEAD GET]", got)
	}
	if len(res.Findings) != 3 {
		t.Errorf("findings = %+v, want h, g and h2", res.Findings)
	}
}
