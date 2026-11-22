package defectdojo

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

const (
	ScanTypeNmap    = "Nmap Scan"
	ScanTypeGeneric = "Generic Findings Import"

	ImportPath   = "/api/v2/import-scan/"
	ReimportPath = "/api/v2/reimport-scan/"

	maxResponseBytes = 1 << 20
	maxErrorBody     = 300
	choicePage       = 200
	maxChoices       = 2000

	notAPI = "the answer is not JSON, the base URL does not look like a DefectDojo API"
)

type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Client struct {
	BaseURL string
	Token   string
	HTTP    Doer
}

type APIError struct {
	Method string
	Path   string
	Status int
	Body   string
	NotAPI bool
}

func (e *APIError) Error() string {
	msg := fmt.Sprintf("defectdojo %s %s: %d %s", e.Method, e.Path, e.Status, http.StatusText(e.Status))
	if e.Status == http.StatusUnauthorized || e.Status == http.StatusForbidden {
		msg += ": the API token was rejected"
	}
	if e.NotAPI {
		msg += ": " + notAPI
	}
	if e.Body != "" {
		msg += ": " + e.Body
	}
	return msg
}

func (e *APIError) testMissing() bool {
	body := strings.ToLower(e.Body)
	return !e.NotAPI && (e.Status == http.StatusNotFound || e.Status == http.StatusBadRequest && strings.Contains(body, "test") &&
		(strings.Contains(body, "does not exist") || strings.Contains(body, "not found")))
}

type Upload struct {
	ScanType string
	FileName string
	File     []byte
}

func NormalizeBaseURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("base URL %q must be an absolute http or https URL", raw)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("base URL %q must not contain credentials, a query or a fragment", raw)
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	u.RawPath = ""
	return u.String(), nil
}

func (c *Client) CheckEngagement(ctx context.Context, productID, engagementID int) error {
	path := "/api/v2/engagements/" + strconv.Itoa(engagementID) + "/"
	req, err := c.newRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	var body struct {
		Product int `json:"product"`
	}
	if err := c.do(req, path, &body); err != nil {
		return err
	}
	if body.Product != productID {
		return fmt.Errorf("defectdojo engagement %d belongs to product %d, not %d", engagementID, body.Product, productID)
	}
	return nil
}

type Choice struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

func (c *Client) Products(ctx context.Context) ([]Choice, error) {
	return c.list(ctx, "/api/v2/products/", url.Values{})
}

func (c *Client) Engagements(ctx context.Context, productID int) ([]Choice, error) {
	return c.list(ctx, "/api/v2/engagements/", url.Values{"product": {strconv.Itoa(productID)}})
}

func (c *Client) list(ctx context.Context, path string, q url.Values) ([]Choice, error) {
	var all []Choice
	for len(all) < maxChoices {
		q.Set("limit", strconv.Itoa(choicePage))
		q.Set("offset", strconv.Itoa(len(all)))
		req, err := c.newRequest(ctx, http.MethodGet, path+"?"+q.Encode(), nil)
		if err != nil {
			return nil, err
		}
		var body struct {
			Count   int      `json:"count"`
			Results []Choice `json:"results"`
		}
		if err := c.do(req, path, &body); err != nil {
			return nil, err
		}
		all = append(all, body.Results...)
		if len(body.Results) == 0 || len(all) >= body.Count {
			break
		}
	}
	slices.SortFunc(all, func(a, b Choice) int {
		return cmp.Or(cmp.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)), cmp.Compare(a.ID, b.ID))
	})
	return all, nil
}

func (c *Client) TestExists(ctx context.Context, testID int) (bool, error) {
	path := "/api/v2/tests/" + strconv.Itoa(testID) + "/"
	req, err := c.newRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return false, err
	}
	var body struct {
		ID int `json:"id"`
	}
	err = c.do(req, path, &body)
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.Status == http.StatusNotFound && !apiErr.NotAPI {
		return false, nil
	}
	return err == nil, err
}

func (c *Client) Import(ctx context.Context, engagementID int, up Upload) (int, error) {
	return c.upload(ctx, ImportPath, "engagement", engagementID, up)
}

func (c *Client) Reimport(ctx context.Context, testID int, up Upload) (int, error) {
	return c.upload(ctx, ReimportPath, "test", testID, up)
}

func (c *Client) upload(ctx context.Context, path, idField string, id int, up Upload) (int, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fields := [][2]string{
		{"scan_type", up.ScanType},
		{idField, strconv.Itoa(id)},
		{"minimum_severity", "Info"},
		{"active", "true"},
		{"verified", "false"},
	}
	for _, f := range fields {
		if err := mw.WriteField(f[0], f[1]); err != nil {
			return 0, fmt.Errorf("defectdojo upload: %w", err)
		}
	}
	fw, err := mw.CreateFormFile("file", up.FileName)
	if err != nil {
		return 0, fmt.Errorf("defectdojo upload: %w", err)
	}
	if _, err := fw.Write(up.File); err != nil {
		return 0, fmt.Errorf("defectdojo upload: %w", err)
	}
	if err := mw.Close(); err != nil {
		return 0, fmt.Errorf("defectdojo upload: %w", err)
	}
	req, err := c.newRequest(ctx, http.MethodPost, path, &buf)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	var body struct {
		TestID int `json:"test_id"`
		Test   int `json:"test"`
	}
	if err := c.do(req, path, &body); err != nil {
		return 0, err
	}
	if body.TestID == 0 {
		body.TestID = body.Test
	}
	if body.TestID == 0 {
		return 0, fmt.Errorf("defectdojo POST %s: response has no test id", path)
	}
	return body.TestID, nil
}

func (c *Client) newRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	if c.HTTP == nil {
		return nil, errors.New("defectdojo: no http client")
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
	if err != nil {
		return nil, fmt.Errorf("defectdojo %s %s: %w", method, path, err)
	}
	req.Header.Set("Authorization", "Token "+c.Token)
	req.Header.Set("Accept", "application/json")
	return req, nil
}

func (c *Client) do(req *http.Request, path string, out any) error {
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("defectdojo %s %s: %s", req.Method, path, c.redact(err.Error()))
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("defectdojo %s %s: read response: %s", req.Method, path, c.redact(err.Error()))
	}
	isJSON := json.Valid(data)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &APIError{Method: req.Method, Path: path, Status: resp.StatusCode, Body: c.errorBody(data), NotAPI: !isJSON && len(data) > 0}
	}
	if !isJSON {
		return fmt.Errorf("defectdojo %s %s: %s", req.Method, path, notAPI)
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("defectdojo %s %s: decode response: %w", req.Method, path, err)
	}
	return nil
}

func (c *Client) errorBody(data []byte) string {
	var v any
	if json.Unmarshal(data, &v) == nil {
		b, err := json.Marshal(c.withoutToken(v))
		if err != nil {
			return ""
		}
		data = b
	} else if c.Token != "" && bytes.Contains(data, []byte(c.Token)) {
		return ""
	}
	s := strings.Join(strings.Fields(string(data)), " ")
	if s == "{}" || s == "[]" || s == "null" {
		return ""
	}
	if len(s) > maxErrorBody {
		s = strings.ToValidUTF8(s[:maxErrorBody], "") + "…"
	}
	return s
}

func (c *Client) withoutToken(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			if c.leaks(x) {
				delete(t, k)
				continue
			}
			t[k] = c.withoutToken(x)
		}
	case []any:
		out := t[:0]
		for _, x := range t {
			if !c.leaks(x) {
				out = append(out, c.withoutToken(x))
			}
		}
		return out
	}
	return v
}

func (c *Client) leaks(v any) bool {
	s, ok := v.(string)
	return ok && c.Token != "" && strings.Contains(s, c.Token)
}

func (c *Client) redact(s string) string {
	if c.Token == "" {
		return s
	}
	return strings.ReplaceAll(s, c.Token, "[redacted]")
}
