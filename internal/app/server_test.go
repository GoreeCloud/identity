package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStatusEndpoints(t *testing.T) {
	for _, tc := range []struct {
		path   string
		status string
	}{{"/healthz", "ok"}, {"/readyz", "ready"}} {
		t.Run(tc.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			rec := httptest.NewRecorder()
			Handler().ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
			}
			body := strings.TrimSpace(rec.Body.String())
			if !strings.Contains(body, `"service":"goreecloud-identity"`) || !strings.Contains(body, `"status":"`+tc.status+`"`) {
				t.Fatalf("unexpected body %q", body)
			}
			if !strings.Contains(body, `"production_accepted":false`) {
				t.Fatalf("health/readiness must not imply Identity production acceptance: %q", body)
			}
			if !strings.Contains(body, `"scope":"development-foundation"`) {
				t.Fatalf("development scope missing from status response: %q", body)
			}
			if rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("missing no-store")
			}
		})
	}
}

func TestHeadStatusIsBodylessAndNonCacheable(t *testing.T) {
	for _, path := range []string{"/healthz", "/readyz"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodHead, path, nil)
			rec := httptest.NewRecorder()
			Handler().ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("HEAD status = %d", rec.Code)
			}
			if rec.Body.Len() != 0 {
				t.Fatalf("HEAD unexpectedly returned a response body")
			}
			if rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("HEAD status must not be cached")
			}
			if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatal("missing nosniff protection")
			}
			if rec.Header().Get("Content-Type") != "application/json" {
				t.Fatal("missing JSON response content type")
			}
		})
	}
}

func TestStatusEndpointsRejectMutationMethods(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/healthz", strings.NewReader("ignored"))
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}
