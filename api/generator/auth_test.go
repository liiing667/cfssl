package generator

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/signer/local"
)

func TestNewCertRejectsAuthenticatedProfile(t *testing.T) {
	conf, err := config.LoadConfig([]byte(`{
		"signing": {
			"default": {
				"usages": ["digital signature"],
				"expiry": "1h",
				"auth_key": "sample"
			}
		},
		"auth_keys": {
			"sample": {
				"type": "standard",
				"key": "0123456789ABCDEF0123456789ABCDEF"
			}
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}

	s, err := local.NewSignerFromFile(testCaFile, testCaKeyFile, conf.Signing)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewCertGeneratorHandlerFromSigner(CSRValidate, s)

	request := &csr.CertificateRequest{
		CN:         "auth-required.example",
		KeyRequest: &csr.KeyRequest{A: "ecdsa", S: 256},
	}
	body, err := json.Marshal(map[string]interface{}{"request": request})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s; want authentication required", rec.Code, rec.Body.String())
	}
}

func newCertRequest(t *testing.T, profile string) *httptest.ResponseRecorder {
	t.Helper()

	conf, err := config.LoadConfig([]byte(`{
		"signing": {
			"default": {
				"usages": ["digital signature"],
				"expiry": "1h"
			}
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	s, err := local.NewSignerFromFile(testCaFile, testCaKeyFile, conf.Signing)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewCertGeneratorHandlerFromSigner(CSRValidate, s)

	request := &csr.CertificateRequest{
		CN:         "unauthenticated.example",
		Hosts:      []string{"unauthenticated.example"},
		KeyRequest: &csr.KeyRequest{A: "ecdsa", S: 256},
	}
	body, err := json.Marshal(map[string]interface{}{
		"request": request,
		"profile": profile,
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestNewCertUnauthenticatedProfileControl(t *testing.T) {
	rec := newCertRequest(t, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s; want success", rec.Code, rec.Body.String())
	}
}

func TestNewCertRejectsUnknownProfile(t *testing.T) {
	rec := newCertRequest(t, "does-not-exist")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s; want unknown profile error", rec.Code, rec.Body.String())
	}
}
