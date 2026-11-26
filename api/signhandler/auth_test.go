package signhandler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/cloudflare/cfssl/auth"
	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/signer/local"
)

func TestAuthHandlerRejectsProfilesOutsidePolicy(t *testing.T) {
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
	handler, err := NewAuthHandlerFromSigner(s)
	if err != nil {
		t.Fatal(err)
	}

	csrPEM, err := os.ReadFile(testCSRFile)
	if err != nil {
		t.Fatal(err)
	}
	signRequest, err := json.Marshal(map[string]string{
		"certificate_request": string(csrPEM),
		"profile":             "not-configured",
	})
	if err != nil {
		t.Fatal(err)
	}
	token, err := conf.Signing.Default.Provider.Token(signRequest)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(&auth.AuthenticatedRequest{
		Request: signRequest,
		Token:   token,
	})
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s; want unknown profile error", rec.Code, rec.Body.String())
	}
}

func TestAuthHandlerAcceptsConfiguredProfile(t *testing.T) {
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
	handler, err := NewAuthHandlerFromSigner(s)
	if err != nil {
		t.Fatal(err)
	}

	csrPEM, err := os.ReadFile(testCSRFile)
	if err != nil {
		t.Fatal(err)
	}
	signRequest, err := json.Marshal(map[string]string{"certificate_request": string(csrPEM)})
	if err != nil {
		t.Fatal(err)
	}
	token, err := conf.Signing.Default.Provider.Token(signRequest)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(&auth.AuthenticatedRequest{
		Request: signRequest,
		Token:   token,
	})
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s; want success", rec.Code, rec.Body.String())
	}
}
