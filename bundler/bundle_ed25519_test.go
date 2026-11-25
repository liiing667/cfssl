package bundler

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestBundleEd25519Certificate(t *testing.T) {
	ca, caKey, caPEM := newEd25519CA(t)
	leaf, leafKey := newEd25519Leaf(t, ca, caKey)

	b, err := NewBundlerFromPEM(caPEM, nil)
	if err != nil {
		t.Fatal(err)
	}

	bundle, err := b.Bundle([]*x509.Certificate{leaf, ca}, leafKey, Optimal)
	if err != nil {
		t.Fatalf("bundling Ed25519 certificate: %v", err)
	}
	if bundle.Root == nil || !bundle.Root.Equal(ca) {
		t.Fatal("bundle root is not the Ed25519 CA")
	}

	encoded, err := bundle.MarshalJSON()
	if err != nil {
		t.Fatalf("marshaling Ed25519 bundle: %v", err)
	}
	var result map[string]interface{}
	if err := json.Unmarshal(encoded, &result); err != nil {
		t.Fatal(err)
	}

	if got := result["key_type"]; got != "Ed25519" {
		t.Fatalf("key_type = %v, want Ed25519", got)
	}
	if got := result["key_size"]; got != float64(ed25519.PublicKeySize) {
		t.Fatalf("key_size = %v, want %d", got, ed25519.PublicKeySize)
	}
	if got := result["signature"]; got != "Ed25519" {
		t.Fatalf("signature = %v, want Ed25519", got)
	}
	key, _ := result["key"].(string)
	if !strings.Contains(key, "BEGIN Ed25519 PRIVATE KEY") {
		t.Fatalf("key does not contain an Ed25519 private key: %q", key)
	}

	keyless, err := b.Bundle([]*x509.Certificate{leaf, ca}, nil, Optimal)
	if err != nil {
		t.Fatalf("keyless Ed25519 bundling: %v", err)
	}
	keylessJSON, err := keyless.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(keylessJSON, []byte(`"key_type":"Ed25519"`)) {
		t.Fatalf("keyless bundle has the wrong key type: %s", keylessJSON)
	}
}

func TestBundleEd25519KeyMismatch(t *testing.T) {
	ca, caKey, caPEM := newEd25519CA(t)
	leaf, _ := newEd25519Leaf(t, ca, caKey)
	_, otherKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	b, err := NewBundlerFromPEM(caPEM, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Bundle([]*x509.Certificate{leaf, ca}, otherKey, Optimal); err == nil {
		t.Fatal("bundling with a mismatched Ed25519 key succeeded")
	}
}

func newEd25519CA(t *testing.T) (*x509.Certificate, ed25519.PrivateKey, []byte) {
	t.Helper()

	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Ed25519 Test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SignatureAlgorithm:    x509.PureEd25519,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func newEd25519Leaf(t *testing.T, ca *x509.Certificate, caKey ed25519.PrivateKey) (*x509.Certificate, ed25519.PrivateKey) {
	t.Helper()

	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "ed25519.bundle.test"},
		DNSNames:              []string{"ed25519.bundle.test"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.PureEd25519,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, key.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}
