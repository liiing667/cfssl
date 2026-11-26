package local

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/signer"
)

func TestSignConcurrentInitializationUsesOneIssuer(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy := &config.Signing{Default: &config.SigningProfile{
		Usage:        []string{"cert sign", "crl sign"},
		ExpiryString: "1h",
		Expiry:       time.Hour,
		CAConstraint: config.CAConstraint{IsCA: true},
	}}
	s, err := NewSigner(priv, nil, signer.DefaultSigAlgo(priv), policy)
	if err != nil {
		t.Fatal(err)
	}

	const requests = 8
	type result struct {
		cert *x509.Certificate
		err  error
	}
	results := make(chan result, requests)
	var wg sync.WaitGroup
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cn := fmt.Sprintf("concurrent-ca-%d", i)
			csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
				Subject: pkix.Name{CommonName: cn},
			}, priv)
			if err != nil {
				results <- result{err: err}
				return
			}
			csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
			certPEM, err := s.Sign(signer.SignRequest{Request: string(csrPEM)})
			if err != nil {
				results <- result{err: err}
				return
			}
			cert, err := helpers.ParseCertificatePEM(certPEM)
			if err != nil {
				results <- result{err: err}
				return
			}
			if cert.Subject.CommonName != cn {
				results <- result{err: fmt.Errorf("certificate subject = %q, want %q", cert.Subject.CommonName, cn)}
				return
			}
			results <- result{cert: cert}
		}(i)
	}
	wg.Wait()
	close(results)

	ca, err := s.Certificate("", "")
	if err != nil {
		t.Fatal(err)
	}
	for result := range results {
		if result.err != nil {
			t.Error(result.err)
			continue
		}
		if result.cert.Issuer.String() != ca.Subject.String() {
			t.Errorf("certificate issuer = %q, want CA subject %q", result.cert.Issuer, ca.Subject)
		}
		if err := result.cert.CheckSignatureFrom(ca); err != nil {
			t.Errorf("certificate does not verify against the initialized CA: %v", err)
		}
	}
}
