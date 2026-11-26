package initca

import (
	"fmt"
	"sync"
	"testing"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/helpers"
)

func TestNewConcurrentSharedCAPolicy(t *testing.T) {
	originalCAPolicy := CAPolicy
	defer func() { CAPolicy = originalCAPolicy }()

	shared := &config.Signing{
		Default: &config.SigningProfile{
			Usage:        []string{"cert sign", "crl sign"},
			ExpiryString: "43800h",
			Expiry:       5 * helpers.OneYear,
			CRL:          "https://ca.example/shared.crl",
			CAConstraint: config.CAConstraint{IsCA: true, MaxPathLen: 7},
		},
	}
	CAPolicy = func() *config.Signing { return shared }

	const requests = 8
	var wg sync.WaitGroup
	errs := make(chan error, requests)
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := &csr.CertificateRequest{
				CN:         fmt.Sprintf("shared-policy-ca-%d", i),
				KeyRequest: &csr.KeyRequest{A: "ecdsa", S: 256},
				CRL:        fmt.Sprintf("https://ca.example/request-%d.crl", i),
				CA: &csr.CAConfig{
					Expiry:     "1h",
					PathLength: i%2 + 1,
				},
			}
			certPEM, _, _, err := New(req)
			if err != nil {
				errs <- err
				return
			}
			cert, err := helpers.ParseCertificatePEM(certPEM)
			if err != nil {
				errs <- err
				return
			}
			if cert.Subject.CommonName != req.CN {
				errs <- fmt.Errorf("certificate subject = %q, want %q", cert.Subject.CommonName, req.CN)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	if shared.Default.ExpiryString != "43800h" ||
		shared.Default.CRL != "https://ca.example/shared.crl" ||
		shared.Default.CAConstraint.MaxPathLen != 7 {
		t.Fatalf("CAPolicy's shared policy was modified: %+v", shared.Default)
	}
}
