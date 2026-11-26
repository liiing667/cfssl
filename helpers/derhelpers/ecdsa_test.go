package derhelpers

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	cferr "github.com/cloudflare/cfssl/errors"
)

var (
	testOIDP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	testOIDP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	testOIDP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

type testECPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

type testPKCS8 struct {
	Version    int
	Algo       asn1.RawValue
	PrivateKey []byte
}

func marshalSEC1(t *testing.T, curveOID asn1.ObjectIdentifier, scalar []byte, pubPoint []byte) []byte {
	t.Helper()
	der, err := asn1.Marshal(testECPrivateKey{
		Version:       1,
		PrivateKey:    scalar,
		NamedCurveOID: curveOID,
		PublicKey:     asn1.BitString{Bytes: pubPoint, BitLength: len(pubPoint) * 8},
	})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func marshalPKCS8EC(t *testing.T, curveOID asn1.ObjectIdentifier, sec1DER []byte) []byte {
	t.Helper()
	oidDER, err := asn1.Marshal(curveOID)
	if err != nil {
		t.Fatal(err)
	}
	algDER, err := asn1.Marshal(pkix.AlgorithmIdentifier{
		Algorithm:  oidPublicKeyECDSA,
		Parameters: asn1.RawValue{FullBytes: oidDER},
	})
	if err != nil {
		t.Fatal(err)
	}
	der, err := asn1.Marshal(testPKCS8{
		Version:    0,
		Algo:       asn1.RawValue{FullBytes: algDER},
		PrivateKey: sec1DER,
	})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func expectKeyMismatch(t *testing.T, der []byte, label string) {
	t.Helper()
	_, err := ParsePrivateKeyDER(der)
	if err == nil {
		t.Fatalf("%s: expected mismatched EC key to be rejected", label)
	}
	wantCode := int(cferr.PrivateKeyError) + int(cferr.KeyMismatch)
	cfErr, ok := err.(*cferr.Error)
	if !ok || cfErr.ErrorCode != wantCode {
		t.Fatalf("%s: expected PrivateKeyError/KeyMismatch, got %v", label, err)
	}
}

// TestParsePrivateKeyDER_StandardECKeys ensures well-formed EC keys on every
// supported NIST curve continue to parse, in both SEC 1 and PKCS #8 form.
func TestParsePrivateKeyDER_StandardECKeys(t *testing.T) {
	curves := []struct {
		name  string
		curve elliptic.Curve
		oid   asn1.ObjectIdentifier
	}{
		{"P-256", elliptic.P256(), testOIDP256},
		{"P-384", elliptic.P384(), testOIDP384},
		{"P-521", elliptic.P521(), testOIDP521},
	}

	for _, c := range curves {
		t.Run(c.name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(c.curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}

			sec1, err := x509.MarshalECPrivateKey(key)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParsePrivateKeyDER(sec1); err != nil {
				t.Fatalf("standard SEC1 %s key rejected: %v", c.name, err)
			}

			pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParsePrivateKeyDER(pkcs8); err != nil {
				t.Fatalf("standard PKCS#8 %s key rejected: %v", c.name, err)
			}
		})
	}
}

// TestParsePrivateKeyDER_NonECKeysUnaffected ensures RSA and Ed25519 keys are
// untouched by the EC validation path.
func TestParsePrivateKeyDER_NonECKeysUnaffected(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePrivateKeyDER(x509.MarshalPKCS1PrivateKey(rsaKey)); err != nil {
		t.Fatalf("RSA key rejected: %v", err)
	}

	_, edPub, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edDER, err := MarshalEd25519PrivateKey(edPub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePrivateKeyDER(edDER); err != nil {
		t.Fatalf("Ed25519 key rejected: %v", err)
	}
}

// TestParsePrivateKeyDER_CurveMismatch is the regression test for the
// inconsistent signing identity issue: an EC key whose parameters name one
// curve while the embedded public key is a point on another curve must be
// rejected, for both SEC 1 and PKCS #8 encodings.
func TestParsePrivateKeyDER_CurveMismatch(t *testing.T) {
	k256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	scalar256 := k256.D.FillBytes(make([]byte, 32))
	pub384 := elliptic.Marshal(elliptic.P384(), k384.PublicKey.X, k384.PublicKey.Y)

	// SEC 1: P-256 named curve + P-384 embedded public point.
	mismatchedSEC1 := marshalSEC1(t, testOIDP256, scalar256, pub384)
	expectKeyMismatch(t, mismatchedSEC1, "SEC1")

	// Same payload wrapped in PKCS #8 with a P-256 algorithm identifier.
	mismatchedPKCS8 := marshalPKCS8EC(t, testOIDP256, mismatchedSEC1)
	expectKeyMismatch(t, mismatchedPKCS8, "PKCS#8")
}

// TestParsePrivateKeyDER_EmbeddedPubNotOnCurve rejects an embedded public
// point that is not a valid point on the named curve at all.
func TestParsePrivateKeyDER_EmbeddedPubNotOnCurve(t *testing.T) {
	k256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	scalar := k256.D.FillBytes(make([]byte, 32))
	// A well-sized but bogus point (all 0xff coordinates).
	bogusPoint := make([]byte, 1+2*32)
	bogusPoint[0] = 4
	for i := 1; i < len(bogusPoint); i++ {
		bogusPoint[i] = 0xff
	}

	expectKeyMismatch(t, marshalSEC1(t, testOIDP256, scalar, bogusPoint), "bogus point")
}

// TestParsePrivateKeyDER_EmbeddedPubWrongPoint rejects a key whose embedded
// public key is a valid point on the named curve, but does not correspond to
// the private scalar.
func TestParsePrivateKeyDER_EmbeddedPubWrongPoint(t *testing.T) {
	k256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	scalar := k256.D.FillBytes(make([]byte, 32))
	otherPub := elliptic.Marshal(elliptic.P256(), other.PublicKey.X, other.PublicKey.Y)

	expectKeyMismatch(t, marshalSEC1(t, testOIDP256, scalar, otherPub), "wrong point")
}

// TestParsePrivateKeyDER_CompressedPoint ensures an embedded public key using
// the compressed point encoding is accepted when consistent and rejected when
// it belongs to another curve.
func TestParsePrivateKeyDER_CompressedPoint(t *testing.T) {
	k256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	scalar := k256.D.FillBytes(make([]byte, 32))

	// Consistent compressed P-256 point: must parse.
	goodCompressed := elliptic.MarshalCompressed(elliptic.P256(), k256.PublicKey.X, k256.PublicKey.Y)
	if _, err := ParsePrivateKeyDER(marshalSEC1(t, testOIDP256, scalar, goodCompressed)); err != nil {
		t.Fatalf("consistent compressed point rejected: %v", err)
	}

	// Compressed P-384 point inside a key whose parameters name P-256: reject.
	foreignCompressed := elliptic.MarshalCompressed(elliptic.P384(), k384.PublicKey.X, k384.PublicKey.Y)
	expectKeyMismatch(t, marshalSEC1(t, testOIDP256, scalar, foreignCompressed), "foreign compressed point")
}

// TestValidateECPrivateKeyDER_NonEC confirms non-EC DER is reported as not EC
// and left to the standard parser.
func TestValidateECPrivateKeyDER_NonEC(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := ValidateECPrivateKeyDER(x509.MarshalPKCS1PrivateKey(rsaKey))
	if err != nil {
		t.Fatalf("RSA DER produced an error: %v", err)
	}
	if ok {
		t.Fatal("RSA DER reported as EC key")
	}
}

// TestParsePrivateKeyDER_PKCS8CorruptInnerKey ensures an EC PKCS #8 wrapper
// whose inner SEC 1 payload is malformed is rejected rather than bypassing the
// curve consistency check.
func TestParsePrivateKeyDER_PKCS8CorruptInnerKey(t *testing.T) {
	oidDER, err := asn1.Marshal(testOIDP256)
	if err != nil {
		t.Fatal(err)
	}
	algDER, err := asn1.Marshal(pkix.AlgorithmIdentifier{
		Algorithm:  oidPublicKeyECDSA,
		Parameters: asn1.RawValue{FullBytes: oidDER},
	})
	if err != nil {
		t.Fatal(err)
	}
	corrupt, err := asn1.Marshal(testPKCS8{
		Version:    0,
		Algo:       asn1.RawValue{FullBytes: algDER},
		PrivateKey: []byte{0x30, 0x03, 0x02, 0x01, 0x01},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePrivateKeyDER(corrupt); err == nil {
		t.Fatal("corrupt inner SEC 1 key inside an EC PKCS#8 wrapper was accepted")
	}
}
