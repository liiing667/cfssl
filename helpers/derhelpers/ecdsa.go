package derhelpers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"

	cferr "github.com/cloudflare/cfssl/errors"
)

// OID id-ecPublicKey (RFC 5480): algorithm identifier used for EC keys inside
// PKCS #8 PrivateKeyInfo.
var oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

// ecPrivateKey mirrors the ASN.1 Elliptic Curve Private Key Structure
// (RFC 5915 / SEC 1). The standard library's parser does not expose the
// embedded publicKey field, so the structure has to be inspected directly to
// validate it.
type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

// pkcs8ECPrivateKey is the subset of PKCS #8 PrivateKeyInfo needed to locate
// an EC key and its named curve.
type pkcs8ECPrivateKey struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

// namedCurveFromOID maps the named-curve OIDs supported by cfssl to curves.
// It deliberately only accepts the standard NIST curves; anything else is
// rejected rather than silently accepted.
func namedCurveFromOID(oid asn1.ObjectIdentifier) elliptic.Curve {
	switch {
	case oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}): // secp256r1
		return elliptic.P256()
	case oid.Equal(asn1.ObjectIdentifier{1, 3, 132, 0, 34}): // secp384r1
		return elliptic.P384()
	case oid.Equal(asn1.ObjectIdentifier{1, 3, 132, 0, 35}): // secp521r1
		return elliptic.P521()
	case oid.Equal(asn1.ObjectIdentifier{1, 3, 132, 0, 33}): // secp224r1
		return elliptic.P224()
	}
	return nil
}

// ValidateECPrivateKeyDER validates an ECDSA private key encoded as either a
// SEC 1 ECPrivateKey or a PKCS #8 PrivateKeyInfo carrying an EC key. Non-EC
// inputs return ok == false and no error, leaving them to the regular parser.
//
// It verifies that the public key embedded in the key material:
//   - lies on the curve named by the key's EC parameters, and
//   - equals the point derived from the private scalar on that curve.
//
// This rejects keys whose EC parameters select a different curve than the
// embedded public key (for example a P-256 private scalar with a P-384 public
// key). Without the check, the signer would use the private scalar on one
// curve while the issued certificate binds the mismatched public key, yielding
// a certificate whose signature does not match the signing identity.
func ValidateECPrivateKeyDER(keyDER []byte) (ok bool, err error) {
	curve, scalar, embeddedPub, isEC, err := extractECKeyMaterial(keyDER)
	if err != nil || !isEC {
		return isEC, err
	}

	if curve == nil {
		return true, cferr.New(cferr.PrivateKeyError, cferr.KeyMismatch)
	}

	// Derive the public point from the private scalar on the named curve.
	x, y := curve.ScalarBaseMult(scalar)
	if x == nil || y == nil || !curve.IsOnCurve(x, y) {
		return true, cferr.New(cferr.PrivateKeyError, cferr.KeyMismatch)
	}
	// The embedded public key is optional in SEC 1; when present it must be
	// consistent. An empty BitString means "absent" and is left to the
	// standard parser, which recomputes the public key from the scalar.
	if len(embeddedPub) == 0 {
		return true, nil
	}

	// The embedded point must itself be a valid point on the named curve.
	// Both the uncompressed (0x04) form produced by Go/OpenSSL SEC 1 output
	// and the compressed (0x02/0x03) form are accepted.
	var ex, ey *big.Int
	switch {
	case len(embeddedPub) > 0 && embeddedPub[0] == 4:
		ex, ey = elliptic.Unmarshal(curve, embeddedPub)
	case len(embeddedPub) > 0 && (embeddedPub[0] == 2 || embeddedPub[0] == 3):
		ex, ey = elliptic.UnmarshalCompressed(curve, embeddedPub)
	default:
		return true, cferr.New(cferr.PrivateKeyError, cferr.KeyMismatch)
	}
	if ex == nil || ey == nil {
		return true, cferr.New(cferr.PrivateKeyError, cferr.KeyMismatch)
	}
	// ...and it must equal the point derived from the private scalar.
	if ex.Cmp(x) != 0 || ey.Cmp(y) != 0 {
		return true, cferr.New(cferr.PrivateKeyError, cferr.KeyMismatch)
	}

	return true, nil
}

// extractECKeyMaterial inspects the DER encoding and returns the named curve,
// the private scalar and the raw embedded public point (uncompressed or
// compressed SEC 1 encoding) for an EC key. For non-EC inputs isEC is false.
func extractECKeyMaterial(keyDER []byte) (curve elliptic.Curve, scalar, embeddedPub []byte, isEC bool, err error) {
	// First try PKCS #8 PrivateKeyInfo.
	var p8 pkcs8ECPrivateKey
	if _, p8Err := asn1.Unmarshal(keyDER, &p8); p8Err == nil && p8.Algo.Algorithm.Equal(oidPublicKeyECDSA) {
		curveOID := new(asn1.ObjectIdentifier)
		if _, oidErr := asn1.Unmarshal(p8.Algo.Parameters.FullBytes, curveOID); oidErr != nil {
			return nil, nil, nil, true, cferr.New(cferr.PrivateKeyError, cferr.KeyMismatch)
		}
		curve = namedCurveFromOID(*curveOID)

		var sec1 ecPrivateKey
		if rest, sec1Err := asn1.Unmarshal(p8.PrivateKey, &sec1); sec1Err != nil || len(rest) != 0 {
			return nil, nil, nil, true, cferr.New(cferr.PrivateKeyError, cferr.KeyMismatch)
		}
		return curve, sec1.PrivateKey, sec1.PublicKey.RightAlign(), true, nil
	}

	// Otherwise try a bare SEC 1 ECPrivateKey.
	var sec1 ecPrivateKey
	if rest, sec1Err := asn1.Unmarshal(keyDER, &sec1); sec1Err != nil || len(rest) != 0 {
		// Not a structure we recognize as EC: let the standard parser handle
		// (and produce its own error for) the input.
		return nil, nil, nil, false, nil
	}

	curve = namedCurveFromOID(sec1.NamedCurveOID)
	return curve, sec1.PrivateKey, sec1.PublicKey.RightAlign(), true, nil
}

// validateParsedECPrivateKey is a defense-in-depth check applied to the key
// returned by the standard library. On current Go releases the parser already
// recomputes a consistent public key, but keeping this check means a key whose
// parsed form is somehow self-inconsistent can never be issued.
func validateParsedECPrivateKey(key *ecdsa.PrivateKey) error {
	if key == nil || key.Curve == nil || key.D == nil || key.X == nil || key.Y == nil {
		return cferr.New(cferr.PrivateKeyError, cferr.KeyMismatch)
	}
	x, y := key.Curve.ScalarBaseMult(key.D.Bytes())
	if x == nil || y == nil || !key.Curve.IsOnCurve(x, y) {
		return cferr.New(cferr.PrivateKeyError, cferr.KeyMismatch)
	}
	if key.X.Cmp(x) != 0 || key.Y.Cmp(y) != 0 {
		return cferr.New(cferr.PrivateKeyError, cferr.KeyMismatch)
	}
	return nil
}
