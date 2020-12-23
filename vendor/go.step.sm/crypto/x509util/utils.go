package x509util

import (
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"net"
	"net/url"
	"strings"

	"github.com/pkg/errors"
)

// FingerprintEncoding defines the supported encodigns in certificate
// fingerprints.
type FingerprintEncoding int

// Supported fingerprint encodings.
const (
	HexFingerprint FingerprintEncoding = iota
	Base64Fingerprint
	Base64UrlFingerprint
)

// SplitSANs splits a slice of Subject Alternative Names into slices of
// IP Addresses and DNS Names. If an element is not an IP address, then it
// is bucketed as a DNS Name.
func SplitSANs(sans []string) (dnsNames []string, ips []net.IP, emails []string, uris []*url.URL) {
	dnsNames = []string{}
	ips = []net.IP{}
	emails = []string{}
	uris = []*url.URL{}
	for _, san := range sans {
		if ip := net.ParseIP(san); ip != nil {
			ips = append(ips, ip)
		} else if u, err := url.Parse(san); err == nil && u.Scheme != "" {
			uris = append(uris, u)
		} else if strings.Contains(san, "@") {
			emails = append(emails, san)
		} else {
			dnsNames = append(dnsNames, san)
		}
	}
	return
}

// CreateSANs splits the given sans and returns a list of SubjectAlternativeName
// structs.
func CreateSANs(sans []string) []SubjectAlternativeName {
	dnsNames, ips, emails, uris := SplitSANs(sans)
	sanTypes := make([]SubjectAlternativeName, 0, len(sans))
	for _, v := range dnsNames {
		sanTypes = append(sanTypes, SubjectAlternativeName{Type: "dns", Value: v})
	}
	for _, v := range ips {
		sanTypes = append(sanTypes, SubjectAlternativeName{Type: "ip", Value: v.String()})
	}
	for _, v := range emails {
		sanTypes = append(sanTypes, SubjectAlternativeName{Type: "email", Value: v})
	}
	for _, v := range uris {
		sanTypes = append(sanTypes, SubjectAlternativeName{Type: "uri", Value: v.String()})
	}
	return sanTypes
}

// Fingerprint returns the SHA-256 fingerprint of the certificate.
func Fingerprint(cert *x509.Certificate) string {
	return EncodedFingerprint(cert, HexFingerprint)
}

// EncodedFingerprint returns an encoded the SHA-256 fingerprint of the
// certificate using the specified encoding. In an invalid encoding is passed,
// the return value will be an empty string.
func EncodedFingerprint(cert *x509.Certificate, encoding FingerprintEncoding) string {
	sum := sha256.Sum256(cert.Raw)
	switch encoding {
	case HexFingerprint:
		return strings.ToLower(hex.EncodeToString(sum[:]))
	case Base64Fingerprint:
		return base64.StdEncoding.EncodeToString(sum[:])
	case Base64UrlFingerprint:
		return base64.URLEncoding.EncodeToString(sum[:])
	default:
		return ""
	}
}

// generateSerialNumber returns a random serial number.
func generateSerialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	sn, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, errors.Wrap(err, "error generating serial number")
	}
	return sn, nil
}

// subjectPublicKeyInfo is a PKIX public key structure defined in RFC 5280.
type subjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

// generateSubjectKeyID generates the key identifier according the the RFC 5280
// section 4.2.1.2.
//
// The keyIdentifier is composed of the 160-bit SHA-1 hash of the value of the
// BIT STRING subjectPublicKey (excluding the tag, length, and number of unused
// bits).
func generateSubjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, errors.Wrap(err, "error marshaling public key")
	}
	var info subjectPublicKeyInfo
	if _, err = asn1.Unmarshal(b, &info); err != nil {
		return nil, errors.Wrap(err, "error unmarshaling public key")
	}
	hash := sha1.Sum(info.SubjectPublicKey.Bytes)
	return hash[:], nil
}
