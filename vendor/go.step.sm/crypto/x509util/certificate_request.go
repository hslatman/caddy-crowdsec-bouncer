package x509util

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"

	"github.com/pkg/errors"
)

var emptyASN1Subject = []byte{0x30, 0}
var oidExtensionSubjectAltName = []int{2, 5, 29, 17}

// CertificateRequest is the JSON representation of an X.509 certificate. It is
// used to build a certificate request from a template.
type CertificateRequest struct {
	Version            int                      `json:"version"`
	Subject            Subject                  `json:"subject"`
	DNSNames           MultiString              `json:"dnsNames"`
	EmailAddresses     MultiString              `json:"emailAddresses"`
	IPAddresses        MultiIP                  `json:"ipAddresses"`
	URIs               MultiURL                 `json:"uris"`
	SANs               []SubjectAlternativeName `json:"sans"`
	Extensions         []Extension              `json:"extensions"`
	SignatureAlgorithm SignatureAlgorithm       `json:"signatureAlgorithm"`
	PublicKey          interface{}              `json:"-"`
	PublicKeyAlgorithm x509.PublicKeyAlgorithm  `json:"-"`
	Signature          []byte                   `json:"-"`
	Signer             crypto.Signer            `json:"-"`
}

// NewCertificateRequest creates a certificate request from a template.
func NewCertificateRequest(signer crypto.Signer, opts ...Option) (*CertificateRequest, error) {
	pub := signer.Public()
	o, err := new(Options).apply(&x509.CertificateRequest{
		PublicKey: pub,
	}, opts)
	if err != nil {
		return nil, err
	}

	// If no template use only the certificate request with the default leaf key
	// usages.
	if o.CertBuffer == nil {
		return &CertificateRequest{
			PublicKey: pub,
			Signer:    signer,
		}, nil
	}

	// With templates
	var cr CertificateRequest
	if err := json.NewDecoder(o.CertBuffer).Decode(&cr); err != nil {
		return nil, errors.Wrap(err, "error unmarshaling certificate")
	}
	cr.PublicKey = pub
	cr.Signer = signer
	return &cr, nil
}

// newCertificateRequest is an internal method that creates a CertificateRequest
// from an x509.CertificateRequest.
//
// This method is used to create the template variable .Insecure.CR or to
// initialize the Certificate when no templates are used. newCertificateRequest
// will always ignore the SignatureAlgorithm because we cannot guarantee that
// the signer will be able to sign a certificate template if
// Certificate.SignatureAlgorithm is set.
func newCertificateRequest(cr *x509.CertificateRequest) *CertificateRequest {
	// Set SubjectAltName extension as critical if Subject is empty.
	fixSubjectAltName(cr)
	return &CertificateRequest{
		Version:            cr.Version,
		Subject:            newSubject(cr.Subject),
		DNSNames:           cr.DNSNames,
		EmailAddresses:     cr.EmailAddresses,
		IPAddresses:        cr.IPAddresses,
		URIs:               cr.URIs,
		Extensions:         newExtensions(cr.Extensions),
		PublicKey:          cr.PublicKey,
		PublicKeyAlgorithm: cr.PublicKeyAlgorithm,
		Signature:          cr.Signature,
		// Do not enforce signature algorithm from the CSR, it might not
		// be compatible with the certificate signer.
		SignatureAlgorithm: 0,
	}
}

// GetCertificateRequest returns the equivalent x509.CertificateRequest.
func (c *CertificateRequest) GetCertificateRequest() (*x509.CertificateRequest, error) {
	cert := c.GetCertificate().GetCertificate()
	asn1Data, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            cert.Subject,
		DNSNames:           cert.DNSNames,
		IPAddresses:        cert.IPAddresses,
		EmailAddresses:     cert.EmailAddresses,
		URIs:               cert.URIs,
		ExtraExtensions:    cert.ExtraExtensions,
		SignatureAlgorithm: x509.SignatureAlgorithm(c.SignatureAlgorithm),
	}, c.Signer)
	if err != nil {
		return nil, errors.Wrap(err, "error creating certificate request")
	}
	// This should not fail
	return x509.ParseCertificateRequest(asn1Data)
}

// GetCertificate returns the Certificate representation of the
// CertificateRequest.
//
// GetCertificate will not specify a SignatureAlgorithm, it's not possible to
// guarantee that the certificate signer can sign with the CertificateRequest
// SignatureAlgorithm.
func (c *CertificateRequest) GetCertificate() *Certificate {
	return &Certificate{
		Subject:            c.Subject,
		DNSNames:           c.DNSNames,
		EmailAddresses:     c.EmailAddresses,
		IPAddresses:        c.IPAddresses,
		URIs:               c.URIs,
		SANs:               c.SANs,
		Extensions:         c.Extensions,
		PublicKey:          c.PublicKey,
		PublicKeyAlgorithm: c.PublicKeyAlgorithm,
		SignatureAlgorithm: 0,
	}
}

// GetLeafCertificate returns the Certificate representation of the
// CertificateRequest, including KeyUsage and ExtKeyUsage extensions.
//
// GetLeafCertificate will not specify a SignatureAlgorithm, it's not possible
// to guarantee that the certificate signer can sign with the CertificateRequest
// SignatureAlgorithm.
func (c *CertificateRequest) GetLeafCertificate() *Certificate {
	keyUsage := x509.KeyUsageDigitalSignature
	if _, ok := c.PublicKey.(*rsa.PublicKey); ok {
		keyUsage |= x509.KeyUsageKeyEncipherment
	}

	cert := c.GetCertificate()
	cert.KeyUsage = KeyUsage(keyUsage)
	cert.ExtKeyUsage = ExtKeyUsage([]x509.ExtKeyUsage{
		x509.ExtKeyUsageServerAuth,
		x509.ExtKeyUsageClientAuth,
	})
	return cert
}

// CreateCertificateRequest creates a simple X.509 certificate request with the
// given common name and sans.
func CreateCertificateRequest(commonName string, sans []string, signer crypto.Signer) (*x509.CertificateRequest, error) {
	dnsNames, ips, emails, uris := SplitSANs(sans)
	asn1Data, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
		DNSNames:       dnsNames,
		IPAddresses:    ips,
		EmailAddresses: emails,
		URIs:           uris,
	}, signer)
	if err != nil {
		return nil, errors.Wrap(err, "error creating certificate request")
	}
	// This should not fail
	return x509.ParseCertificateRequest(asn1Data)
}

// fixSubjectAltName makes sure to mark the SAN extension to critical if the
// subject is empty.
func fixSubjectAltName(cr *x509.CertificateRequest) {
	if asn1Subject, err := asn1.Marshal(cr.Subject.ToRDNSequence()); err == nil {
		if bytes.Equal(asn1Subject, emptyASN1Subject) {
			for i, ext := range cr.Extensions {
				if ext.Id.Equal(oidExtensionSubjectAltName) {
					cr.Extensions[i].Critical = true
				}
			}
		}
	}
}
