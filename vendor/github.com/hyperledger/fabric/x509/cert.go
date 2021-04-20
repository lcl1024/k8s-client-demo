package x509

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"math/big"
	"net"
	"net/url"
	"time"
)

type SignatureAlgorithm int

const (
	UnknownSignatureAlgorithm SignatureAlgorithm = iota
	MD2WithRSA
	MD5WithRSA
	//	SM3WithRSA reserve
	SHA1WithRSA
	SHA256WithRSA
	SHA384WithRSA
	SHA512WithRSA
	DSAWithSHA1
	DSAWithSHA256
	ECDSAWithSHA1
	ECDSAWithSHA256
	ECDSAWithSHA384
	ECDSAWithSHA512
	SHA256WithRSAPSS
	SHA384WithRSAPSS
	SHA512WithRSAPSS
	SM2WithSM3
	SM2WithSHA1
	SM2WithSHA256
)

type PublicKeyAlgorithm int

const (
	UnknownPublicKeyAlgorithm PublicKeyAlgorithm = iota
	RSA
	DSA
	ECDSA
)

// A Certificate represents an X.509 certificate.
type Certificate struct {
	Raw                     []byte // Complete ASN.1 DER content (certificate, signature algorithm and signature).
	RawTBSCertificate       []byte // Certificate part of raw ASN.1 DER content.
	RawSubjectPublicKeyInfo []byte // DER encoded SubjectPublicKeyInfo.
	RawSubject              []byte // DER encoded Subject
	RawIssuer               []byte // DER encoded Issuer

	Signature          []byte
	SignatureAlgorithm SignatureAlgorithm

	PublicKeyAlgorithm PublicKeyAlgorithm
	PublicKey          interface{}

	Version             int
	SerialNumber        *big.Int
	Issuer              pkix.Name
	Subject             pkix.Name
	NotBefore, NotAfter time.Time // Validity bounds.
	KeyUsage            KeyUsage

	// Extensions contains raw X.509 extensions. When parsing certificates,
	// this can be used to extract non-critical extensions that are not
	// parsed by this package. When marshaling certificates, the Extensions
	// field is ignored, see ExtraExtensions.
	Extensions []pkix.Extension

	// ExtraExtensions contains extensions to be copied, raw, into any
	// marshaled certificates. Values override any extensions that would
	// otherwise be produced based on the other fields. The ExtraExtensions
	// field is not populated when parsing certificates, see Extensions.
	ExtraExtensions []pkix.Extension

	// UnhandledCriticalExtensions contains a list of extension IDs that
	// were not (fully) processed when parsing. Verify will fail if this
	// slice is non-empty, unless verification is delegated to an OS
	// library which understands all the critical extensions.
	//
	// Users can access these extensions using Extensions and can remove
	// elements from this slice if they believe that they have been
	// handled.
	UnhandledCriticalExtensions []asn1.ObjectIdentifier

	ExtKeyUsage        []ExtKeyUsage           // Sequence of extended key usages.
	UnknownExtKeyUsage []asn1.ObjectIdentifier // Encountered extended key usages unknown to this package.

	// BasicConstraintsValid indicates whether IsCA, MaxPathLen,
	// and MaxPathLenZero are valid.
	BasicConstraintsValid bool
	IsCA                  bool

	// MaxPathLen and MaxPathLenZero indicate the presence and
	// value of the BasicConstraints' "pathLenConstraint".
	//
	// When parsing a certificate, a positive non-zero MaxPathLen
	// means that the field was specified, -1 means it was unset,
	// and MaxPathLenZero being true mean that the field was
	// explicitly set to zero. The case of MaxPathLen==0 with MaxPathLenZero==false
	// should be treated equivalent to -1 (unset).
	//
	// When generating a certificate, an unset pathLenConstraint
	// can be requested with either MaxPathLen == -1 or using the
	// zero value for both MaxPathLen and MaxPathLenZero.
	MaxPathLen int
	// MaxPathLenZero indicates that BasicConstraintsValid==true
	// and MaxPathLen==0 should be interpreted as an actual
	// maximum path length of zero. Otherwise, that combination is
	// interpreted as MaxPathLen not being set.
	MaxPathLenZero bool

	SubjectKeyId   []byte
	AuthorityKeyId []byte

	// RFC 5280, 4.2.2.1 (Authority Information Access)
	OCSPServer            []string
	IssuingCertificateURL []string

	// Subject Alternate Name values. (Note that these values may not be valid
	// if invalid values were contained within a parsed certificate. For
	// example, an element of DNSNames may not be a valid DNS domain name.)
	DNSNames       []string
	EmailAddresses []string
	IPAddresses    []net.IP
	URIs           []*url.URL

	// Name constraints
	PermittedDNSDomainsCritical bool // if true then the name constraints are marked critical.
	PermittedDNSDomains         []string
	ExcludedDNSDomains          []string
	PermittedIPRanges           []*net.IPNet
	ExcludedIPRanges            []*net.IPNet
	PermittedEmailAddresses     []string
	ExcludedEmailAddresses      []string
	PermittedURIDomains         []string
	ExcludedURIDomains          []string

	// CRL Distribution Points
	CRLDistributionPoints []string

	PolicyIdentifiers []asn1.ObjectIdentifier
}

// CertificateRequest represents a PKCS #10, certificate signature request.
type CertificateRequest struct {
	Raw                      []byte // Complete ASN.1 DER content (CSR, signature algorithm and signature).
	RawTBSCertificateRequest []byte // Certificate request info part of raw ASN.1 DER content.
	RawSubjectPublicKeyInfo  []byte // DER encoded SubjectPublicKeyInfo.
	RawSubject               []byte // DER encoded Subject.

	Version            int
	Signature          []byte
	SignatureAlgorithm SignatureAlgorithm

	PublicKeyAlgorithm PublicKeyAlgorithm
	PublicKey          interface{}

	Subject pkix.Name

	// Attributes contains the CSR attributes that can parse as
	// pkix.AttributeTypeAndValueSET.
	//
	// Deprecated: Use Extensions and ExtraExtensions instead for parsing and
	// generating the requestedExtensions attribute.
	Attributes []pkix.AttributeTypeAndValueSET

	// Extensions contains all requested extensions, in raw form. When parsing
	// CSRs, this can be used to extract extensions that are not parsed by this
	// package.
	Extensions []pkix.Extension

	// ExtraExtensions contains extensions to be copied, raw, into any CSR
	// marshaled by CreateCertificateRequest. Values override any extensions
	// that would otherwise be produced based on the other fields but are
	// overridden by any extensions specified in Attributes.
	//
	// The ExtraExtensions field is not populated by ParseCertificateRequest,
	// see Extensions instead.
	ExtraExtensions []pkix.Extension

	// Subject Alternate Name values.
	DNSNames       []string
	EmailAddresses []string
	IPAddresses    []net.IP
	URIs           []*url.URL
}

// CheckCRLSignature wrapper to plugin
func (c *Certificate) CheckCRLSignature(crl *pkix.CertificateList) error {
	if plugin == nil {
		AddPlugin(NewStandardCert())
	}

	return plugin.CertCheckCRLSignature(c, crl)
}

// CheckSignature wrapper to plugin
func (c *Certificate) CheckSignature(algo SignatureAlgorithm, signed, signature []byte) error {
	if plugin == nil {
		AddPlugin(NewStandardCert())
	}

	return plugin.CertCheckSignature(c, algo, signed, signature)
}

// CheckSignatureFrom wrapper to plugin
func (c *Certificate) CheckSignatureFrom(parent *Certificate) error {
	if plugin == nil {
		AddPlugin(NewStandardCert())
	}

	return plugin.CertCheckSignatureFrom(c, parent)
}

// CreateCRL wrapper to plugin
func (c *Certificate) CreateCRL(rand io.Reader, priv interface{}, revokedCerts []pkix.RevokedCertificate, now, expiry time.Time) (crlBytes []byte, err error) {
	if plugin == nil {
		AddPlugin(NewStandardCert())
	}

	return plugin.CertCreateCRL(c, rand, priv, revokedCerts, now, expiry)
}

// Equal wrapper to plugin
func (c *Certificate) Equal(other *Certificate) bool {
	if plugin == nil {
		AddPlugin(NewStandardCert())
	}

	return plugin.CertEqual(c, other)
}

// Verify wrapper to plugin
func (c *Certificate) Verify(opts VerifyOptions) (chains [][]*Certificate, err error) {
	if plugin == nil {
		AddPlugin(NewStandardCert())
	}

	return plugin.CertVerify(c, opts)
}

// VerifyHostname wrapper to plugin
func (c *Certificate) VerifyHostname(h string) error {
	if plugin == nil {
		AddPlugin(NewStandardCert())
	}

	return plugin.CertVerifyHostname(c, h)
}

// CertPool is a set of certificates.
type CertPool struct {
	bySubjectKeyId map[string][]int
	byName         map[string][]int
	certs          []*Certificate
}

// AddCert adds a certificate to a pool.
// Wrapper
func (p *CertPool) AddCert(cert *Certificate) {
	if plugin == nil {
		AddPlugin(NewStandardCert())
	}

	plugin.CertPoolAddCert(p, cert)
}

// AppendCertsFromPEM wrapper to plugin
func (p *CertPool) AppendCertsFromPEM(pemCerts []byte) (ok bool) {
	if plugin == nil {
		AddPlugin(NewStandardCert())
		return false
	}

	return plugin.CertPoolAppendCertsFromPEM(p, pemCerts)
}

// Subjects wrapper to plugin
func (p *CertPool) Subjects() [][]byte {
	if plugin == nil {
		AddPlugin(NewStandardCert())
		return nil
	}

	return plugin.CertPoolSubjects(p)
}

// VerifyOptions contains parameters for Certificate.Verify. It's a structure
// because other PKIX verification APIs have ended up needing many options.
type VerifyOptions struct {
	DNSName       string
	Intermediates *CertPool
	Roots         *CertPool // if nil, the system roots are used
	CurrentTime   time.Time // if zero, the current time is used
	// KeyUsage specifies which Extended Key Usage values are acceptable. A leaf
	// certificate is accepted if it contains any of the listed values. An empty
	// list means ExtKeyUsageServerAuth. To accept any key usage, include
	// ExtKeyUsageAny.
	//
	// Certificate chains are required to nest these extended key usage values.
	// (This matches the Windows CryptoAPI behavior, but not the spec.)
	KeyUsages []ExtKeyUsage
	// MaxConstraintComparisions is the maximum number of comparisons to
	// perform when checking a given certificate's name constraints. If
	// zero, a sensible default is used. This limit prevents pathological
	// certificates from consuming excessive amounts of CPU time when
	// validating.
	MaxConstraintComparisions int
}

// KeyUsage represents the set of actions that are valid for a given key. It's
// a bitmap of the KeyUsage* constants.
type KeyUsage int

const (
	KeyUsageDigitalSignature KeyUsage = 1 << iota
	KeyUsageContentCommitment
	KeyUsageKeyEncipherment
	KeyUsageDataEncipherment
	KeyUsageKeyAgreement
	KeyUsageCertSign
	KeyUsageCRLSign
	KeyUsageEncipherOnly
	KeyUsageDecipherOnly
)

// ExtKeyUsage represents an extended set of actions that are valid for a given key.
// Each of the ExtKeyUsage* constants define a unique action.
type ExtKeyUsage int

const (
	ExtKeyUsageAny ExtKeyUsage = iota
	ExtKeyUsageServerAuth
	ExtKeyUsageClientAuth
	ExtKeyUsageCodeSigning
	ExtKeyUsageEmailProtection
	ExtKeyUsageIPSECEndSystem
	ExtKeyUsageIPSECTunnel
	ExtKeyUsageIPSECUser
	ExtKeyUsageTimeStamping
	ExtKeyUsageOCSPSigning
	ExtKeyUsageMicrosoftServerGatedCrypto
	ExtKeyUsageNetscapeServerGatedCrypto
)
