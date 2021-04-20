package x509

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"time"

	commoncrypto "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/crypto"
)

// StandardCert 标准加密证书库插件
type StandardCert struct {
}

// NewStandardCert returns a standard cert X509 plugin
func NewStandardCert() *StandardCert {
	logger.Infof("Create standard cert plugin")
	return &StandardCert{}
}

func (stdCert *StandardCert) Name() string {
	return "Go Standard Cert Plugin"
}

// NewCertPool returns a new, empty CertPool.
func (stdCert *StandardCert) NewCertPool() *CertPool {
	return toCommonCertPool(x509.NewCertPool())
}

// CreateCertificate
func (stdCert *StandardCert) CreateCertificate(rand io.Reader, template, parent *Certificate, pub, priv interface{}) (cert []byte, err error) {
	x509temp, x509parent := toGoCert(template), toGoCert(parent)
	return x509.CreateCertificate(rand, x509temp, x509parent, pub, priv)
}

func (stdCert *StandardCert) CreateCertificateRequest(rand io.Reader, template *CertificateRequest, priv interface{}) (csr []byte, err error) {
	x509temp := toGoCertRequest(template)
	return x509.CreateCertificateRequest(rand, x509temp, priv)
}

// ParseCertificate
func (stdCert *StandardCert) ParseCertificate(asn1Data []byte) (*Certificate, error) {
	c, err := x509.ParseCertificate(asn1Data)
	if err != nil {
		return nil, err
	}
	if c == nil {
		logger.Error("ParseCertificate failed. c is nil")
	}
	return toCommonCert(c), nil
}

// ParseCertificates
func (stdCert *StandardCert) ParseCertificates(asn1Data []byte) ([]*Certificate, error) {
	certs, err := x509.ParseCertificates(asn1Data)
	if err != nil {
		return nil, err
	}
	if certs == nil {
		logger.Error("ParseCertificate failed. c is nil")
	}
	var commonCerts []*Certificate
	for _, cert := range certs {
		commonCerts = append(commonCerts, toCommonCert(cert))
	}
	return commonCerts, nil
}

// ParseCertificates
func (stdCert *StandardCert) ParseCertificateRequest(asn1Data []byte) (*CertificateRequest, error) {
	certReq, err := x509.ParseCertificateRequest(asn1Data)
	if err != nil {
		return nil, err
	}
	if certReq == nil {
		logger.Error("ParseCertificate failed. c is nil")
	}
	return toCommonCertRequest(certReq), nil
}

// ParseCRL
func (stdCert *StandardCert) ParseCRL(crlBytes []byte) (*pkix.CertificateList, error) {
	return x509.ParseCRL(crlBytes)
}

// MarshalECPrivateKey
func (stdCert *StandardCert) MarshalECPrivateKey(key *commoncrypto.PrivateKey) ([]byte, error) {
	return x509.MarshalECPrivateKey(toGoPrivateKey(key))
}

// ParseECPrivateKey
func (stdCert *StandardCert) ParseECPrivateKey(der []byte) (*commoncrypto.PrivateKey, error) {
	k, err := x509.ParseECPrivateKey(der)
	if err != nil {
		return nil, err
	}
	return toCommonPrivateKey(k), nil
}

// MarshalPKIXPublicKey
func (stdCert *StandardCert) MarshalPKIXPublicKey(pub interface{}) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(pub)
}

// ParsePKIXPublicKey
func (stdCert *StandardCert) ParsePKIXPublicKey(derBytes []byte) (pub interface{}, err error) {
	return x509.ParsePKIXPublicKey(derBytes)
}

// ParsePKCS8PrivateKey
func (stdCert *StandardCert) ParsePKCS8PrivateKey(der []byte) (key interface{}, err error) {
	return x509.ParsePKCS8PrivateKey(der)
}

// MarshalPKCS1PrivateKey
func (stdCert *StandardCert) MarshalPKCS1PrivateKey(key *rsa.PrivateKey) []byte {
	return x509.MarshalPKCS1PrivateKey(key)
}

// ParsePKCS1PrivateKey
func (stdCert *StandardCert) ParsePKCS1PrivateKey(der []byte) (*rsa.PrivateKey, error) {
	return x509.ParsePKCS1PrivateKey(der)
}

// IsEncryptedPEMBlock
func (stdCert *StandardCert) IsEncryptedPEMBlock(b *pem.Block) bool {
	return x509.IsEncryptedPEMBlock(b)
}

// EncryptPEMBlock
func (stdCert *StandardCert) EncryptPEMBlock(rand io.Reader, blockType string, data, password []byte, alg x509.PEMCipher) (*pem.Block, error) {
	return x509.EncryptPEMBlock(rand, blockType, data, password, alg)
}

// DecryptPEMBlock
func (stdCert *StandardCert) DecryptPEMBlock(b *pem.Block, password []byte) ([]byte, error) {
	return x509.DecryptPEMBlock(b, password)
}

// Go标准库并没有实现密钥和PEM的转换，以下4个函数来自fabric/bccsp模块的原生实现
// PrivateKeyToEncryptedPEMBytes
func (stdCert *StandardCert) PrivateKeyToEncryptedPEMBytes(privateKey interface{}, pwd []byte) ([]byte, error) {
	// 标准加密证书实际不走这里
	return nil, errors.New("standard cert plugin not support this function")
}

// PublicKeyToEncryptedPEMBytes
func (stdCert *StandardCert) PublicKeyToEncryptedPEMBytes(publicKey interface{}, pwd []byte) ([]byte, error) {
	return nil, errors.New("standard cert plugin not support this function")
}

// PEMBytesToPrivateKey
func (stdCert *StandardCert) PEMBytesToPrivateKey(raw []byte, pwd []byte) (interface{}, error) {
	return nil, errors.New("standard cert plugin not support this function")
}

// PEMBytesToPublicKey
func (stdCert *StandardCert) PEMBytesToPublicKey(raw []byte, pwd []byte) (interface{}, error) {
	return nil, errors.New("standard cert plugin not support this function")
}

// CertCheckCRLSignature
func (stdCert *StandardCert) CertCheckCRLSignature(cert *Certificate, crl *pkix.CertificateList) error {
	crt := toGoCert(cert)
	return crt.CheckCRLSignature(crl)
}

// CertCheckSignature
func (stdCert *StandardCert) CertCheckSignature(cert *Certificate, algo SignatureAlgorithm, signed, signature []byte) error {
	crt := toGoCert(cert)
	return crt.CheckSignature(toGoSigAlg(algo), signed, signature)
}

// CertCheckSignatureFrom
func (stdCert *StandardCert) CertCheckSignatureFrom(cert *Certificate, parent *Certificate) error {
	crt := toGoCert(cert)
	par := toGoCert(parent)
	return crt.CheckSignatureFrom(par)
}

// CertCreateCRL
func (stdCert *StandardCert) CertCreateCRL(cert *Certificate, rand io.Reader, priv interface{}, revokedCerts []pkix.RevokedCertificate, now, expiry time.Time) (crlBytes []byte, err error) {
	crt := toGoCert(cert)
	return crt.CreateCRL(rand, priv, revokedCerts, now, expiry)
}

// CertEqual
func (stdCert *StandardCert) CertEqual(cert *Certificate, other *Certificate) bool {
	crt := toGoCert(cert)
	oh := toGoCert(other)
	return crt.Equal(oh)
}

// CertVerify
func (stdCert *StandardCert) CertVerify(cert *Certificate, opts VerifyOptions) (chains [][]*Certificate, err error) {
	crt := toGoCert(cert)
	cs, err := crt.Verify(*toGoVerifyOpts(&opts))
	if err != nil {
		return nil, err
	}
	return toCommonCertLists(cs), nil
}

// CertVerifyHostname
func (stdCert *StandardCert) CertVerifyHostname(cert *Certificate, h string) error {
	crt := toGoCert(cert)
	return crt.VerifyHostname(h)
}

// CertPoolAddCert
func (stdCert *StandardCert) CertPoolAddCert(pool *CertPool, cert *Certificate) {
	crt := toGoCert(cert)
	cp := toGoCertPool(pool)
	cp.AddCert(crt)
}

// CertPoolAppendCertsFromPEM
func (stdCert *StandardCert) CertPoolAppendCertsFromPEM(pool *CertPool, pemCerts []byte) (ok bool) {
	cp := toGoCertPool(pool)
	return cp.AppendCertsFromPEM(pemCerts)
}

// CertPoolSubjects
func (stdCert *StandardCert) CertPoolSubjects(pool *CertPool) [][]byte {
	cp := toGoCertPool(pool)
	return cp.Subjects()
}

func (stdCert *StandardCert) CheckSignature(request *CertificateRequest) error {
	cq := toGoCertRequest(request)
	return cq.CheckSignature()
}
