package x509

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"time"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/crypto"
)

type X509 interface {
	Name() string

	NewCertPool() *CertPool

	// 证书
	CreateCertificate(rand io.Reader, template, parent *Certificate, pub, priv interface{}) (cert []byte, err error)
	CreateCertificateRequest(rand io.Reader, template *CertificateRequest, priv interface{}) (csr []byte, err error)
	ParseCertificate(asn1Data []byte) (*Certificate, error)
	ParseCertificates(asn1Data []byte) ([]*Certificate, error)
	ParseCRL(crlBytes []byte) (*pkix.CertificateList, error)
	ParseCertificateRequest([]byte) (*CertificateRequest, error)

	// DER格式转换
	// 把椭圆曲线私钥转换为PCKS8标准，DER格式
	MarshalECPrivateKey(key *crypto.PrivateKey) ([]byte, error)
	ParseECPrivateKey(der []byte) (*crypto.PrivateKey, error)
	// 把椭圆曲线公钥转换为PKIX标准，DER格式
	MarshalPKIXPublicKey(pub interface{}) ([]byte, error)
	ParsePKIXPublicKey(derBytes []byte) (pub interface{}, err error)
	// 把PCKS8标准DER格式的数据转换为椭圆曲线私钥
	ParsePKCS8PrivateKey(der []byte) (key interface{}, err error)

	// 辅助函数，SM使用
	MarshalPKCS1PrivateKey(key *rsa.PrivateKey) []byte
	ParsePKCS1PrivateKey(der []byte) (*rsa.PrivateKey, error)
	IsEncryptedPEMBlock(b *pem.Block) bool
	EncryptPEMBlock(rand io.Reader, blockType string, data, password []byte, alg x509.PEMCipher) (*pem.Block, error)
	DecryptPEMBlock(b *pem.Block, password []byte) ([]byte, error)

	// PEM格式转换，GM使用
	// 把私钥转换为加密的PEM格式
	PrivateKeyToEncryptedPEMBytes(privateKey interface{}, pwd []byte) ([]byte, error)
	// 把公钥转换为加密的PEM格式
	PublicKeyToEncryptedPEMBytes(publicKey interface{}, pwd []byte) ([]byte, error)
	// 把PEM数据转换为私钥
	PEMBytesToPrivateKey(raw []byte, pwd []byte) (interface{}, error)
	// 把PME数据转换为公钥
	PEMBytesToPublicKey(raw []byte, pwd []byte) (interface{}, error)

	// 	Certificate wrapper方法
	CertCheckCRLSignature(cert *Certificate, crl *pkix.CertificateList) error
	CertCheckSignature(cert *Certificate, algo SignatureAlgorithm, signed, signature []byte) error
	CertCheckSignatureFrom(cert *Certificate, parent *Certificate) error
	CertCreateCRL(cert *Certificate, rand io.Reader, priv interface{}, revokedCerts []pkix.RevokedCertificate, now, expiry time.Time) (crlBytes []byte, err error)
	CertEqual(cert *Certificate, other *Certificate) bool
	CertVerify(cert *Certificate, opts VerifyOptions) (chains [][]*Certificate, err error)
	CertVerifyHostname(cert *Certificate, h string) error

	// 	CertPool wrapper方法
	CertPoolAddCert(pool *CertPool, cert *Certificate)
	CertPoolAppendCertsFromPEM(pool *CertPool, pemCerts []byte) (ok bool)
	CertPoolSubjects(pool *CertPool) [][]byte

	CheckSignature(request *CertificateRequest) error
}
