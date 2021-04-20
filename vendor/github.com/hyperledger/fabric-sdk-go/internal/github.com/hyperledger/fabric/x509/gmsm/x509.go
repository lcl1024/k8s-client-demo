package gmsm

import (
	gocrypto "crypto"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"time"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/crypto"
	flogging "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/sdkpatch/logbridge"
	commonX509 "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/x509"
	"github.com/tjfoc/gmsm/sm2"
)

/**
 * @Author: eggsy
 * @Description:
 * @File:  x509
 * @Version: 1.0.0
 * @Date: 4/21/20 1:08 下午
 */
var logger = flogging.MustGetLogger("gmsm.x509")

type X509 struct {
}

func NewX509() *X509 {
	return &X509{}
}

func (gmX509 *X509) Name() string {
	return "GMSM Cert Plugin"
}

func (gmX509 *X509) NewCertPool() *commonX509.CertPool {
	pool := sm2.NewCertPool()
	return toCommonCertPool(pool)
}

// 证书
func (gmX509 *X509) CreateCertificate(rand io.Reader, template, parent *commonX509.Certificate, pub, priv interface{}) (cert []byte, err error) {
	tem, par := toGmCert(template), toGmCert(parent)
	pubkey := toSm2PublicKey(pub.(*crypto.PublicKey))
	return sm2.CreateCertificate(rand, tem, par, pubkey, newSm2Signer(priv.(gocrypto.Signer)))
}

func (gmX509 *X509) CreateCertificateRequest(rand io.Reader, template *commonX509.CertificateRequest, priv interface{}) (cert []byte, err error) {
	tem := toGmCertRequest(template)
	return sm2.CreateCertificateRequest(rand, tem, newSm2Signer(priv.(gocrypto.Signer)))
}

func (gmX509 *X509) ParseCertificate(asn1Data []byte) (*commonX509.Certificate, error) {
	cert, err := sm2.ParseCertificate(asn1Data)
	if err != nil {
		logger.Errorf("failed to parse certificate. err: %v", err)
		return nil, err
	}
	return toCommonCert(cert), err
}

func (gmX509 *X509) ParseCertificates(asn1Data []byte) ([]*commonX509.Certificate, error) {
	certs, err := sm2.ParseCertificates(asn1Data)
	if err != nil {
		logger.Errorf("failed to parse certificate. err: %v", err)
		return nil, err
	}
	var certsList []*commonX509.Certificate
	for _, cert := range certs {
		certsList = append(certsList, toCommonCert(cert))
	}
	return certsList, err
}

func (gmX509 *X509) ParseCertificateRequest(asn1Data []byte) (*commonX509.CertificateRequest, error) {
	certReq, err := sm2.ParseCertificateRequest(asn1Data)
	if err != nil {
		logger.Errorf("failed to parse certificate. err: %v", err)
		return nil, err
	}
	return toCommonCertRequest(certReq), err
}

func (gmX509 *X509) ParseCRL(crlBytes []byte) (*pkix.CertificateList, error) {
	certList, err := sm2.ParseCRL(crlBytes)
	if err != nil {
		logger.Errorf("failed to parse certificate revocation list. err: %v", err)
		return nil, err
	}
	return certList, err
}

// DER格式转换
// 把椭圆曲线私钥转换为PCKS8标准，DER格式
// TODO: 该接口不确定，默默参考了下同济的fabric调用gossip/comm/crypto.go 81行
func (gmX509 *X509) MarshalECPrivateKey(key *crypto.PrivateKey) ([]byte, error) {
	privKey := toSm2PrivateKey(key)
	return sm2.MarshalSm2PrivateKey(privKey, nil)
}

// TODO.不知道ParseSm2PrivateKey为啥无法解析(测试sm2自带接口，确定无法解析)。但是ParsePKCS8PrivateKey可以解析
func (gmX509 *X509) ParseECPrivateKey(der []byte) (*crypto.PrivateKey, error) {
	//privKey, err := sm2.ParseSm2PrivateKey(der)
	privKey, err := sm2.ParsePKCS8PrivateKey(der, nil)
	if err != nil {
		logger.Errorf("failed to parse sm2 privateKey. err: %v", err)
		return nil, err
	}
	return toCryptoPrivateKey(privKey), nil
}

// 把椭圆曲线公钥转换为PKIX标准，DER格式
// TODO: 由于ParsePKIXPublicKey,不支持sm2类型公钥,在此修改成直接序列化/反序列化sm2.PublicKey
func (gmX509 *X509) MarshalPKIXPublicKey(pub interface{}) ([]byte, error) {
	key := pub.(*crypto.PublicKey)
	return sm2.MarshalSm2PublicKey(toSm2PublicKey(key))
	//return sm2.MarshalPKIXPublicKey(pub)
}

func (gmX509 *X509) ParsePKIXPublicKey(derBytes []byte) (interface{}, error) {
	//pubkey, err := sm2.ParsePKIXPublicKey(derBytes)
	pubKey, err := sm2.ParseSm2PublicKey(derBytes)
	if err != nil {
		logger.Errorf("failed to parse PKIX publicKey. err: %v", err)
		return nil, err
	}
	return toCryptoPublicKey(pubKey), nil
}

// 把PCKS8标准DER格式的数据转换为椭圆曲线私钥
func (gmX509 *X509) ParsePKCS8PrivateKey(der []byte) (interface{}, error) {
	key, err := sm2.ParsePKCS8PrivateKey(der, nil)
	if err != nil {
		logger.Errorf("failed to parse PKCS8 privateKey. err: %v", err)
		return nil, err
	}
	return toCryptoPrivateKey(key), nil
}

func (gmX509 *X509) MarshalPKCS1PrivateKey(key *rsa.PrivateKey) []byte {
	return sm2.MarshalPKCS1PrivateKey(key)
}

func (gmX509 *X509) ParsePKCS1PrivateKey(der []byte) (*rsa.PrivateKey, error) {
	return sm2.ParsePKCS1PrivateKey(der)
}

// 以下三个方法gmsm未实现
func (gmX509 *X509) IsEncryptedPEMBlock(b *pem.Block) bool {
	return x509.IsEncryptedPEMBlock(b)
}
func (gmX509 *X509) EncryptPEMBlock(rand io.Reader, blockType string, data, password []byte, alg x509.PEMCipher) (*pem.Block, error) {
	return x509.EncryptPEMBlock(rand, blockType, data, password, alg)
}
func (gmX509 *X509) DecryptPEMBlock(b *pem.Block, password []byte) ([]byte, error) {
	return x509.DecryptPEMBlock(b, password)
}

// PEM格式转换
// 把私钥转换为加密的PEM格式
func (gmX509 *X509) PrivateKeyToEncryptedPEMBytes(privateKey interface{}, pwd []byte) ([]byte, error) {
	key := toSm2PrivateKey(privateKey.(*crypto.PrivateKey))
	return sm2.WritePrivateKeytoMem(key, pwd)
}

// 把公钥转换为加密的PEM格式
func (gmX509 *X509) PublicKeyToEncryptedPEMBytes(publicKey interface{}, pwd []byte) ([]byte, error) {
	key := toSm2PublicKey(publicKey.(*crypto.PublicKey))
	return sm2.WritePublicKeytoMem(key, pwd)
}

// 把PEM数据转换为私钥
func (gmX509 *X509) PEMBytesToPrivateKey(raw []byte, pwd []byte) (interface{}, error) {
	key, err := sm2.ReadPrivateKeyFromMem(raw, pwd)
	if err != nil {
		logger.Errorf("failed to read privateKey from mem. err: %v", err)
		return nil, err
	}
	return toCryptoPrivateKey(key), nil
}

// 把PME数据转换为公钥
func (gmX509 *X509) PEMBytesToPublicKey(raw []byte, pwd []byte) (interface{}, error) {
	key, err := sm2.ReadPublicKeyFromMem(raw, pwd)
	if err != nil {
		logger.Errorf("failed to read publicKey from mem. err: %v", err)
		return nil, err
	}
	return toCryptoPublicKey(key), nil
}

// 	Certificate wrapper方法
func (gmX509 *X509) CertCheckCRLSignature(certificate *commonX509.Certificate, crl *pkix.CertificateList) error {
	cert := toGmCert(certificate)
	return cert.CheckCRLSignature(crl)
}

func (gmX509 *X509) CertCheckSignature(certificate *commonX509.Certificate, algo commonX509.SignatureAlgorithm, signed, signature []byte) error {
	cert := toGmCert(certificate)
	algorithm := toSm2SignatureAlgorithm(&algo)
	return cert.CheckSignature(*algorithm, signed, signature)
}

func (gmX509 *X509) CertCheckSignatureFrom(certificate *commonX509.Certificate, parent *commonX509.Certificate) error {
	cert := toGmCert(certificate)
	parentCert := toGmCert(parent)
	return cert.CheckSignatureFrom(parentCert)
}

func (gmX509 *X509) CertCreateCRL(certificate *commonX509.Certificate, rand io.Reader, priv interface{}, revokedCerts []pkix.RevokedCertificate, now, expiry time.Time) (crlBytes []byte, err error) {
	cert := toGmCert(certificate)
	switch priv.(type) {
	case *crypto.PrivateKey:
		priv = toSm2PrivateKey(priv.(*crypto.PrivateKey))
	case gocrypto.Signer:
		priv = newSm2Signer(priv.(gocrypto.Signer))
	}
	return cert.CreateCRL(rand, priv, revokedCerts, now, expiry)
}

func (gmX509 *X509) CertEqual(certificate *commonX509.Certificate, otherCertificate *commonX509.Certificate) bool {
	cert := toGmCert(certificate)
	other := toGmCert(otherCertificate)
	return cert.Equal(other)
}

func (gmX509 *X509) CertVerify(certificate *commonX509.Certificate, opts commonX509.VerifyOptions) (chains [][]*commonX509.Certificate, err error) {
	cert := toGmCert(certificate)
	options := toGmVerifyOpts(&opts)
	gmChains, err := cert.Verify(*options)
	if err != nil {
		logger.Errorf("failed to verify options. err: %v", err)
		return nil, err
	}
	var row = len(gmChains)
	if row == 0 {
		return nil, nil
	}
	var col = len(gmChains[0])
	chains = make([][]*commonX509.Certificate, row)
	for i := 0; i < row; i++ {
		chains[i] = make([]*commonX509.Certificate, col)
		for j := 0; j < col; j++ {
			chains[i][j] = toCommonCert(gmChains[i][j])
		}
	}
	return chains, err
}

func (gmX509 *X509) CertVerifyHostname(certificate *commonX509.Certificate, h string) error {
	cert := toGmCert(certificate)
	return cert.VerifyHostname(h)
}

// 	CertPool wrapper方法
func (gmX509 *X509) CertPoolAddCert(certPool *commonX509.CertPool, certificate *commonX509.Certificate) {
	pool := toGmCertPool(certPool)
	cert := toGmCert(certificate)
	pool.AddCert(cert)
}

func (gmX509 *X509) CertPoolAppendCertsFromPEM(certPool *commonX509.CertPool, pemCerts []byte) (ok bool) {
	pool := toGmCertPool(certPool)
	return pool.AppendCertsFromPEM(pemCerts)
}

func (gmX509 *X509) CertPoolSubjects(certPool *commonX509.CertPool) [][]byte {
	pool := toGmCertPool(certPool)
	return pool.Subjects()
}

func (gmX509 *X509) CheckSignature(request *commonX509.CertificateRequest) error {
	sm2Req := toGmCertRequest(request)
	return sm2Req.CheckSignature()
}
