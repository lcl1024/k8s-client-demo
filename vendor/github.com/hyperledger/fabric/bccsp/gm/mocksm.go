package gm

import (
	"bytes"
	gocrypto "crypto"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	gox509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"hash"
	"io"
	"io/ioutil"
	"math/big"
	"time"

	"fmt"
	"github.com/hyperledger/fabric/crypto"
	"github.com/hyperledger/fabric/x509"
)

type mockSm2 struct{}

func (mockSm2) GenerateKey() (*crypto.PrivateKey, error) {
	privKey := crypto.PrivateKey{
		PublicKey: crypto.PublicKey{
			X:     big.NewInt(0),
			Y:     big.NewInt(0),
			Curve: elliptic.P256(),
		},
		D: big.NewInt(0),
	}
	return &privKey, nil
}

func (mockSm2) Sign(priv *crypto.PrivateKey, rand io.Reader, digest []byte, opts gocrypto.SignerOpts) ([]byte, error) {
	return digest, nil
}

// 数字签名和验证
func (mockSm2) Verify(pub *crypto.PublicKey, digest []byte, sign []byte) bool {
	return bytes.Equal(digest, sign)
}

func (mockSm2) Encrypt(pub *crypto.PublicKey, msg []byte) ([]byte, error) {
	return msg, nil
}

func (mockSm2) Decrypt(priv *crypto.PrivateKey, ciphertext []byte) ([]byte, error) {
	return ciphertext, nil
}

func (mockSm2) SavePrivateKeytoPem(fileName string, key *crypto.PrivateKey, pwd []byte) (bool, error) {
	privateKeyBytes := key.D.Bytes()
	ioutil.WriteFile(fileName, privateKeyBytes, 0600)
	return true, nil
}

func (mockSm2) LoadPrivateKeyFromPem(fileName string, pwd []byte) (*crypto.PrivateKey, error) {
	raw, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	var d big.Int
	priv := crypto.PrivateKey{
		D: d.SetBytes(raw),
	}
	return &priv, nil
}

func (mockSm2) SavePublicKeytoPem(fileName string, key *crypto.PublicKey, _ []byte) (bool, error) {
	return true, nil
}

func (mockSm2) LoadPublicKeyFromPem(fileName string, pwd []byte) (*crypto.PublicKey, error) {
	return nil, nil
}

type mockSm3 struct{}

func (mockSm3) New() hash.Hash {
	return sha256.New()
}

func (mockSm3) Sum(data []byte) []byte {
	return nil
}

type mockSm4 struct{}

func (mockSm4) NewCipher(key []byte) (cipher.Block, error) {
	return nil, nil
}

// 使用对称密钥加密和解密
func (mockSm4) Encrypt(key []byte, dst, src []byte) {
	copy(dst, src)
	return
}

func (mockSm4) Decrypt(key []byte, dst, src []byte) {
	copy(dst, src)
	return
}

// 密钥保存和加载
func (mockSm4) SaveKeyToPem(fileName string, key []byte, pwd []byte) (bool, error) {
	ioutil.WriteFile(fileName, key, 0600)
	return true, nil
}
func (mockSm4) LoadKeyFromPem(fileName string, pwd []byte) ([]byte, error) {
	return ioutil.ReadFile(fileName)
}

type mockX509 struct{}

func (mockX509) Name() string {
	return "mockX509"
}

func (mockX509) NewCertPool() *x509.CertPool {
	return nil
}

// 证书
func (mockX509) CreateCertificate(rand io.Reader, template, parent *x509.Certificate, pub, priv interface{}) (cert []byte, err error) {
	return nil, nil
}

func (mockX509) ParseCertificate(asn1Data []byte) (*x509.Certificate, error) {
	return nil, nil
}

func (mockX509) ParseCRL(crlBytes []byte) (*pkix.CertificateList, error) {
	return nil, nil
}

// DER格式转换
// 把椭圆曲线私钥转换为PCKS8标准，DER格式
func (mockX509) MarshalECPrivateKey(key *crypto.PrivateKey) ([]byte, error) {
	return nil, nil
}

func (mockX509) ParseECPrivateKey(der []byte) (*crypto.PrivateKey, error) {
	return nil, fmt.Errorf("not support")
}

// 把椭圆曲线公钥转换为PKIX标准，DER格式
func (mockX509) MarshalPKIXPublicKey(pub interface{}) ([]byte, error) {
	return []byte("MarshalPKIXPublicKey"), nil
}

func (mockX509) ParsePKIXPublicKey(derBytes []byte) (pub interface{}, err error) {
	return nil, nil
}

// 把PCKS8标准DER格式的数据转换为椭圆曲线私钥
func (mockX509) ParsePKCS8PrivateKey(der []byte) (key interface{}, err error) {
	return nil, fmt.Errorf("not support")
}

// 辅助函数，SM使用
func (mockX509) MarshalPKCS1PrivateKey(key *rsa.PrivateKey) []byte {
	return nil
}

func (mockX509) ParsePKCS1PrivateKey(der []byte) (*rsa.PrivateKey, error) {
	return nil, fmt.Errorf("not support")
}
func (mockX509) IsEncryptedPEMBlock(b *pem.Block) bool {
	return false
}
func (mockX509) EncryptPEMBlock(rand io.Reader, blockType string, data, password []byte, alg gox509.PEMCipher) (*pem.Block, error) {
	return nil, nil
}
func (mockX509) DecryptPEMBlock(b *pem.Block, password []byte) ([]byte, error) {
	return nil, nil
}

// PEM格式转换，GM使用
// 把私钥转换为加密的PEM格式
func (mockX509) PrivateKeyToEncryptedPEMBytes(privateKey interface{}, pwd []byte) ([]byte, error) {
	return nil, nil
}

// 把公钥转换为加密的PEM格式
func (mockX509) PublicKeyToEncryptedPEMBytes(publicKey interface{}, pwd []byte) ([]byte, error) {
	return nil, nil
}

// 把PEM数据转换为私钥
func (mockX509) PEMBytesToPrivateKey(raw []byte, pwd []byte) (interface{}, error) {
	return nil, nil
}

// 把PME数据转换为公钥
func (mockX509) PEMBytesToPublicKey(raw []byte, pwd []byte) (interface{}, error) {
	return nil, nil
}

// 	Certificate wrapper方法
func (mockX509) CertCheckCRLSignature(cert *x509.Certificate, crl *pkix.CertificateList) error {
	return nil
}
func (mockX509) CertCheckSignature(cert *x509.Certificate, algo x509.SignatureAlgorithm, signed, signature []byte) error {
	return nil
}
func (mockX509) CertCheckSignatureFrom(cert *x509.Certificate, parent *x509.Certificate) error {
	return nil
}
func (mockX509) CertCreateCRL(cert *x509.Certificate, rand io.Reader, priv interface{}, revokedCerts []pkix.RevokedCertificate, now, expiry time.Time) (crlBytes []byte, err error) {
	return
}
func (mockX509) CertEqual(cert *x509.Certificate, other *x509.Certificate) bool {
	return true
}
func (mockX509) CertVerify(cert *x509.Certificate, opts x509.VerifyOptions) (chains [][]*x509.Certificate, err error) {
	return
}
func (mockX509) CertVerifyHostname(cert *x509.Certificate, h string) error {
	return nil
}

// 	CertPool wrapper方法
func (mockX509) CertPoolAddCert(pool *x509.CertPool, cert *x509.Certificate) {

}
func (mockX509) CertPoolAppendCertsFromPEM(pool *x509.CertPool, pemCerts []byte) (ok bool) {
	return
}
func (mockX509) CertPoolSubjects(pool *x509.CertPool) [][]byte {
	return nil
}
