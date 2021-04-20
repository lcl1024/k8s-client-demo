package x509

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/crypto"
	flogging "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/sdkpatch/logbridge"
)

// Errors
var (
	ErrNoPlugin = errors.New("no certificate plugin")
)

var logger = flogging.MustGetLogger("x509-stb")

// 证书插件实例，系统启动时初始化
var plugin X509

// AddPlugin 保存证书插件
func AddPlugin(p X509) error {
	logger.Infof("AddPlugin: %v", p.Name())
	if p == nil {
		return errors.New("add plugin failed with parameter is nil")
	}
	plugin = p
	return nil
}

func NewCertPool() *CertPool {
	logger.Debug("NewCertPool")
	if plugin == nil {
		logger.Error(ErrNoPlugin.Error())
		return nil
	}
	return plugin.NewCertPool()
}

func CreateCertificateRequest(rand io.Reader, template *CertificateRequest, priv interface{}) (csr []byte, err error) {
	logger.Debug("CreateCertificateRequest")
	if plugin == nil {
		AddPlugin(NewStandardCert())
	}
	return plugin.CreateCertificateRequest(rand, template, priv)
}

func ParseCertificate(asn1Data []byte) (*Certificate, error) {
	logger.Debug("ParseCertificate")
	if plugin == nil {
		return nil, ErrNoPlugin
	}
	return plugin.ParseCertificate(asn1Data)
}

func ParseCRL(crlBytes []byte) (*pkix.CertificateList, error) {
	logger.Debug("ParseCRL")
	if plugin == nil {
		return nil, ErrNoPlugin
	}
	return plugin.ParseCRL(crlBytes)
}

// DER格式转换
// 把椭圆曲线私钥转换为PCKS8标准，DER格式
func MarshalECPrivateKey(key *crypto.PrivateKey) ([]byte, error) {
	logger.Debug("MarshalECPrivateKey")

	if plugin == nil {
		return nil, ErrNoPlugin
	}
	return plugin.MarshalECPrivateKey(key)
}

// ParseECPrivateKey
func ParseECPrivateKey(der []byte) (*crypto.PrivateKey, error) {
	logger.Debug("ParseECPrivateKey")

	if plugin == nil {
		return nil, ErrNoPlugin
	}
	return plugin.ParseECPrivateKey(der)
}

// 把椭圆曲线公钥转换为PKIX标准，DER格式
func MarshalPKIXPublicKey(pub interface{}) ([]byte, error) {
	logger.Debug("MarshalPKIXPublicKey")

	if plugin == nil {
		return nil, ErrNoPlugin
	}
	return plugin.MarshalPKIXPublicKey(pub)
}

// ParsePKIXPublicKey
func ParsePKIXPublicKey(derBytes []byte) (pub interface{}, err error) {
	logger.Debug("ParsePKIXPublicKey")

	if plugin == nil {
		return nil, ErrNoPlugin
	}
	return plugin.ParsePKIXPublicKey(derBytes)
}

// 把PCKS8标准DER格式的数据转换为椭圆曲线私钥
func ParsePKCS8PrivateKey(der []byte) (key interface{}, err error) {
	logger.Debug("ParsePKCS8PrivateKey")

	if plugin == nil {
		return nil, ErrNoPlugin
	}
	return plugin.ParsePKCS8PrivateKey(der)
}

//  给标准证书库留的接口
func MarshalPKCS1PrivateKey(key *rsa.PrivateKey) []byte {
	logger.Debug("MarshalPKCS1PrivateKey")

	if plugin == nil {
		return nil
	}
	return plugin.MarshalPKCS1PrivateKey(key)
}

func ParsePKCS1PrivateKey(der []byte) (*rsa.PrivateKey, error) {
	logger.Debug("ParsePKCS1PrivateKey")

	if plugin == nil {
		return nil, ErrNoPlugin
	}
	return plugin.ParsePKCS1PrivateKey(der)
}

//  给标准证书库留的接口
func EncryptPEMBlock(rand io.Reader, blockType string, data, password []byte, alg x509.PEMCipher) (*pem.Block, error) {
	logger.Debug("EncryptPEMBlock")

	if plugin == nil {
		return nil, ErrNoPlugin
	}
	return plugin.EncryptPEMBlock(rand, blockType, data, password, alg)
}

//  给标准证书库留的接口
func IsEncryptedPEMBlock(b *pem.Block) bool {
	logger.Debug("IsEncryptedPEMBlock")

	if plugin == nil {
		logger.Error(ErrNoPlugin.Error())
		return false
	}
	return plugin.IsEncryptedPEMBlock(b)
}

//  给标准证书库留的接口
func DecryptPEMBlock(b *pem.Block, password []byte) ([]byte, error) {
	logger.Debug("DecryptPEMBlock")

	if plugin == nil {
		return nil, ErrNoPlugin
	}
	return plugin.DecryptPEMBlock(b, password)
}
