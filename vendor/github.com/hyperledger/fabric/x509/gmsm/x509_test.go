package gmsm

import (
	"crypto/rand"
	"crypto/rsa"
	cryptoX509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/scan/crypto/sha1"
	"github.com/hyperledger/fabric/crypto"
	"github.com/hyperledger/fabric/gm/gmsm"
	"github.com/hyperledger/fabric/x509"
	"github.com/stretchr/testify/assert"
)

/**
 * @Author: eggsy
 * @Description:
 * @File:  x509_test
 * @Version: 1.0.0
 * @Date: 4/21/20 3:39 下午
 */

func TestNewX509(t *testing.T) {
	X509 := NewX509()
	assert.NotNil(t, X509)
}

func TestX509_NewCertPool(t *testing.T) {
	X509 := NewX509()
	pool := X509.NewCertPool()
	assert.NotNil(t, pool)
}

// 测试创建证书并保存
func TestX509_CreateCertificate(t *testing.T) {
	X509 := NewX509()
	commonName := "test.example.com"
	testExtKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	testUnknownExtKeyUsage := []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}}
	extraExtensionData := []byte("extra extension")
	template := x509.Certificate{
		// SerialNumber is negative to ensure that negative
		// values are parsed. This is due to the prevalence of
		// buggy code that produces certificates with negative
		// serial numbers.
		SerialNumber: big.NewInt(-1),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"TEST"},
			Country:      []string{"China"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  []int{2, 5, 4, 42},
					Value: "Gopher",
				},
				// This should override the Country, above.
				{
					Type:  []int{2, 5, 4, 6},
					Value: "NL",
				},
			},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(10, 0, 0),

		//		SignatureAlgorithm: ECDSAWithSHA256,
		SignatureAlgorithm: x509.SM2WithSM3,

		SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage:     x509.KeyUsageCertSign,

		ExtKeyUsage:        testExtKeyUsage,
		UnknownExtKeyUsage: testUnknownExtKeyUsage,

		BasicConstraintsValid: true,
		IsCA:                  true,

		OCSPServer:            []string{"http://ocsp.example.com"},
		IssuingCertificateURL: []string{"http://crt.example.com/ca1.crt"},

		DNSNames:       []string{"test.example.com"},
		EmailAddresses: []string{"gopher@golang.org"},
		IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},

		PolicyIdentifiers:   []asn1.ObjectIdentifier{[]int{1, 2, 3}},
		PermittedDNSDomains: []string{".example.com", "example.com"},

		CRLDistributionPoints: []string{"http://crl1.example.com/ca1.crl", "http://crl2.example.com/ca1.crl"},

		ExtraExtensions: []pkix.Extension{
			{
				Id:    []int{1, 2, 3, 4},
				Value: extraExtensionData,
			},
			// This extension should override the SubjectKeyId, above.
			{
				Id:       []int{2, 5, 29, 14},
				Critical: false,
				Value:    []byte{0x04, 0x04, 4, 3, 2, 1},
			},
		},
	}
	SM2 := gmsm.NewSm2()
	privKey, _ := SM2.GenerateKey()
	// 1. test CreateCertificate
	priv := toSm2PrivateKey(privKey)
	certBytes, err := X509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, priv)
	assert.NoError(t, err)
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}
	file, _ := os.Create("cert.pem")
	defer file.Close()
	err = pem.Encode(file, block)
	assert.NoError(t, err)
	// 2. test ParseCertificate
	cert, err := X509.ParseCertificate(block.Bytes)
	// 3. test CertCheckSignatureFrom
	err = X509.CertCheckSignatureFrom(cert, cert)
	assert.NoError(t, err)
	// 4. test CertVerifyHostname
	err = X509.CertVerifyHostname(cert, "test.example.com")
	assert.NoError(t, err)
	pool := X509.NewCertPool()
	// 5. test CertPoolAddCert
	X509.CertPoolAddCert(pool, cert)
	opts := x509.VerifyOptions{
		DNSName:   "test.example.com",
		Roots:     pool,
		KeyUsages: testExtKeyUsage,
	}
	// 6. test CertVerify
	_, err = X509.CertVerify(cert, opts)
	assert.NoError(t, err)
	// 7. test CertPoolSubjects
	res := X509.CertPoolSubjects(pool)
	assert.True(t, string(res[0]) == string(cert.RawSubject))
	// 8. test CertCheckSignature
	err = X509.CertCheckSignature(cert, cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	assert.NoError(t, err)
	// 9. test CertCreateCRL
	now := time.Now()
	expiry := time.Now().AddDate(10, 0, 0)
	revokedCerts := []pkix.RevokedCertificate{
		{
			SerialNumber:   big.NewInt(1),
			RevocationTime: now,
		},
		{
			SerialNumber:   big.NewInt(42),
			RevocationTime: now,
		},
	}
	crlBytes, err := X509.CertCreateCRL(cert, rand.Reader, privKey, revokedCerts, now, expiry)
	assert.NoError(t, err)
	// 10. test ParseCRL
	crl, _ := X509.ParseCRL(crlBytes)
	// 11. test CertCheckCRLSignature
	err = X509.CertCheckCRLSignature(cert, crl)
	assert.NoError(t, err)
	// 12. test CertPoolAppendCertsFromPEM
	// 保存证书
	bytes, _ := ioutil.ReadFile("cert.pem")
	flag := X509.CertPoolAppendCertsFromPEM(pool, bytes)
	assert.True(t, flag)

}

func TestX509_MarshalPKCS1PrivateKeyAndParsePKCS1PrivateKey(t *testing.T) {
	size := 1024
	privKey, err := rsa.GenerateKey(rand.Reader, size)
	assert.NoError(t, err)
	// Marshal
	X509 := NewX509()
	keybytes := X509.MarshalPKCS1PrivateKey(privKey)
	key, _ := X509.ParsePKCS1PrivateKey(keybytes)
	// 用privkey公钥加密，key解密
	sha := sha1.New()
	var plainData = []byte("this is test data")
	ciperdata, err := rsa.EncryptOAEP(sha, rand.Reader, &privKey.PublicKey, plainData, nil)
	assert.NoError(t, err)
	data, err := rsa.DecryptOAEP(sha, rand.Reader, key, ciperdata, nil)
	assert.NoError(t, err)
	assert.True(t, string(plainData) == string(data))
}

func TestX509_MarshalAndParseECPrivateKey(t *testing.T) {
	// 测试gmsm sm2	自己实现的Marshal和Parse不通过
	//priv, _ := sm2.GenerateKey()
	//bytes, err := sm2.MarshalSm2PrivateKey(priv, nil)
	//assert.NoError(t, err)
	//_, err = sm2.ParseSm2PrivateKey(bytes)
	//assert.NoError(t, err)
	X509 := NewX509()
	Sm2 := gmsm.NewSm2()
	privKey, err := Sm2.GenerateKey()
	assert.NoError(t, err)
	pemByte, err := X509.MarshalECPrivateKey(privKey)
	assert.NoError(t, err)
	privKey2, err := X509.ParseECPrivateKey(pemByte)
	assert.NoError(t, err)
	// 也不知道怎么测试，privKey2的公钥加密，看看privKey能否解密
	var plainData = "this is test data"
	ciperData, err := Sm2.Encrypt(&privKey2.PublicKey, []byte(plainData))
	assert.NoError(t, err)
	data, err := Sm2.Decrypt(privKey, ciperData)
	assert.NoError(t, err)
	assert.True(t, string(data) == plainData)
}

func TestX509_MarshalAndParsePKIXPublicKey(t *testing.T) {
	Sm2 := gmsm.NewSm2()
	privKey, err := Sm2.GenerateKey()
	assert.NoError(t, err)
	pub := &privKey.PublicKey
	X509 := NewX509()
	bytes, err := X509.MarshalPKIXPublicKey(pub)
	assert.NoError(t, err)
	pubKey, err := X509.ParsePKIXPublicKey(bytes)
	assert.NoError(t, err)
	// 也不知道怎么测试，pubKey的公钥加密，看看privKey能否解密
	var plainData = "this is test data"
	ciperData, err := Sm2.Encrypt(pubKey.(*crypto.PublicKey), []byte(plainData))
	assert.NoError(t, err)
	data, err := Sm2.Decrypt(privKey, ciperData)
	assert.NoError(t, err)
	assert.True(t, string(data) == plainData)
}

func TestX509_PublicKeyToEncryptedPEMBytesAndPEMBytesToPublicKey(t *testing.T) {
	X509 := NewX509()
	Sm2 := gmsm.NewSm2()
	privKey, err := Sm2.GenerateKey()
	assert.NoError(t, err)
	pubKey := privKey.PublicKey
	pemByte, err := X509.PublicKeyToEncryptedPEMBytes(&pubKey, nil)
	assert.NoError(t, err)
	pubKey2, err := X509.PEMBytesToPublicKey(pemByte, nil)
	assert.NoError(t, err)
	// 也不知道怎么测试，用pubKey2加密，看看privKey能否解密
	var plainData = "this is test data"
	ciperData, err := Sm2.Encrypt(pubKey2.(*crypto.PublicKey), []byte(plainData))
	assert.NoError(t, err)
	data, err := Sm2.Decrypt(privKey, ciperData)
	assert.NoError(t, err)
	assert.True(t, string(data) == plainData)
}

func TestX509_PrivateKeyToEncryptedPEMBytesAndPEMBytesToPrivatecKey(t *testing.T) {
	X509 := NewX509()
	Sm2 := gmsm.NewSm2()
	privKey, err := Sm2.GenerateKey()
	assert.NoError(t, err)
	pemBytes, err := X509.PrivateKeyToEncryptedPEMBytes(privKey, nil)
	assert.NoError(t, err)
	privKey2, err := X509.PEMBytesToPrivateKey(pemBytes, nil)
	assert.NoError(t, err)
	// 也不知道怎么测试，用privKey的公钥加密，看看privKey2能否解密
	var plainData = "this is test data"
	ciperData, err := Sm2.Encrypt(&privKey.PublicKey, []byte(plainData))
	assert.NoError(t, err)
	data, err := Sm2.Decrypt(privKey2.(*crypto.PrivateKey), ciperData)
	assert.NoError(t, err)
	assert.True(t, string(data) == plainData)
}

func TestX509_EncryptAndDecryptPEMBlock(t *testing.T) {
	certpath := "cert.pem"
	// 加密
	bytes, err := ioutil.ReadFile(certpath)
	assert.NoError(t, err)
	X509 := NewX509()
	block, err := X509.EncryptPEMBlock(rand.Reader, "CERTIFICATE", bytes, nil, cryptoX509.PEMCipherDES)
	assert.NoError(t, err)
	// 判断
	assert.True(t, X509.IsEncryptedPEMBlock(block))
	// 解密
	data, err := X509.DecryptPEMBlock(block, nil)
	assert.NoError(t, err)
	assert.True(t, string(bytes) == string(data))
}
