package gmsm

import (
	"crypto"
	"io"

	commoncrypto "github.com/hyperledger/fabric/crypto"
	"github.com/hyperledger/fabric/gm"
	"github.com/tjfoc/gmsm/sm2"
)

/**
 * @Author: eggsy
 * @Description:
 * @File:  sm2
 * @Version: 1.0.0
 * @Date: 4/20/20 3:32 下午
 */

type SM2 struct {
}

func NewSm2() gm.Sm2 {
	return &SM2{}
}

// 创建私钥
func (s *SM2) GenerateKey() (*commoncrypto.PrivateKey, error) {
	key, err := sm2.GenerateKey()
	if err != nil {
		logger.Errorf("failed to generate private, err: %v", err)
		return nil, err
	}
	// 需要进行类型强转
	return toCryptoPrivateKey(key), nil
}

// 数字签名和验证
func (s *SM2) Sign(priv *commoncrypto.PrivateKey, rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	privKey := toSm2PrivateKey(priv)
	return privKey.Sign(rand, digest, opts)
}

func (s *SM2) Verify(pub *commoncrypto.PublicKey, digest []byte, sign []byte) bool {
	pubKey := toSm2PublicKey(pub)
	return pubKey.Verify(digest, sign)
}

// 非对称加密和解密
func (s *SM2) Encrypt(pub *commoncrypto.PublicKey, msg []byte) ([]byte, error) {
	pubKey := toSm2PublicKey(pub)
	return pubKey.Encrypt(msg)
}

func (s *SM2) Decrypt(priv *commoncrypto.PrivateKey, ciphertext []byte) ([]byte, error) {
	privKey := toSm2PrivateKey(priv)
	return privKey.Decrypt(ciphertext)
}

// 公钥和私钥的保存与加载
func (s *SM2) SavePrivateKeytoPem(fileName string, key *commoncrypto.PrivateKey, pwd []byte) (bool, error) {
	privKey := toSm2PrivateKey(key)
	return sm2.WritePrivateKeytoPem(fileName, privKey, pwd)
}

func (s *SM2) LoadPrivateKeyFromPem(fileName string, pwd []byte) (*commoncrypto.PrivateKey, error) {
	key, err := sm2.ReadPrivateKeyFromPem(fileName, pwd)
	if err != nil {
		logger.Errorf("failed to read private key from pem. fileName: %s, err: %v", fileName, err)
		return nil, err
	}
	return toCryptoPrivateKey(key), nil
}

func (s *SM2) SavePublicKeytoPem(fileName string, key *commoncrypto.PublicKey, _ []byte) (bool, error) {
	pubKey := toSm2PublicKey(key)
	return sm2.WritePublicKeytoPem(fileName, pubKey, nil)
}

func (s *SM2) LoadPublicKeyFromPem(fileName string, pwd []byte) (*commoncrypto.PublicKey, error) {
	key, err := sm2.ReadPublicKeyFromPem(fileName, pwd)
	if err != nil {
		logger.Errorf("failed to read public key from pem. fileName: %s, err: %v", fileName, err)
		return nil, err
	}
	return toCryptoPublicKey(key), nil
}
