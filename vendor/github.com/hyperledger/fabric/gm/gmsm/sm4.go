package gmsm

import (
	"crypto/cipher"

	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/gm"
	"github.com/tjfoc/gmsm/sm4"
)

/**
 * @Author: eggsy
 * @Description:
 * @File:  sm4
 * @Version: 1.0.0
 * @Date: 4/20/20 3:32 下午
 */
var logger = flogging.MustGetLogger("gm.gmsm")

type SM4 struct {
}

func NewSm4() gm.Sm4 {
	return &SM4{}
}
func (s *SM4) NewCipher(key []byte) (cipher.Block, error) {
	return sm4.NewCipher(key)
}

func (s *SM4) Encrypt(key []byte, dst, src []byte) {
	c, err := sm4.NewCipher(key)
	if err != nil {
		logger.Errorf("failed to created cipher. err: %v", err)
		return
	}
	c.Encrypt(dst, src)
}

func (s *SM4) Decrypt(key []byte, dst, src []byte) {
	c, err := sm4.NewCipher(key)
	if err != nil {
		logger.Errorf("failed to created cipher. err: %v", err)
		return
	}
	c.Decrypt(dst, src)
}

func (s *SM4) SaveKeyToPem(fileName string, key []byte, pwd []byte) (bool, error) {
	return sm4.WriteKeyToPem(fileName, key, pwd)
}

func (s *SM4) LoadKeyFromPem(fileName string, pwd []byte) ([]byte, error) {
	return sm4.ReadKeyFromPem(fileName, pwd)
}
