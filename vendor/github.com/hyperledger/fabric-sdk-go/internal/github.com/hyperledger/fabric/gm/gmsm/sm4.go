/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package gmsm

import (
	"crypto/cipher"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/gm"
	flogging "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/sdkpatch/logbridge"
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
