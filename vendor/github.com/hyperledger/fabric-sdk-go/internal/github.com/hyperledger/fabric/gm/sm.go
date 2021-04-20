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
package gm

import (
	gocrypto "crypto"
	"crypto/cipher"
	"hash"
	"io"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/crypto"
)

type Sm2 interface {
	// 创建私钥
	GenerateKey() (*crypto.PrivateKey, error)

	// 数字签名和验证
	Sign(priv *crypto.PrivateKey, rand io.Reader, digest []byte, opts gocrypto.SignerOpts) ([]byte, error)
	Verify(pub *crypto.PublicKey, digest []byte, sign []byte) bool

	// 非对称加密和解密
	Encrypt(pub *crypto.PublicKey, msg []byte) ([]byte, error)
	Decrypt(priv *crypto.PrivateKey, ciphertext []byte) ([]byte, error)

	// 公钥和私钥的保存与加载
	SavePrivateKeytoPem(fileName string, key *crypto.PrivateKey, pwd []byte) (bool, error)
	LoadPrivateKeyFromPem(fileName string, pwd []byte) (*crypto.PrivateKey, error)
	SavePublicKeytoPem(fileName string, key *crypto.PublicKey, _ []byte) (bool, error)
	LoadPublicKeyFromPem(fileName string, pwd []byte) (*crypto.PublicKey, error)
}

type Sm3 interface {
	// 创建符合Hash接口的sm3实例
	New() hash.Hash
	// 使用sm3计算数据的摘要
	Sum(data []byte) []byte
}

type Sm4 interface {
	// 创建符合Block接口的sm4实例
	NewCipher(key []byte) (cipher.Block, error)

	// 使用对称密钥加密和解密
	Encrypt(key []byte, dst, src []byte)
	Decrypt(key []byte, dst, src []byte)

	// 密钥保存和加载
	SaveKeyToPem(fileName string, key []byte, pwd []byte) (bool, error)
	LoadKeyFromPem(fileName string, pwd []byte) ([]byte, error)
}
