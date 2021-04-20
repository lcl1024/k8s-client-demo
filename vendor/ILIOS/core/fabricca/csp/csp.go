/*
Copyright IBM Corp. 2017 All Rights Reserved.

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
package csp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	"github.com/astaxie/beego/logs"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/factory"
	"github.com/hyperledger/fabric/bccsp/signer"
	"github.com/hyperledger/fabric/bccsp/utils"
)

// GeneratePrivateKey creates a private key and stores it in keystorePath
func GeneratePrivateKey(keystorePath string) (bccsp.Key,
	crypto.Signer, error) {
	logs.Debug("GeneratePrivateKey")
	var err error
	var priv bccsp.Key
	var s crypto.Signer

	opts := &factory.FactoryOpts{
		ProviderName: "SW",
		SwOpts: &factory.SwOpts{
			HashFamily: "SHA2",
			SecLevel:   256,

			FileKeystore: &factory.FileKeystoreOpts{
				KeyStorePath: keystorePath,
			},
		},
	}
	csp, err := factory.GetBCCSPFromOpts(opts)
	if err == nil {
		// generate a key
		priv, err = csp.KeyGen(&bccsp.ECDSAP256KeyGenOpts{Temporary: false})
		if err == nil {
			// create a crypto.Signer
			s, err = signer.New(csp, priv)
		}
	}
	return priv, s, err
}
func ImportPrivateKey(data []byte) (bccsp.Key,
	crypto.Signer, error) {
	logs.Debug("ImportPrivateKey")
	var priv bccsp.Key
	var s crypto.Signer

	opts := &factory.FactoryOpts{
		ProviderName: "SW",
		SwOpts: &factory.SwOpts{
			HashFamily: "SHA2",
			SecLevel:   256,
			Ephemeral:  true,
		},
	}
	csp, err := factory.GetBCCSPFromOpts(opts)
	if err != nil {
		return nil, nil, err
	}
	priv, err = ImportBCCSPKeyFromPEM(data, csp, true)
	if err != nil {
		return nil, nil, err
	}
	s, err = signer.New(csp, priv)
	if err != nil {
		return nil, nil, err
	}
	return priv, s, err
}

func GetECPublicKey(priv bccsp.Key) (*ecdsa.PublicKey, error) {

	// get the public key
	pubKey, err := priv.PublicKey()
	if err != nil {
		return nil, err
	}
	// marshal to bytes
	pubKeyBytes, err := pubKey.Bytes()
	if err != nil {
		return nil, err
	}
	// unmarshal using pkix
	ecPubKey, err := x509.ParsePKIXPublicKey(pubKeyBytes)
	if err != nil {
		return nil, err
	}
	return ecPubKey.(*ecdsa.PublicKey), nil
}

func ImportBCCSPKeyFromPEM(keyBuff []byte, myCSP bccsp.BCCSP, temporary bool) (bccsp.Key, error) {
	key, err := utils.PEMtoPrivateKey(keyBuff, nil)
	if err != nil {
		return nil, err
	}
	switch key.(type) {
	case *ecdsa.PrivateKey:
		priv, err := utils.PrivateKeyToDER(key.(*ecdsa.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("Failed to convert ECDSA private key : %s", err.Error())
		}
		sk, err := myCSP.KeyImport(priv, &bccsp.ECDSAPrivateKeyImportOpts{Temporary: temporary})
		if err != nil {
			return nil, fmt.Errorf("Failed to import ECDSA private key : %s", err.Error())
		}
		return sk, nil
	case *rsa.PrivateKey:
		return nil, fmt.Errorf("Failed to import RSA key; RSA private key import is not supported")
	default:
		return nil, fmt.Errorf("Failed to import key: invalid secret key type")
	}
}
