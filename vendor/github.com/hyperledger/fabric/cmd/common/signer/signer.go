/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signer

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/asn1"
	"encoding/pem"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/factory"
	"github.com/hyperledger/fabric/bccsp/utils"
	"github.com/hyperledger/fabric/common/crypto"
	"github.com/hyperledger/fabric/protos/common"
	"github.com/hyperledger/fabric/protos/msp"
	proto_utils "github.com/hyperledger/fabric/protos/utils"
	"github.com/pkg/errors"
	"io/ioutil"
	"math/big"
)

/**
 * @Author: eggsy
 * @Description:
 * @File:  signer
 * @Version: 1.0.0
 * @Date: 2019-12-27 17:38
 */

type Signer struct {
	key     bccsp.Key
	Creator []byte
}

type Config struct {
	MSPID        string
	IdentityPath string
	KeyPath      string
}

func (si *Signer) NewSignatureHeader() (*common.SignatureHeader, error) {
	nonce, err := crypto.GetRandomNonce()
	if err != nil {
		return nil, err
	}
	return &common.SignatureHeader{
		Creator: si.Creator,
		Nonce:   nonce,
	}, nil
}

// NewSigner creates a new Signer out of the given configuration
func NewSigner(conf Config) (*Signer, error) {
	sId, err := serializeIdentity(conf.IdentityPath, conf.MSPID)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	key, err := loadPrivateKey(conf.KeyPath)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return &Signer{
		Creator: sId,
		key:     key,
	}, nil
}

func (si *Signer) Sign(msg []byte) ([]byte, error) {
	if len(msg) == 0 {
		return nil, errors.New("msg (to sign) required")
	}
	digest, err := factory.GetDefault().Hash(msg, &bccsp.SHA256Opts{})
	if err != nil {
		return nil, err
	}
	signature, err := factory.GetDefault().Sign(si.key, digest, nil)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

func serializeIdentity(clientCert string, mspID string) ([]byte, error) {
	b, err := ioutil.ReadFile(clientCert)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	sId := &msp.SerializedIdentity{
		Mspid:   mspID,
		IdBytes: b,
	}
	return proto_utils.MarshalOrPanic(sId), nil
}

func loadPrivateKey(file string) (bccsp.Key, error) {
	b, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	bl, _ := pem.Decode(b)
	if bl == nil {
		return nil, errors.Errorf("failed to decode PEM block from %s", file)
	}
	key, err := factory.GetDefault().KeyImport(bl.Bytes, &bccsp.ECDSAPrivateKeyImportOpts{true})
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse private key from %s", file)
	}
	return key, nil
}

func signECDSA(k *ecdsa.PrivateKey, digest []byte) (signature []byte, err error) {
	r, s, err := ecdsa.Sign(rand.Reader, k, digest)
	if err != nil {
		return nil, err
	}

	s, _, err = utils.ToLowS(&k.PublicKey, s)
	if err != nil {
		return nil, err
	}

	return marshalECDSASignature(r, s)
}

func marshalECDSASignature(r, s *big.Int) ([]byte, error) {
	return asn1.Marshal(ECDSASignature{r, s})
}

type ECDSASignature struct {
	R, S *big.Int
}
