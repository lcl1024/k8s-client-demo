package gmsm

import (
	gocrypto "crypto"
	"io"

	"github.com/hyperledger/fabric/crypto"
)

// sm2Signer 为的是获取sm2所使用的公钥
type sm2Signer struct {
	bccspsigner gocrypto.Signer
}

func newSm2Signer(signer gocrypto.Signer) *sm2Signer {
	return &sm2Signer{signer}
}

// Public 转换成sm2的公钥
func (ss *sm2Signer) Public() gocrypto.PublicKey {
	pub := ss.bccspsigner.Public()
	p, ok := pub.(*crypto.PublicKey)
	if !ok {
		return pub
	}
	return toSm2PublicKey(p)
}

func (ss *sm2Signer) Sign(rand io.Reader, digest []byte, opts gocrypto.SignerOpts) (signature []byte, err error) {
	return ss.bccspsigner.Sign(rand, digest, opts)
}
