package x509

import (
	"crypto/ecdsa"
	"crypto/x509"
	"unsafe"

	commoncrypto "github.com/hyperledger/fabric/crypto"
)

func toGoCert(cert *Certificate) *x509.Certificate {
	return (*x509.Certificate)(unsafe.Pointer(cert))
}

func toGoCertRequest(certReq *CertificateRequest) *x509.CertificateRequest {
	return (*x509.CertificateRequest)(unsafe.Pointer(certReq))
}

func toCommonCert(cert *x509.Certificate) *Certificate {
	return (*Certificate)(unsafe.Pointer(cert))
}

func toCommonCertLists(chains [][]*x509.Certificate) [][]*Certificate {
	var ret [][]*Certificate
	for _, certs := range chains {
		var row []*Certificate
		for _, c := range certs {
			row = append(row, toCommonCert(c))
		}
		ret = append(ret, row)
	}
	return ret
}
func toCommonCertRequest(certReq *x509.CertificateRequest) *CertificateRequest {
	return (*CertificateRequest)(unsafe.Pointer(certReq))
}

func toGoCertPool(pool *CertPool) *x509.CertPool {
	return (*x509.CertPool)(unsafe.Pointer(pool))
}

func toCommonCertPool(pool *x509.CertPool) *CertPool {
	return (*CertPool)(unsafe.Pointer(pool))
}

func toGoVerifyOpts(opts *VerifyOptions) *x509.VerifyOptions {
	return (*x509.VerifyOptions)(unsafe.Pointer(opts))
}

func toCommonVerifyOpts(opts *x509.VerifyOptions) *VerifyOptions {
	return (*VerifyOptions)(unsafe.Pointer(opts))
}

func toGoSigAlg(alg SignatureAlgorithm) x509.SignatureAlgorithm {
	return x509.SignatureAlgorithm(alg)
}

func toCommonSigAlg(alg x509.SignatureAlgorithm) SignatureAlgorithm {
	return SignatureAlgorithm(alg)
}

func toGoPrivateKey(key *commoncrypto.PrivateKey) *ecdsa.PrivateKey {
	return (*ecdsa.PrivateKey)(unsafe.Pointer(key))
}

func toCommonPrivateKey(key *ecdsa.PrivateKey) *commoncrypto.PrivateKey {
	return (*commoncrypto.PrivateKey)(unsafe.Pointer(key))
}
