package gmsm

import (
	"unsafe"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/crypto"
	commonX509 "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/x509"
	"github.com/tjfoc/gmsm/sm2"
)

func toSm2PrivateKey(priv *crypto.PrivateKey) *sm2.PrivateKey {
	return (*sm2.PrivateKey)(unsafe.Pointer(priv))
}

func toCryptoPrivateKey(priv *sm2.PrivateKey) *crypto.PrivateKey {
	return (*crypto.PrivateKey)(unsafe.Pointer(priv))

}

func toSm2PublicKey(pub *crypto.PublicKey) *sm2.PublicKey {
	return (*sm2.PublicKey)(unsafe.Pointer(pub))
}

func toCryptoPublicKey(pub *sm2.PublicKey) *crypto.PublicKey {
	return (*crypto.PublicKey)(unsafe.Pointer(pub))

}

func toGmCert(cert *commonX509.Certificate) *sm2.Certificate {
	return (*sm2.Certificate)(unsafe.Pointer(cert))
}

func toGmCertRequest(certReq *commonX509.CertificateRequest) *sm2.CertificateRequest {
	return (*sm2.CertificateRequest)(unsafe.Pointer(certReq))
}

func toCommonCert(cert *sm2.Certificate) *commonX509.Certificate {
	return (*commonX509.Certificate)(unsafe.Pointer(cert))
}

func toCommonCertRequest(certReq *sm2.CertificateRequest) *commonX509.CertificateRequest {
	return (*commonX509.CertificateRequest)(unsafe.Pointer(certReq))
}

func toGmCertPool(pool *commonX509.CertPool) *sm2.CertPool {
	return (*sm2.CertPool)(unsafe.Pointer(pool))
}

func toCommonCertPool(pool *sm2.CertPool) *commonX509.CertPool {
	return (*commonX509.CertPool)(unsafe.Pointer(pool))
}

func toGmVerifyOpts(opts *commonX509.VerifyOptions) *sm2.VerifyOptions {
	return (*sm2.VerifyOptions)(unsafe.Pointer(opts))
}

func toCommonVerifyOpts(opts *sm2.VerifyOptions) *commonX509.VerifyOptions {
	return (*commonX509.VerifyOptions)(unsafe.Pointer(opts))
}

func toCommonSignatureAlgorithm(algorithm *sm2.SignatureAlgorithm) *commonX509.SignatureAlgorithm {
	return (*commonX509.SignatureAlgorithm)(unsafe.Pointer(algorithm))

}
func toSm2SignatureAlgorithm(algorithm *commonX509.SignatureAlgorithm) *sm2.SignatureAlgorithm {
	return (*sm2.SignatureAlgorithm)(unsafe.Pointer(algorithm))

}
