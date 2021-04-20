package util

import (
	stdx509 "crypto/x509"
	"unsafe"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/x509"
)

//func ToStdX509(certificate *x509.Certificate) *stdx509.Certificate {
//	var cert1 x509.Certificate
//	cert1 = *certificate
//	cert := (*stdx509.Certificate)(unsafe.Pointer(&cert1))
//	cert.CRLDistributionPoints = nil
//	return cert
//}

func ToFabricX509(certificate *stdx509.Certificate) *x509.Certificate {
	return (*x509.Certificate)(unsafe.Pointer(certificate))
}

//func ToStdX509CertPool(certPool *x509.CertPool) *stdx509.CertPool {
//	return (*stdx509.CertPool)(unsafe.Pointer(certPool))
//}
