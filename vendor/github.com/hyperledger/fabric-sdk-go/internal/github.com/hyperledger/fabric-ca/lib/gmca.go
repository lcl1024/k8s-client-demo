package lib

import (
	"crypto"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"net"
	"net/mail"

	"github.com/cloudflare/cfssl/csr"
	fabriccrypto "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/crypto"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/x509"
)

//cloudflare 证书请求 转成 国密证书请求
func generate(priv crypto.Signer, req *csr.CertificateRequest) (csr []byte, err error) {
	sigAlgo := signerAlgo(priv)
	if sigAlgo == x509.UnknownSignatureAlgorithm {
		return nil, fmt.Errorf("Private key is unavailable")
	}
	var tpl = x509.CertificateRequest{
		Subject:            req.Name(),
		SignatureAlgorithm: sigAlgo,
	}
	for i := range req.Hosts {
		if ip := net.ParseIP(req.Hosts[i]); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else if email, err := mail.ParseAddress(req.Hosts[i]); err == nil && email != nil {
			tpl.EmailAddresses = append(tpl.EmailAddresses, email.Address)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, req.Hosts[i])
		}
	}

	if req.CA != nil {
		err = appendCAInfoToCSR(req.CA, &tpl)
		if err != nil {
			err = fmt.Errorf("sm2 GenerationFailed")
			return
		}
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, &tpl, priv)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: der,
	}
	csr = pem.EncodeToMemory(block)
	return
}

func signerAlgo(priv crypto.Signer) x509.SignatureAlgorithm {
	switch priv.Public().(type) {
	case *fabriccrypto.PublicKey:
		return x509.SM2WithSM3
	default:
		return x509.UnknownSignatureAlgorithm
	}
}

// appendCAInfoToCSR appends CAConfig BasicConstraint extension to a CSR
func appendCAInfoToCSR(reqConf *csr.CAConfig, csreq *x509.CertificateRequest) error {
	pathlen := reqConf.PathLength
	if pathlen == 0 && !reqConf.PathLenZero {
		pathlen = -1
	}
	val, err := asn1.Marshal(csr.BasicConstraints{true, pathlen})

	if err != nil {
		return err
	}

	csreq.ExtraExtensions = []pkix.Extension{
		{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 19},
			Value:    val,
			Critical: true,
		},
	}
	return nil
}
