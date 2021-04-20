package lib

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/mail"
	"time"
	"unsafe"

	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/signer"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/bccsp"
	fabriccrypto "github.com/hyperledger/fabric/crypto"
	"github.com/hyperledger/fabric/x509"
)

//证书签名
func signCert(req signer.SignRequest, ca *CA) (cert []byte, err error) {

	block, _ := pem.Decode([]byte(req.Request))
	if block == nil {
		return nil, fmt.Errorf("decode error")
	}
	if block.Type != "NEW CERTIFICATE REQUEST" && block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("not a csr")
	}
	template, err := parseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	template.NotBefore = req.NotBefore
	template.NotAfter = req.NotAfter

	certfile := ca.Config.CA.Certfile
	_, signer, x509cert, err := util.GetSignerFromCertFile(certfile, ca.csp)
	if err != nil {
		return nil, err
	}

	pub, err := util.ImportBCCSPPubKey(template.PublicKey, ca.csp)
	if err == nil {
		template.SubjectKeyId = pub.SKI()
	}

	cert, err = createCertificateToMem(template, x509cert, toFabricPub(template.PublicKey), signer)
	if err != nil {
		return nil, err
	}
	clientCert, err := util.GetX509CertificateFromPEM(cert)
	if err != nil {
		return nil, err
	}
	var certRecord = certdb.CertificateRecord{
		Serial:  clientCert.SerialNumber.String(),
		AKI:     hex.EncodeToString(clientCert.AuthorityKeyId),
		CALabel: req.Label,
		Status:  "good",
		Expiry:  clientCert.NotAfter,
		PEM:     string(cert),
	}
	//aki := hex.EncodeToString(cert.AuthorityKeyId)
	//serial := util.GetSerialAsHex(cert.SerialNumber)

	err = ca.certDBAccessor.InsertCertificate(certRecord)
	return
}

//生成证书
func createGmCert(req *csr.CertificateRequest, signer crypto.Signer, priv bccsp.Key) (cert []byte, err error) {
	csrPEM, err := generate(signer, req)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, fmt.Errorf("gmsm2 csr DecodeFailed")
	}

	if block.Type != "NEW CERTIFICATE REQUEST" && block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("gmsm2 not a csr")
	}
	template, err := parseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	template.SubjectKeyId = priv.SKI()
	template.NotBefore = time.Now()
	if req.CA.Expiry == "" {
		req.CA.Expiry = defaultRootCACertificateExpiration
	}
	expiry, err := time.ParseDuration(req.CA.Expiry)
	if err != nil {
		return nil, err
	}
	template.NotAfter = time.Now().Add(expiry)
	cert, err = createCertificateToMem(template, template, toFabricPub(template.PublicKey), signer)
	return
}

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

//证书请求转换成证书  参数为  block .Bytes
func parseCertificateRequest(csrBytes []byte) (template *x509.Certificate, err error) {
	csrv, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		//err = cferr.Wrap(cferr.CSRError, cferr.ParseFailed, err)
		return
	}
	err = x509.CheckSignature(csrv)
	if err != nil {
		//err = cferr.Wrap(cferr.CSRError, cferr.KeyMismatch, err)
		return
	}
	template = &x509.Certificate{
		Subject:            csrv.Subject,
		PublicKeyAlgorithm: csrv.PublicKeyAlgorithm,
		PublicKey:          csrv.PublicKey,
		SignatureAlgorithm: csrv.SignatureAlgorithm,
		DNSNames:           csrv.DNSNames,
		IPAddresses:        csrv.IPAddresses,
		EmailAddresses:     csrv.EmailAddresses,
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign |
			x509.KeyUsageCRLSign,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth},
	}
	for _, val := range csrv.Extensions {
		// Check the CSR for the X.509 BasicConstraints (RFC 5280, 4.2.1.9)
		// extension and append to template if necessary
		if val.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 19}) {
			var constraints csr.BasicConstraints
			var rest []byte

			if rest, err = asn1.Unmarshal(val.Value, &constraints); err != nil {
			} else if len(rest) != 0 {
			}

			template.BasicConstraintsValid = true
			template.IsCA = constraints.IsCA
			template.MaxPathLen = constraints.MaxPathLen
			template.MaxPathLenZero = template.MaxPathLen == 0
		}
	}
	serialNumber := make([]byte, 20)
	_, err = io.ReadFull(rand.Reader, serialNumber)
	if err != nil {
		return nil, err
	}

	// SetBytes interprets buf as the bytes of a big-endian
	// unsigned integer. The leading byte should be masked
	// off to ensure it isn't negative.
	serialNumber[0] &= 0x7F

	template.SerialNumber = new(big.Int).SetBytes(serialNumber)

	return
}

func createCertificateToMem(template, parent *x509.Certificate, pubKey *fabriccrypto.PublicKey, privKey crypto.Signer) ([]byte, error) {
	der, err := x509.CreateCertificate(rand.Reader, template, parent, pubKey, privKey)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	}
	return pem.EncodeToMemory(block), nil
}

func toFabricPub(pub interface{}) *fabriccrypto.PublicKey {
	switch pub.(type) {
	case *ecdsa.PublicKey:
		return (*fabriccrypto.PublicKey)(unsafe.Pointer(pub.(*ecdsa.PublicKey)))
	case *fabriccrypto.PublicKey:
		return pub.(*fabriccrypto.PublicKey)
	}
	return nil
}
