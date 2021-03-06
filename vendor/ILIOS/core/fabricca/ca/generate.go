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
package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"path"
	"time"

	"path/filepath"

	"ILIOS/common"
	"ILIOS/core/fabricca/csp"

	"github.com/astaxie/beego/logs"
	"github.com/hyperledger/fabric/bccsp"
)

type CA struct {
	Name               string
	Country            string
	Province           string
	Locality           string
	OrganizationalUnit string
	StreetAddress      string
	PostalCode         string
	//SignKey  *ecdsa.PrivateKey
	Signer   crypto.Signer
	SignCert *x509.Certificate
}

// NewCA creates an instance of CA and saves the signing key pair in
// baseDir/name
func NewCA(baseDir, org, name, country, province, locality, orgUnit, streetAddress, postalCode string) (*CA, error) {

	var ca *CA
	var priv bccsp.Key
	var signer crypto.Signer
	exist := common.FileExists(path.Join(baseDir, "tls-key.pem"))
	if exist == false {
		err := os.MkdirAll(baseDir, 0755)
		if err == nil {
			priv, signer, err = csp.GeneratePrivateKey(baseDir)
			if err != nil {
				return nil, err
			}
		}
	} else {
		data, err := ioutil.ReadFile(path.Join(baseDir, "tls-key.pem"))
		if err != nil {
			return nil, err
		}
		priv, signer, err = csp.ImportPrivateKey(data)
		if err != nil {
			return nil, err
		}
	}
	ecPubKey, err := csp.GetECPublicKey(priv)
	if err != nil {
		return nil, err
	}
	template := x509Template()
	//this is a CA
	template.IsCA = true
	template.KeyUsage |= x509.KeyUsageDigitalSignature |
		x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign |
		x509.KeyUsageCRLSign
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}

	//set the organization for the subject
	subject := subjectTemplateAdditional(country, province, locality, orgUnit, streetAddress, postalCode)
	subject.Organization = []string{org}
	subject.CommonName = name

	template.Subject = subject
	template.SubjectKeyId = priv.SKI()
	var x509Cert *x509.Certificate
	if exist == false {
		x509Cert, err = genCertificateECDSA(baseDir, name, &template, &template,
			ecPubKey, signer)
		if err != nil {
			return nil, err
		}
	} else {
		certBytes, err := ioutil.ReadFile(path.Join(baseDir, "tls-cert.pem"))
		if err != nil {
			return nil, err
		}
		x509Cert, err = pemToX509Cert(certBytes)
		if err != nil {
			logs.Error("111111", err)
			return nil, err
		}
	}
	ca = &CA{
		Name:               name,
		Signer:             signer,
		SignCert:           x509Cert,
		Country:            country,
		Province:           province,
		Locality:           locality,
		OrganizationalUnit: orgUnit,
		StreetAddress:      streetAddress,
		PostalCode:         postalCode,
	}

	return ca, nil
}

// SignCertificate creates a signed certificate based on a built-in template
// and saves it in baseDir/name
func (ca *CA) SignCertificate(baseDir, name string, sans []string, pub *ecdsa.PublicKey,
	ku x509.KeyUsage, eku []x509.ExtKeyUsage) (*x509.Certificate, error) {

	template := x509Template()
	template.KeyUsage = ku
	template.ExtKeyUsage = eku

	//set the organization for the subject
	subject := subjectTemplateAdditional(ca.Country, ca.Province, ca.Locality, ca.OrganizationalUnit, ca.StreetAddress, ca.PostalCode)
	subject.CommonName = name

	template.Subject = subject
	for _, san := range sans {
		// try to parse as an IP address first
		ip := net.ParseIP(san)
		if ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, san)
		}
	}

	cert, err := genCertificateECDSA(baseDir, name, &template, ca.SignCert,
		pub, ca.Signer)

	if err != nil {
		return nil, err
	}

	return cert, nil
}

// default template for X509 subject
func subjectTemplate() pkix.Name {
	return pkix.Name{
		Country:  []string{"CN"},
		Locality: []string{"ZheJiang"},
		Province: []string{"HangZhou"},
	}
}

// Additional for X509 subject
func subjectTemplateAdditional(country, province, locality, orgUnit, streetAddress, postalCode string) pkix.Name {
	name := subjectTemplate()
	if len(country) >= 1 {
		name.Country = []string{country}
	}
	if len(province) >= 1 {
		name.Province = []string{province}
	}

	if len(locality) >= 1 {
		name.Locality = []string{locality}
	}
	if len(orgUnit) >= 1 {
		name.OrganizationalUnit = []string{orgUnit}
	}
	if len(streetAddress) >= 1 {
		name.StreetAddress = []string{streetAddress}
	}
	if len(postalCode) >= 1 {
		name.PostalCode = []string{postalCode}
	}
	return name
}

// default template for X509 certificates
func x509Template() x509.Certificate {

	//generate a serial number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	now := time.Now()
	//basic template to use
	x509 := x509.Certificate{
		SerialNumber:          serialNumber,
		NotBefore:             now,
		NotAfter:              now.Add(3650 * 24 * time.Hour), //~ten years
		BasicConstraintsValid: true,
	}
	return x509

}

// generate a signed X509 certificate using ECDSA
func genCertificateECDSA(baseDir, name string, template, parent *x509.Certificate, pub *ecdsa.PublicKey,
	priv interface{}) (*x509.Certificate, error) {

	//create the x509 public cert
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		return nil, err
	}

	//write cert out to file
	fileName := filepath.Join(baseDir, name+"-cert.pem")
	certFile, err := os.Create(fileName)
	if err != nil {
		return nil, err
	}
	//pem encode the cert
	err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	certFile.Close()
	if err != nil {
		return nil, err
	}

	x509Cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}
	return x509Cert, nil
}

func pemToX509Cert(pemCert []byte) (*x509.Certificate, error) {
	block, pemCert := pem.Decode(pemCert)
	if block == nil {
		return nil, fmt.Errorf("can't ParseCertificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	} else {
		return cert, nil
	}
}
