package fabricca

import (
	"net/url"

	"github.com/cloudflare/cfssl/csr"

	"github.com/astaxie/beego/logs"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric/bccsp/factory"
)

type ClientConfig struct {
	Userid              string
	CaUser              string
	CaPassword          string
	CaName              string
	CaUrl               string
	ClientConfig        *lib.ClientConfig
	RegistrationRequest api.RegistrationRequest
	CAInfo              api.GetCAInfoRequest
}
type CSR struct {
	CN    string
	Names []CSRName
	Hosts []string
}
type CSRName struct {
	C            string // Country
	ST           string // State
	L            string // Locality
	O            string // OrganisationName
	OU           string // OrganisationalUnitName
	SerialNumber string
}
type MspFile struct {
	Name    string
	Content []byte
	Path    string
}
type Msp struct {
	CaCerts   MspFile
	KeyStore  MspFile
	SignCerts MspFile
}

// 提供CSR或默认

func NewCSRName(c string, st string, l string, o string, ou string) CSRName {
	return CSRName{
		C:  c,
		ST: st,
		L:  l,
		O:  o,
		OU: ou,
	}
}

func NewCSR(cn string, names []CSRName, hosts []string) CSR {
	return CSR{
		CN:    cn,
		Names: names,
		Hosts: hosts,
	}
}

func NewEnrollClientConfig(userid string, causer string, capassword string, caname string, caurl string, cacsr CSR) (*ClientConfig, error) {
	purl, err := url.Parse(caurl)
	logs.Info("url %+v ", purl)
	if err != nil {
		logs.Error(err)
		return nil, err
	}
	csrname := []csr.Name{}
	for _, v := range cacsr.Names {
		n := csr.Name{
			C:  v.C,
			ST: v.ST,
			L:  v.L,
			O:  v.O,
			OU: v.OU,
		}
		csrname = append(csrname, n)
	}
	//pa := path.Join(configpath.GetBaaSTmpPath(userid), "ca", caname, "enroll", causer, "msp")
	pa := MspEnrollPath(userid, caname, causer)
	return &ClientConfig{
		Userid:     userid,
		CaUser:     causer,
		CaPassword: capassword,
		CaName:     caname,
		CaUrl:      purl.Host,
		ClientConfig: &lib.ClientConfig{
			MSPDir: pa,
			Debug:  true,
			CSR: api.CSRInfo{
				CN:    cacsr.CN,
				Names: csrname,
				Hosts: cacsr.Hosts,
			},
			CSP: &factory.FactoryOpts{
				ProviderName: "SW",
				SwOpts: &factory.SwOpts{
					SecLevel:   256,
					HashFamily: "SHA2",
				},
			},
		},
	}, nil
}

func NewRegisterClientConfig(userid string, caname string, caurl string, causer string,
	casecret string, catype string, maxEnrollments int, affiliation string, attributes []api.Attribute) (*ClientConfig, error) {
	purl, err := url.Parse(caurl)
	logs.Info("url %+v ", purl)
	if err != nil {
		logs.Error(err)
		return nil, err
	}
	//pa := path.Join(configpath.GetBaaSTmpPath(userid), "ca", caname, "register", causer, "msp")
	pa := MspEnrollPath(userid, caname, causer)
	return &ClientConfig{
		Userid: userid,
		CaName: caname,
		CaUrl:  caurl,
		ClientConfig: &lib.ClientConfig{
			MSPDir: pa,
			Debug:  true,
		},
		RegistrationRequest: api.RegistrationRequest{
			Name:           causer,
			Type:           catype,
			Secret:         casecret,
			MaxEnrollments: maxEnrollments,
			Affiliation:    affiliation,
			Attributes:     attributes,
			CAName:         caname,
		},
	}, nil
}

func NewGetCaCertConfig(userid string, caurl string, caname string) *ClientConfig {
	return &ClientConfig{
		Userid: userid,
		CaName: caname,
		ClientConfig: &lib.ClientConfig{
			Debug: true,
			URL:   caurl,
		},
		CAInfo: api.GetCAInfoRequest{
			CAName: caname,
		},
	}
}
