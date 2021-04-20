package fabricca

import (
	"io/ioutil"

	"github.com/astaxie/beego/logs"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric/bccsp/factory"
)

type RegisterResponse struct {
	// Name is the unique name of the identity
	Name string `json:"id" help:"Unique name of the identity"`
	// Type of identity being registered (e.g. "peer, app, user")
	Type string `json:"type" help:"Type of identity being registered (e.g. 'peer, app, user')"`
	// Secret is an optional password.  If not specified,
	// a random secret is generated.  In both cases, the secret
	// is returned in the RegistrationResponse.
	Secret string `json:"secret,omitempty" help:"The enrollment secret for the identity being registered"`
	// MaxEnrollments is the maximum number of times the secret can
	// be reused to enroll.
	MaxEnrollments int `json:"max_enrollments,omitempty" def:"-1" help:"The maximum number of times the secret can be reused to enroll."`
	// is returned in the response.
	// The identity's affiliation.
	// For example, an affiliation of "org1.department1" associates the identity with "department1" in "org1".
	Affiliation string `json:"affiliation" help:"The identity's affiliation"`
	// Attributes associated with this identity
	Attributes []api.Attribute `json:"attrs,omitempty"`
	// CAName is the name of the CA to connect to
	CAName string `json:"caname,omitempty" skip:"true"`
}

func (c *ClientConfig) Register() (RegisterResponse, error) {
	clientconfig := &lib.ClientConfig{
		Debug:  true,
		URL:    c.CaUrl,
		CAName: c.CaName,
		CSP: &factory.FactoryOpts{
			ProviderName: "SW",
			SwOpts: &factory.SwOpts{
				SecLevel:   256,
				HashFamily: "SHA2",
			},
		},
	}
	client := lib.Client{
		HomeDir: "",
		Config:  clientconfig,
	}
	admin, err := c.BaaSAdminUser()
	if err != nil {
		logs.Error("GET BaaSAdminUser ERROR", err)
		return RegisterResponse{}, err
	}
	signcerts, err := signcerts(c.Userid, c.CaName, string(admin))
	if err != nil {
		logs.Error("GET signcerts ERROR", err)
		return RegisterResponse{}, err
	}
	keystores, err := keystore(c.Userid, c.CaName, string(admin))
	if err != nil {
		logs.Error("GET keystore ERROR", err)
		return RegisterResponse{}, err
	}

	id, err := client.LoadIdentity(keystores.Path, signcerts.Path)
	if err != nil {
		logs.Error("LoadIdentity error", err)
		return RegisterResponse{}, err
	}

	res, err := id.Register(&c.RegistrationRequest)
	if err != nil {
		logs.Error("Register error", err)
		return RegisterResponse{}, err
	}
	response := RegisterResponse{
		Name:           c.RegistrationRequest.Name,
		Type:           c.RegistrationRequest.Type,
		Secret:         res.Secret,
		MaxEnrollments: c.RegistrationRequest.MaxEnrollments,
		Affiliation:    c.RegistrationRequest.Affiliation,
		Attributes:     c.RegistrationRequest.Attributes,
		CAName:         c.RegistrationRequest.CAName,
	}
	return response, nil
}

func (c *ClientConfig) BaaSAdminUser() ([]byte, error) {
	filepath := BaaSAdminUserPath(c.Userid, c.CaName)
	logs.Info("filepath", filepath)
	admin, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	return admin, nil
}
