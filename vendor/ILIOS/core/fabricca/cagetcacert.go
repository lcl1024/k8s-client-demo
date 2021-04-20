package fabricca

import (
	"github.com/hyperledger/fabric-ca/lib"
)

func (c *ClientConfig) GetCAInfo() (*lib.GetServerInfoResponse, error) {
	client := &lib.Client{
		HomeDir: "",
		Config:  c.ClientConfig,
	}

	si, err := client.GetCAInfo(&c.CAInfo)
	return si, err
}
