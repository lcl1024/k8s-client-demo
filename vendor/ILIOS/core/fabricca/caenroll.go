package fabricca

import (
	"ILIOS/common"
	"fmt"
	"os"

	"github.com/astaxie/beego/logs"
)

func (c *ClientConfig) Enroll() (Msp, error) {
	if c.hasEnrolled() {
		msp, err := c.readMsp()
		if err != nil {
			return Msp{}, err
		}
		return msp, nil
	}
	rawurl := fmt.Sprintf("http://%s:%s@%s", c.CaUser, c.CaPassword, c.CaUrl)
	logs.Debug("Entered runEnroll", rawurl)

	resp, err := c.ClientConfig.Enroll(rawurl, "")
	if err != nil {
		os.RemoveAll(c.ClientConfig.MSPDir)
		return Msp{}, err
	}

	ID := resp.Identity
	err = ID.Store()
	if err != nil {
		os.RemoveAll(c.ClientConfig.MSPDir)
		return Msp{}, fmt.Errorf("Failed to store enrollment information: %s", err)
	}

	err = storeCAChain(c.ClientConfig, &resp.ServerInfo)
	if err != nil {
		os.RemoveAll(c.ClientConfig.MSPDir)
		return Msp{}, err
	}
	msp, err := c.readMsp()
	if err != nil {
		return Msp{}, err
	}
	return msp, nil
}

func (c *ClientConfig) readMsp() (Msp, error) {
	cacerts, err := cacerts(c.Userid, c.CaName, c.CaUser)
	if err != nil {
		return Msp{}, err
	}
	keystore, err := keystore(c.Userid, c.CaName, c.CaUser)
	if err != nil {
		return Msp{}, err
	}
	signcerts, err := signcerts(c.Userid, c.CaName, c.CaUser)
	if err != nil {
		return Msp{}, err
	}
	return Msp{
		CaCerts:   cacerts,
		KeyStore:  keystore,
		SignCerts: signcerts,
	}, nil
}

func (c *ClientConfig) hasEnrolled() bool {
	flag := common.CheckFileIsExist(c.ClientConfig.MSPDir)
	logs.Info("hasEnrolled", flag)
	return flag
}
