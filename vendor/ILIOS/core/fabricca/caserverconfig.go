package fabricca

import (
	"ILIOS/common"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/astaxie/beego/logs"
)

type CaServerConfig struct {
	Config    []byte
	BaasAdmin BaaSAdmin
	CaAdmin   []CaAdmin
}

func NewCaServerConfig() *CaServerConfig {
	str := readTemplateFile()
	return &CaServerConfig{
		Config:    str,
		BaasAdmin: createBaasAdmin(),
		CaAdmin:   []CaAdmin{},
	}
}

func readTemplateFile() []byte {
	basepath := filepath.Join(common.Getwd(), "core/fabricca", FabricCaServerConfig)
	logs.Info("ca path", basepath)
	data, err := ioutil.ReadFile(basepath)
	if err != nil {
		panic("Can't find " + basepath)
	}
	return data

}

func (c *CaServerConfig) repalceBassAdmin() {
	conf := string(c.Config)
	//baasadmin
	conf = strings.Replace(conf, "<<<BAASADMIN>>>", c.BaasAdmin.BaaSAdminUser, 1)
	conf = strings.Replace(conf, "<<<BAASADMINPW>>>", c.BaasAdmin.BaaSAdminPasswd, 1)
	c.Config = []byte(conf)
}

func (c *CaServerConfig) replaceCaOrg(caname string, orgname string) {
	conf := string(c.Config)
	// This is a root CA
	conf = strings.Replace(conf, "<<<CANAME>>>", caname, 1)
	conf = strings.Replace(conf, "<<<COMMONNAME>>>", caname, 1)
	conf = strings.Replace(conf, "<<<PATHLENGTH>>>", "1", 1)
	conf = strings.Replace(conf, "<<<ORGNAME>>>", orgname, 1)
	c.Config = []byte(conf)
}

func (c *CaServerConfig) insertAdminIdentity(adminuser string, adminpw string) {
	conf := c.Config
	index := strings.Index(string(conf), AdminFlag)
	substr := conf[0:index]
	midstr := []byte(AdminTemplate)
	laststr := conf[index:len(conf)]
	str := commonFunc.Merge(substr, midstr, laststr)
	confstr := string(str)
	confstr = strings.Replace(confstr, "<<<ADMIN>>>", adminuser, 1)
	confstr = strings.Replace(confstr, "<<<ADMINPW>>>", adminpw, 1)
	c.Config = []byte(confstr)
	admin := CaAdmin{
		CaAdminUser:   adminuser,
		CaAdminPasswd: adminpw,
	}
	c.CaAdmin = append(c.CaAdmin, admin)

}

func (c *CaServerConfig) insertCSR(csr CSRName) {
	conf := c.Config
	index := strings.Index(string(conf), CsrFlag)
	substr := conf[0:index]
	midstr := []byte(CsrTemplate)
	laststr := conf[index:len(conf)]
	str := commonFunc.Merge(substr, midstr, laststr)
	confstr := string(str)
	confstr = strings.Replace(confstr, "<<<C>>>", csr.C, 1)
	confstr = strings.Replace(confstr, "<<<ST>>>", csr.ST, 1)
	confstr = strings.Replace(confstr, "<<<L>>>", csr.L, 1)
	confstr = strings.Replace(confstr, "<<<O>>>", csr.O, 1)
	confstr = strings.Replace(confstr, "<<<OU>>>", csr.OU, 1)
	c.Config = []byte(confstr)
}

func (c *CaServerConfig) insertHost(host string) {
	conf := c.Config
	index := strings.Index(string(conf), HostFlag)
	substr := conf[0:index]
	midstr := []byte(HostTemplate)
	laststr := conf[index:len(conf)]
	str := commonFunc.Merge(substr, midstr, laststr)
	confstr := string(str)
	confstr = strings.Replace(confstr, "<<<MYHOST>>>", host, 1)
	c.Config = []byte(confstr)
}

func (c *CaServerConfig) cleanflag() {
	conf := string(c.Config)
	conf = strings.Replace(conf, AdminFlag, "", -1)
	conf = strings.Replace(conf, CsrFlag, "", -1)
	conf = strings.Replace(conf, HostFlag, "", -1)
	c.Config = []byte(conf)
}
func (c *CaServerConfig) Configurate(ca Ca) {
	c.repalceBassAdmin()
	c.replaceCaOrg(ca.CaName, ca.CaName)
	for _, v := range ca.CaAdmins {
		c.insertAdminIdentity(v.Name, v.Password)
	}
	for _, v := range ca.CSRName {
		c.insertCSR(v)
	}
	for _, v := range ca.Hostname {
		c.insertHost(v)
	}
	c.cleanflag()
}
