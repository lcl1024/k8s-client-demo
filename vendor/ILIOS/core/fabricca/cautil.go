package fabricca

import (
	"ILIOS/common"
	"ILIOS/core/configpath"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/astaxie/beego/logs"
	yaml "github.com/ghodss/yaml"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/util"
)

var FabricCaServerConfig = ""

const FabricCaServerSqliteConfig = "fabric-ca-server.yaml"
const FabricCaServerPostgresConfig = "fabric-ca-server-postgres.yaml"
const FabricCaClientConfig = "fabric-ca-client.yaml"

const BaaSAdminFile = "BaaSAdminUser"
const BaaSAdminPasswdFile = "BaaSAdminPasswd"

const AdminFlag = "#<***ADMIN-INSERT***>"
const AdminTemplate = `    - name: <<<ADMIN>>>
      pass: <<<ADMINPW>>>
      type: client
      affiliation: ""
      maxenrollments: -1
      attrs:
        hf.Registrar.Roles: "user,app,peer,orderer,client,validator,auditor"
        hf.Registrar.DelegateRoles: "user,app,peer,orderer,client,validator,auditor"
        hf.Revoker: true
        hf.IntermediateCA: true
`

const CsrFlag = "#<***CSR-INSERT***>"
const CsrTemplate = `    - C: <<<C>>>
      ST: <<<ST>>>
      L: <<<L>>>
      O: <<<O>>>
      OU: <<<OU>>>
`
const HostFlag = "#<***HOST-INSERT***>"
const HostTemplate = `    - <<<MYHOST>>>
`

type BaaSAdmin struct {
	BaaSAdminUser   string
	BaaSAdminPasswd string
}
type CaAdmin struct {
	CaAdminUser   string
	CaAdminPasswd string
}

func init() {
	//if common.GetCaDbType() == common.DbSqlite {
	//	FabricCaServerConfig = FabricCaServerSqliteConfig
	//} else if common.GetCaDbType() == common.DBPostGres {
	//	FabricCaServerConfig = FabricCaServerPostgresConfig
	//} else {
	//	panic("不支持的数据库类型，仅支持sqlite3,postgres")
	//}
}

func ReadCaServerConfig() *lib.ServerConfig {
	return readCaServerConfig()
}

func readCaServerConfig() *lib.ServerConfig {
	basepath := filepath.Join(common.Getwd(), "core/fabricca", FabricCaServerConfig)
	logs.Info("ca path", basepath)
	data, err := ioutil.ReadFile(basepath)
	if err != nil {
		logs.Error("Can't find " + FabricCaServerConfig)
		return nil
	}
	config := lib.ServerConfig{}
	err = yaml.Unmarshal(data, &config)
	logs.Info("%+v", config)
	if err != nil {
		logs.Error("Unmarshal " + FabricCaServerConfig + " Error")
		return nil
	}
	return &config
}

func ReadCaConfig() *lib.CAConfig {
	basepath := filepath.Join(common.Getwd(), "core/fabricca", FabricCaServerConfig)
	logs.Info("ca path", basepath)
	data, err := ioutil.ReadFile(basepath)
	if err != nil {
		logs.Error("Can't find " + FabricCaServerConfig)
		return nil
	}
	config := lib.CAConfig{}
	err = yaml.Unmarshal(data, &config)
	logs.Info("%+v", config)
	if err != nil {
		logs.Error("Unmarshal " + FabricCaServerConfig + " Error")
		return nil
	}
	return &config
}
func readCaClientConfig() *lib.ClientConfig {
	basepath := filepath.Join(common.Getwd(), "core/fabricca", FabricCaClientConfig)
	logs.Info("ca path", basepath)
	data, err := ioutil.ReadFile(basepath)
	if err != nil {
		logs.Error("Can't find " + FabricCaClientConfig)
		return nil
	}
	config := lib.ClientConfig{}
	err = yaml.Unmarshal(data, &config)
	logs.Info("%+v", config)
	if err != nil {
		logs.Error("Unmarshal " + FabricCaClientConfig + " Error")
		return nil
	}
	//config.CSP.ProviderName = common.GetBCCSP()
	return &config
}
func CreateCustomConfigFile(adminuser string, adminpassword string, orgname string, orgdomain string) *lib.ServerConfig {
	config := readCaServerConfig()
	config.CAcfg.CA.Name = orgname
	config.CAcfg.CSR.CN = orgname
	config.CAcfg.CSR.Hosts[0] = orgdomain
	config.CAcfg.CSR.CA.PathLength = 0
	config.CAcfg.Registry.Identities[0].Name = adminuser
	config.CAcfg.Registry.Identities[0].Pass = adminpassword
	logs.Info(config)
	return config
}

func ExportToYaml(config interface{}) []byte {
	str, _ := yaml.Marshal(config)
	logs.Info(string(str))
	return str
}

func CustomConfigFile(adminuser string, adminpassword string, caname string, orgname string, orgdomain string) (string, BaaSAdmin) {
	basepath := filepath.Join(common.Getwd(), "core/fabricca", FabricCaServerConfig)
	logs.Info("ca path", basepath)
	data, err := ioutil.ReadFile(basepath)
	if err != nil {
		panic("Can't find " + FabricCaServerConfig)
	}
	admin := createBaasAdmin()
	cfg := string(data)
	// Do string subtitution to get the default config
	cfg = strings.Replace(cfg, "<<<ADMIN>>>", adminuser, 1)
	cfg = strings.Replace(cfg, "<<<ADMINPW>>>", adminpassword, 1)
	cfg = strings.Replace(cfg, "<<<MYHOST>>>", orgdomain, 1)
	cfg = strings.Replace(cfg, "<<<CANAME>>>", orgname, 1)
	// This is a root CA
	cfg = strings.Replace(cfg, "<<<COMMONNAME>>>", caname, 1)
	cfg = strings.Replace(cfg, "<<<PATHLENGTH>>>", "1", 1)
	cfg = strings.Replace(cfg, "<<<ORGNAME>>>", orgname, 1)

	// baasadmin
	cfg = strings.Replace(cfg, "<<<BAASADMIN>>>", admin.BaaSAdminUser, 1)
	cfg = strings.Replace(cfg, "<<<BAASADMINPW>>>", admin.BaaSAdminPasswd, 1)

	return cfg, admin
}

func storeCAChain(config *lib.ClientConfig, si *lib.GetServerInfoResponse) error {
	mspDir := config.MSPDir
	// Get a unique name to use for filenames
	serverURL, err := url.Parse(config.URL)
	if err != nil {
		return err
	}
	fname := serverURL.Host
	if config.CAName != "" {
		fname = fmt.Sprintf("%s-%s", fname, config.CAName)
	}
	fname = strings.Replace(fname, ":", "-", -1)
	fname = strings.Replace(fname, ".", "-", -1) + ".pem"
	// Split the root and intermediate certs
	block, intermediateCerts := pem.Decode(si.CAChain)
	if block == nil {
		return errors.New("No root certificate was found")
	}
	rootCert := pem.EncodeToMemory(block)
	dirPrefix := dirPrefixByProfile(config.Enrollment.Profile)
	// Store the root certificate in "cacerts"
	certsDir := fmt.Sprintf("%scacerts", dirPrefix)
	err = storeFile("CA root certificate", mspDir, certsDir, fname, rootCert)
	if err != nil {
		return err
	}
	// Store the intermediate certs if there are any
	if len(intermediateCerts) > 0 {
		certsDir = fmt.Sprintf("%sintermediatecerts", dirPrefix)
		err = storeFile("CA intermediate certificates", mspDir, certsDir, fname, intermediateCerts)
		if err != nil {
			return err
		}
	}
	return nil
}

func createBaasAdmin() BaaSAdmin {
	return BaaSAdmin{
		BaaSAdminUser:   util.RandomString(12),
		BaaSAdminPasswd: util.RandomString(12),
	}
}

func storeFile(what, mspDir, subDir, fname string, contents []byte) error {
	dir := path.Join(mspDir, subDir)
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		return fmt.Errorf("Failed to create directory for %s at '%s': %s", what, dir, err)
	}
	fpath := path.Join(dir, fname)
	err = util.WriteFile(fpath, contents, 0644)
	if err != nil {
		return fmt.Errorf("Failed to store %s at '%s': %s", what, fpath, err)
	}
	return nil
}

// Return the prefix to add to the "cacerts" and "intermediatecerts" directories
// based on the target profile.  If the profile is "tls", these directories become
// "tlscacerts" and "tlsintermediatecerts", respectively.  There is no prefix for
// any other profile.
func dirPrefixByProfile(profile string) string {
	if profile == "tls" {
		return "tls"
	}
	return ""
}

func getRootCert(resp *lib.EnrollmentResponse) ([]byte, error) {
	block, _ := pem.Decode(resp.ServerInfo.CAChain)
	if block == nil {
		return nil, errors.New("No root certificate was found")
	}
	rootCert := pem.EncodeToMemory(block)
	return rootCert, nil
}

func AllRoles() []string {
	return []string{"user", "app", "peer", "orderer", "client", "validator", "auditor"}
}

func AllAttributes() []string {
	return []string{"hf.Registrar.Roles", "hf.Registrar.DelegateRoles", "hf.Revoker", "hf.IntermediateCA"}
}

func MspEnrollPath(userid string, caname string, causer string) string {
	pa := path.Join(configpath.GetBaaSTmpPath(userid), "ca", caname, "users", causer, "msp")
	return pa
}

func OrgMspPath(userid string, caname string) string {
	if caname == BaaSOrgName() { //默认公共链baasorg的msp地址
		return BaaSOrgMspPath()
	} else {
		pa := path.Join(configpath.GetBaaSTmpPath(userid), "ca", caname, "msp")
		return pa
	}

}

//CustomFabricTLSPath 自定义的tls证书路径
func CustomFabricTLSPath(commonname string) string {
	pa := filepath.Join(common.Getwd(), "conf/tls", commonname)
	return pa
}

//OrgMspPath 公有��������baasorg组织
func BaaSOrgName() string {
	return "baasorg"
}

func BaaSOrgMspPath() string {
	pa := filepath.Join(common.Getwd(), "cert/baasorg/msp")
	return pa
}

func BaaSOrgAdminPath() string {
	pa := filepath.Join(common.Getwd(), "cert/baasorg/msp")
	return pa

}

func getMspPath(userid string, caname string, msptype string) []string {
	pa := path.Join(configpath.GetBaaSTmpPath(userid), "ca", caname, "users")
	fileinfos, _ := ioutil.ReadDir(pa)
	paths := []string{}
	for _, v := range fileinfos {
		if strings.Contains(v.Name(), msptype) == true {
			paths = append(paths, path.Join(pa, v.Name(), "msp"))
		}
	}
	return paths
}

func PeerAdminMspPath(userid string, caname string) []string {
	return getMspPath(userid, caname, "adminpeer")
}
func PeerUserMspPath(userid string, caname string) []string {
	return getMspPath(userid, caname, "userpeer")
}
func OrdererAdminMspPath(userid string, caname string) []string {
	return getMspPath(userid, caname, "adminpeer")
}
func OrdererUserMspPath(userid string, caname string) []string {
	return getMspPath(userid, caname, "userorderer")
}

func CaServerConfigPath(userid string, orgname string) string {
	pa := path.Join(configpath.GetBaaSTmpPath(userid), "ca", orgname)
	pa = path.Join(pa, FabricCaServerConfig)
	return pa
}

func CaKeystorePath(userid string, orgname string) string {
	pa := path.Join(configpath.GetBaaSTmpPath(userid), "ca", orgname, "ca")
	return pa
}
func CaTLSKeystorePath(userid string, orgname string) string {
	pa := path.Join(configpath.GetBaaSTmpPath(userid), "ca", orgname, "tlsca")
	return pa
}
func UserTLSKeystorePath(userid string, orgname string, username string) string {
	pa := path.Join(configpath.GetBaaSTmpPath(userid), "ca", orgname, "users", username, "tls")
	return pa
}

func BaaSAdminUserPath(userid string, orgname string) string {
	pa := path.Join(configpath.GetBaaSTmpPath(userid), "ca", orgname)
	pa = path.Join(pa, BaaSAdminFile)
	return pa
}

func BaaSAdminPasswordPath(userid string, orgname string) string {
	pa := path.Join(configpath.GetBaaSTmpPath(userid), "ca", orgname)
	pa = path.Join(pa, BaaSAdminPasswdFile)
	return pa
}

func readFile(dir string) (MspFile, error) {
	filelist, err := ioutil.ReadDir(dir)
	if err != nil {
		logs.Error("Can't find " + dir)
		return MspFile{}, err
	}
	if len(filelist) != 0 {
		filepath := path.Join(dir, filelist[0].Name())
		logs.Info("filepath", filepath)
		priv, err := ioutil.ReadFile(filepath)
		if err != nil {
			return MspFile{}, err
		}
		return MspFile{
			Name:    filelist[0].Name(),
			Content: priv,
			Path:    filepath,
		}, nil
	}
	return MspFile{}, fmt.Errorf("No File in Dir %s", dir)
}

func keystore(userid string, caname string, causer string) (MspFile, error) {
	msp := MspEnrollPath(userid, caname, causer)
	return readFile(path.Join(msp, "keystore"))
}
func cacerts(userid string, caname string, causer string) (MspFile, error) {
	msp := MspEnrollPath(userid, caname, causer)
	return readFile(path.Join(msp, "cacerts"))
}
func signcerts(userid string, caname string, causer string) (MspFile, error) {
	msp := MspEnrollPath(userid, caname, causer)
	return readFile(path.Join(msp, "signcerts"))
}
func tlscacertspath(userid string, caname string, causer string) string {
	msp := MspEnrollPath(userid, caname, causer)
	return path.Join(msp, "tlscacerts")
}

func tlscacerts(userid string, caname string, causer string) (MspFile, error) {
	msp := MspEnrollPath(userid, caname, causer)
	return readFile(path.Join(msp, "tlscacerts"))
}

type CommonFunc struct{}

var commonFunc CommonFunc

func (c *CommonFunc) Merge(s ...[]byte) (slice []byte) {
	switch len(s) {
	case 0:
		break
	case 1:
		slice = s[0]
		break
	default:
		s1 := s[0]
		s2 := commonFunc.Merge(s[1:]...) //...将数组元素打散
		slice = make([]byte, len(s1)+len(s2))
		copy(slice, s1)
		copy(slice[len(s1):], s2)
		break
	}
	return
}
