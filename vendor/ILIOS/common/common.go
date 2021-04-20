package common

import (
	"ILIOS/common/flogging"
	"ILIOS/common/packager"
	"ILIOS/core/configpath"
	"time"

	"io/ioutil"
	"net/url"
	"os"
	"path"
	"strings"

	"ILIOS/common/viper"

	"fmt"

	"github.com/astaxie/beego"
	"github.com/astaxie/beego/logs"
)

const (
	STORAGETYPELOCAL = "local"
	STORAGETYPENFS   = "nfs"
)

type NodeType int

const (
	NodeTypeCa        NodeType = iota
	NodeTypePeer
	NodeTypeOrderer
	NodeTypeZookeeper
	NodeTypeKafka
)

const PostGresPassword = "capostgres"

const DbSqlite = "sqlite3"
const DBPostGres = "postgres"

// PubChannelid ...
// 这里的id不能随意更改，config.yaml里要用到
const PubChannelid = "publicchannel"
const MonitorChannelid = "monitorchannel"

// Pubchaincodename ...
const PubCCName = "bcsetupmanager"

// PubCCVersion ...
const PubCCVersion = "1.0"

// Publicchannel Encrypt key

var myViper = viper.New()
var KubeServerUrl string

type PublicCC struct {
	ChainCode []ChainCode
	CCPackage [][]byte
}
type ChainCode struct {
	CCName    string `mapstructure:"name"`
	CCChannel string `mapstructure:"channelid"`
}

type ExternalUrlSetting struct {
	Enbaled      bool         `mapstructure:"enabled"`
	ExternalType ExternalType `mapstructure:"externalType"`
}

type ExternalType struct {
	Orderer   map[string]ExternalUrl `mapstructure:"orderer"`
	Kafka     map[string]ExternalUrl `mapstructure:"kafka"`
	Zookeeper map[string]ExternalUrl `mapstructure:"zookeeper"`
}

type ExternalUrl struct {
	Ports []ExternalPort `mapstructure:"ports"`
	Ip    string         `mapstructure:"ip"`
}
type ExternalPort struct {
	From int `mapstructure:"from"`
	To   int `mapstructure:"to"`
}

var publicCC PublicCC

func init() {
	Init("config", path.Join(Getwd(), "conf/"))
	//if os.Getenv("GOPATH") == "" {
	//	logs.Warning("Can't find GOPATH, set GOPATH")
	//	gopath := path.Join(Getwd(), "gopath")
	//	os.Mkdir(gopath, 0755)
	//	err := os.Setenv("GOPATH", gopath)
	//	if err != nil {
	//		logs.Error("Can't set GOPATH", err)
	//	}
	//}
	//if GetBCCSP() == "GM" {
	//	logs.Debug("*********开启国密********")
	//}
	//if GetNamespaceCreated() == false {
	//	logs.Debug("*********需要创建namespace********")
	//}
	//logs.Debug("*********vm.endpoint %s********", GetVmEndpoint())
}

//InitConfig initializes viper config
func Init(cmdRoot string, envpath string) error {
	viper.AddConfigPath(envpath) // Path to look for the config file in
	logs.Info("envpath", envpath)
	// Now set the configuration file.
	viper.SetConfigName(cmdRoot) // Name of config file (without extension)
	err := viper.ReadInConfig()  // Find and read the config file
	if err != nil {
		logs.Error(err) // Handle errors reading the config file
		return fmt.Errorf("Fatal error when reading %s config file: %s\n", cmdRoot, err)
	}
	//initPublicCC()
	return nil
}

func initPublicCC() {
	chaincode := []ChainCode{}
	err := viper.UnmarshalKey("publicchaincode.chaincode", &chaincode)
	if err != nil {
		logs.Error(err)
		panic(err)
	}
	logs.Debug("chaincode %+v", chaincode)
	packages := [][]byte{}
	wd, _ := os.Getwd()
	goPath := path.Join(wd, beego.AppConfig.String("ILIOS"), "chaincode", "package")
	for _, v := range chaincode {
		ccfilename := path.Join(goPath, v.CCName+".tar.gz")
		if FileExists(ccfilename) {
			logs.Debug("*****read cc from package******")
			chaincodePackage, err := ioutil.ReadFile(ccfilename)
			if err != nil {
				logs.Error(err)
				panic(err)
			}
			packages = append(packages, chaincodePackage)
		} else {
			chaincodePackage, err := packager.PackageCC(v.CCName, "")
			if err != nil {
				logs.Error(err)
				panic(err)
			}
			packages = append(packages, chaincodePackage)
			os.MkdirAll(goPath, 0755)
			err = ioutil.WriteFile(ccfilename, chaincodePackage, 0755)
			if err != nil {
				logs.Error(err)
				panic(err)
			}
		}
	}
	publicCC = PublicCC{
		ChainCode: chaincode,
		CCPackage: packages,
	}
}

func GetPublicCC() PublicCC {
	return publicCC
}
func InitConfig(cmdRoot string, envpath string, config *viper.Viper) error {
	config.AddConfigPath(envpath) // Path to look for the config file in

	// Now set the configuration file.
	config.SetConfigName(cmdRoot) // Name of config file (without extension)
	err := config.ReadInConfig()  // Find and read the config file
	if err != nil {
		logs.Error(err) // Handle errors reading the config file
		return fmt.Errorf("Fatal error when reading %s config file: %s\n", cmdRoot, err)
	}
	return nil
}

// SetLogLevelFromViper sets the log level for 'module' logger to the value in
// core.yaml
func SetLogLevelFromViper(module string) error {
	var err error
	if module != "" {
		logLevelFromViper := viper.GetString("logging." + module)
		_, err = flogging.SetModuleLevel(module, logLevelFromViper)
	}
	return err
}

func GetKubeServerUrl() string {
	slaveip := viper.GetString("custombaasip")
	if slaveip != "" {
		logs.Debug("GetKubeServerUrl", slaveip)
		return viper.GetString("custombaasip")
	}

	if KubeServerUrl == "" {
		configfile := viper.GetString("kuberneteconfig")
		basepath := path.Join(Getwd(), "conf")
		logs.Debug("KubeServer config path", basepath)

		myViper.AddConfigPath(basepath)
		myViper.SetConfigType("yaml")
		myViper.SetConfigName(filenameWithSuffix(path.Join(basepath, configfile)))
		// If a config file is found, read it in.
		err := myViper.ReadInConfig()

		if err != nil {
			logs.Error(err)
			panic(err)
		}
		clusters := (myViper.Get("clusters")).([]interface{})
		if len(clusters) == 0 {
			panic("k8s配置信息有误")
		}
		cluster0 := clusters[0].(map[interface{}]interface{})
		cluster := cluster0["cluster"].(map[interface{}]interface{})
		u, err := url.Parse(cluster["server"].(string))
		if err != nil {
			panic("k8s配置信息有误")
		}
		strs := strings.Split(u.Host, ":")
		KubeServerUrl = strs[0]
	}
	logs.Info("KubeServerUrl ", KubeServerUrl)
	return KubeServerUrl
}

func GetExternalIpOrDomainName(nodetype NodeType) string {
	if isExternalIpOrDomainNameEnabled() == false {
		return GetKubeServerUrl()
	} else {
		if nodetype == NodeTypeOrderer {
			return viper.GetString("externalIpOrDomainName.custom.orderer")
		} else if nodetype == NodeTypePeer {
			return viper.GetString("externalIpOrDomainName.custom.peer")
		} else if nodetype == NodeTypeCa {
			return viper.GetString("externalIpOrDomainName.custom.ca")
		} else if nodetype == NodeTypeKafka {
			return viper.GetString("externalIpOrDomainName.custom.kafka")
		} else if nodetype == NodeTypeZookeeper {
			return viper.GetString("externalIpOrDomainName.custom.zookeeper")
		}
	}
	return ""

}

func isExternalIpOrDomainNameEnabled() bool {
	return viper.GetBool("externalIpOrDomainName.enabled")
}

func filenameWithSuffix(fullFilename string) string {
	filenameWithSuffix := path.Base(fullFilename)
	fileSuffix := path.Ext(fullFilename)
	filenameOnly := strings.TrimSuffix(filenameWithSuffix, fileSuffix)
	return filenameOnly
}

func Getwd() string {
	wd, _ := os.Getwd()
	//basepath := path.Join(wd, beego.AppConfig.String("ILIOS"))
	basepath := wd
	return basepath
}

func GetAllUsers() []string {
	fileinfos, err := ioutil.ReadDir(configpath.GetBaasUserPath())
	if err != nil {
		//logs.Error(err)
		return []string{}
	}
	users := []string{}
	for _, v := range fileinfos {
		if v.IsDir() {
			users = append(users, v.Name())
		}
	}
	return users
}

func IsAutoSignature() bool {
	res, err := beego.AppConfig.Bool("autosignature")
	if err != nil {
		return false
	}
	return res
}

func GetUrlPrefix() string {
	if IsTlsEnabled() {
		return "grpcs://"
	}
	return "grpc://"
}

func IsTlsEnabled() bool {
	return viper.GetBool("fabric.tls.enabled")
}

func IsTlsAutoGenerate() bool {
	return viper.GetBool("fabric.tls.autogenerate")
}

//ShowDecryptFile pro模式会强制关闭
func ShowDecryptFile() bool {
	if IsDevMode() == ModePro {
		return false
	}
	return viper.GetBool("decrypt")
}

func GetCaDbType() string {
	return viper.GetString("cadb")
}

func GetBlockSyncTime() time.Duration {
	logs.Debug("GetBlockSyncTime", viper.GetDuration("blockSyncTime"))
	return viper.GetDuration("blockSyncTime")
}

//SaveSdkYaml pro模式会强制关闭
func SaveSdkYaml() bool {
	if IsDevMode() == ModePro {
		return false
	}
	return viper.GetBool("fabric.sdk.savesdkyaml")
}

func GetBCCSP() string {
	bccsp := viper.GetString("fabric.BCCSP.Default")
	if bccsp == "" {
		return "SW"
	}
	return bccsp
}

func GetBaasdtrName() string {
	return viper.GetString("baasdtrname")
}

func GetResourceStorage() string {
	storage := viper.GetString("storage.pvc.resourcestorage")
	if storage == "" {
		return "50G"
	}
	return storage
}

func GetPvcName() string {
	return viper.GetString("storage.pvc.claimName")
}

func GetNamespaceCreated() bool {
	return viper.GetBool("namespacecreated")
}

func GetVmEndpoint() string {
	return viper.GetString("fabric.vm.endpoint")
}

func GetChaincodePeerAddressExternal() bool {
	return viper.GetBool("fabric.chaincode.peerAddressExternal")
}

type NodeSelector struct {
	Key   string
	Value string
}

func GetNodeSelector() NodeSelector {
	key := viper.GetString("nodeselector.key")
	value := viper.GetString("nodeselector.value")
	if key == "" {
		key = "ilios"
	}
	if value == "" {
		value = "true"
	}
	return NodeSelector{
		Key:   key,
		Value: value,
	}
}

const (
	//ModeDev 开发者模式 打印信息
	ModeDev string = "dev"
	//ModePro 发布��式
	ModePro string = "pro"
)

var mode = ModeDev

func IsDevMode() string {
	mode = viper.GetString("mode")
	if mode == ModeDev {
		mode = ModeDev
	} else if mode == ModePro {
		mode = ModePro
	} else {
		logs.Error(viper.GetString("mode"), " mode do not exist")
	}
	return mode
}
