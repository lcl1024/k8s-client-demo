package configpath

import (
	"os"
	"path"

	"ILIOS/common/viper"

)

func CryptoFilePath(userid string) string {
	return "/crypto/"
}

func ConfigtxgenFilePath(userid string) string {
	return path.Join(NfsUserLocation(userid), userid+"/configtxgen/")
}

func GetCryptoTmpPath(userid string) string {
	return path.Join(GetConfigTxTmpPath(userid), CryptoFilePath(userid))
}

func GetConfigTxTmpPath(userid string) string {
	wd, _ := os.Getwd()
	return path.Join(wd, viper.GetString("baas.tmpbasepath"), ConfigtxgenFilePath(userid))
}

func NfsUserLocation(userid string) string {
	nfspath := path.Join(viper.GetString("storage.nfs.path"), viper.GetString("storage.basepath"), viper.GetString("storage.blockchainpath"), "Users")
	return nfspath
}

func GetBaaSTmpPath(userid string) string {
	wd, _ := os.Getwd()
	return path.Join(wd, viper.GetString("baas.tmpbasepath"), path.Join(NfsUserLocation(userid), userid))
}

func GetBaasUserPath() string {
	wd, _ := os.Getwd()
	return path.Join(wd, viper.GetString("baas.tmpbasepath"), NfsUserLocation(""))
}

func GetK8sConfigPath(userid string) string {
	return path.Join(GetBaaSTmpPath(userid), "k8s")
}

func GetGenesisBlockPath(userid string) string {
	return path.Join(GetConfigTxTmpPath(userid), "genesis.block")
}

func GetChannelTxPath(userid string, channelid string) string {
	return path.Join(GetConfigTxTmpPath(userid), "./channel-artifacts/"+channelid+".tx")
}

func GetBrotherBaasSynPath(userid string) string {
	return path.Join(GetBaaSTmpPath(userid), "baas/synchronous")
}

func GetBrotherBaasSetupPath(userid string) string {
	return path.Join(GetBaaSTmpPath(userid), "baas")
}

func BlockchainSetupResPath(userid string) string {
	pa := path.Join(GetBaaSTmpPath(userid))
	pa = path.Join(pa, "blockchain")
	//logs.Info("BlockchainSetupResPath ", pa)
	return pa
}
func BlockchainSetupPath(userid string) string {
	pa := path.Join(GetBaaSTmpPath(userid))
	pa = path.Join(pa, "setup")
	//logs.Info("BlockchainSetupResPath ", pa)
	return pa
}

func BlockchainBlockPositionDBPath(userid string) string {
	pa := path.Join(GetBaaSTmpPath(userid))
	pa = path.Join(pa, "block.db")
	//logs.Info("BlockchainBlockPositionDBPath ", pa)
	return pa
}

func BlockchainLookforwardPosPath(userid string, channelid string) string {
	pa := path.Join(GetBaaSTmpPath(userid))
	pa = path.Join(pa, "lookforward."+channelid)
	//logs.de("BlockchainLookforwardPosPath ", pa)
	return pa
}
