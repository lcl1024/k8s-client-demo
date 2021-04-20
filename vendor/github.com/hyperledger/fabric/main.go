package main

import (
	"fmt"
	"wasabi/backEnd/services/sdk/ca-sdk"
)
var orgName = "org1"
var fabricOrgName = "baas1"
var mspDir = "msptest/org1"
var fabricDir = "/Users/yunphant/go/src/github.com/hyperledger/fabric/msptest/baas1"
var ip = "http://192.168.9.99"
var port = "7454"
func main() {
	mmanger, err:= ca_sdk.NewMspManager(ca_sdk.FabricCaClient_type, fabricOrgName, fabricDir, ip, port, "SW", "admin4", "adminpw4", false, "", "", "")
	if err != nil {
		fmt.Println("create mmanger failed err ", err)
		return
	}
	//_, err = mmanger.GenerateNodeMsp("jancan", nil, nil, sdk.ClientNode, false)
	////err = caClient.GenerateNodeMsp("peer0.org1.example.com", nil)
	//if err != nil {
	//	fmt.Println("create generate node msp failed err ", err)
	//	return
	//}

	err = mmanger.RevokerMsp([]string{"jancan"})
	if err != nil {
		fmt.Println("revoker jancan failed err ", err)
		return
	}

	//fmt.Println(caClient.AdminCommonName())
	//fmt.Println(caClient.AdminMSPDir())
	//fmt.Println(caClient.AdminCert())
	//fmt.Println(caClient.MSPDir())
	//fmt.Println(caClient.RootCert())
}
