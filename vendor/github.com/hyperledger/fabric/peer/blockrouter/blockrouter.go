package blockrouter

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/common/tools/protolator"
	"github.com/hyperledger/fabric/core/ledger"
	"github.com/hyperledger/fabric/core/peer"
	"github.com/hyperledger/fabric/peer/leveldbshow"
	_ "github.com/hyperledger/fabric/protos/common"
	_ "github.com/hyperledger/fabric/protos/msp"
	_ "github.com/hyperledger/fabric/protos/orderer"
	_ "github.com/hyperledger/fabric/protos/peer"
)

var ChannelLedger map[string]ledger.PeerLedger

func getLedger(channelName string) ledger.PeerLedger {
	var lgr ledger.PeerLedger

	if _, ok := ChannelLedger[channelName]; !ok {
		lgr = peer.GetLedger(channelName)
		for lgr == nil {
			time.Sleep(1 * time.Second)
			lgr = peer.GetLedger(channelName)
		}
		ChannelLedger[channelName] = lgr
	} else {
		lgr = ChannelLedger[channelName]
	}
	return lgr
}

// 路由入口
func BlockRouter() http.Handler {
	r := gin.Default()
	r.LoadHTMLFiles("blockrouter/result.tmpl")
	r.Static("/static", "blockrouter/static")

	r.GET("/", getHelp)
	r.GET("/help", getHelp)
	r.GET("/channels", getChannels)
	r.GET("/channel/:name", getChainInfo)
	r.GET("/channel/:name/blknum/:num", getBlockByNum)
	r.GET("/channel/:name/blkhash/:hash", getBlockByHash)
	r.GET("/channel/:name/txid/:txid", getBlockByTxID)
	r.GET("/channel/:name/transid/:transid", getTransactionByID)
	r.GET("/statedb/:channel", getStateDBDataNoNS)
	r.GET("/statedb/:channel/:chaincode", getStateDBData)
	r.GET("/historydb/:channel/:chaincode", getHistoryDBData)

	return r
}

func getHelp(c *gin.Context) {
	c.String(200, `Usage: 
        0.<address>:<port>/help
        1.<address>:<port>/channels
        2.<address>:<port>/channel/<channel name>
        3.<address>:<port>/channel/<channel name>/blknum/<block number>
        4.<address>:<port>/channel/<channel name>/blkhash/<block hash>
        5.<address>:<port>/channel/<channel name>/txid/<TxID>
        6.<address>:<port>/channel/<channel name>/transid/<transaction ID>
        7.<address>:<port>/statedb/<channel name>/<chaincode name>
        8.<address>:<port>/historydb/<channel name>/<chaincode name>
    `)
}

func getChannels(c *gin.Context) {
	path := "/var/hyperledger/production/ledgersData/chains/chains"
	files, err := ioutil.ReadDir(path)
	if err != nil {
		log.Printf("Extract channel names error: %s", err)
	}

	var ChannelNames []string
	for _, file := range files {
		if file.IsDir() {
			ChannelNames = append(ChannelNames, file.Name())
		}
	}
	c.JSON(http.StatusOK, gin.H{"channel name:": ChannelNames})
}

func getChainInfo(c *gin.Context) {
	channelName := c.Params.ByName("name")
	lgr := getLedger(channelName)
	info, err := lgr.GetBlockchainInfo()
	if err != nil {
		log.Printf("Failed to get block info with error %s", err)
	}

	marshalAndResp(c, info)
}

func marshalAndResp(c *gin.Context, msg proto.Message) {
	content, err := Marshal2JSON(msg)

	if err != nil {
		log.Printf("Marshal %T failed: %s", msg, err)
	}

	c.HTML(http.StatusOK, "result.tmpl",
		gin.H{
			"json_data": string(content),
		},
	)
}

func getBlockByNum(c *gin.Context) {
	channelName := c.Params.ByName("name")
	num := c.Params.ByName("num")
	blkNum, err := strconv.ParseUint(string(num), 10, 64)
	if err != nil {
		log.Printf("Failed to parse block number with error %s", err)
	}

	lgr := getLedger(channelName)
	block, err := lgr.GetBlockByNumber(blkNum)
	if err != nil {
		log.Printf("Failed to get block number %d with error %s", blkNum, err)
	}

	marshalAndResp(c, block)
}

func getBlockByHash(c *gin.Context) {
	channelName := c.Params.ByName("name")
	blkHash := c.Params.ByName("hash")

	lgr := getLedger(channelName)

	hash, _ := base64.StdEncoding.DecodeString(blkHash)
	block, err := lgr.GetBlockByHash(hash)
	if err != nil {
		log.Printf("Failed to get block hash %s with error %s", hash, err)
	}

	marshalAndResp(c, block)
}

func getBlockByTxID(c *gin.Context) {
	channelName := c.Params.ByName("name")
	id := c.Params.ByName("txid")
	lgr := getLedger(channelName)
	block, err := lgr.GetBlockByTxID(id)
	if err != nil {
		log.Printf("Failed to get block txID %s with error %s", id, err)
	}

	marshalAndResp(c, block)
}

func getTransactionByID(c *gin.Context) {
	channelName := c.Params.ByName("name")
	id := c.Params.ByName("transid")
	lgr := getLedger(channelName)
	tx, err := lgr.GetTransactionByID(id)
	if err != nil {
		log.Printf("Failed to get transaction id %s with error %s", id, err)
	}

	marshalAndResp(c, tx)
}

func getStateDBData(c *gin.Context) {
	db := c.Param("channel")
	ns := c.Param("chaincode")

	msg := ""
	if kvList, err := leveldbshow.GetStateLevelDBData(db, ns); err == nil {
		for _, r := range kvList {
			msg += r + "\n"
		}
		c.String(http.StatusOK, msg)
	} else {
		c.String(http.StatusBadRequest, err.Error())
	}
}

// 直接读取statedb数据会有乱码，因为包含了大量配置数据
// 使用获取区块的方式获取数据
func getStateDBDataNoNS(c *gin.Context) {
	db := c.Param("channel")

	if kvList, err := leveldbshow.GetStateLevelDBData(db, ""); err == nil {
		msg := ""
		for _, r := range kvList {
			msg += r + "\n"
			log.Println(r)
		}
		c.String(http.StatusOK, msg)
	} else {
		c.String(http.StatusBadRequest, err.Error())
	}
}

func getHistoryDBData(c *gin.Context) {
	db := c.Param("channel")
	ns := c.Param("chaincode")

	if kvList, err := leveldbshow.GetHistoryLevelDBData(db, ns); err == nil {
		msg := ""
		for _, r := range kvList {
			msg += r + "\n"
		}
		c.String(http.StatusOK, msg)
	} else {
		c.String(http.StatusBadRequest, err.Error())
	}
}

// 将msg转换为json格式及解码
func Marshal2JSON(msg proto.Message) (string, error) {
	if msg == nil {
		return "", fmt.Errorf("block is nil")
	}
	buffer := &bytes.Buffer{}
	err := protolator.DeepMarshalJSON(buffer, msg)
	if err != nil {
		return "", err
	}
	return buffer.String(), err
}

/*
func main(){
    r := setupRouter()
    r.Run(":9099")
}
*/
