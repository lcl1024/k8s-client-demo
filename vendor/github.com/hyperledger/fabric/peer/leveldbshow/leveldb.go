package leveldbshow

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/common/ledger/util"
	"github.com/hyperledger/fabric/core/ledger/kvledger"
	"github.com/hyperledger/fabric/core/ledger/kvledger/txmgmt/statedb"
	"github.com/hyperledger/fabric/core/ledger/ledgermgmt"
)

type StateDBData struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type HistoryDBData struct {
	Ns       string `json:"Namespace"`
	Key      string `json:"Key"`
	BlockNum uint64 `json:"BlockNumber"`
	TxNum    uint64 `json:"TxNumber"`
	Value    string `json:"Value"`
}

var logger = flogging.MustGetLogger("leveldbcmd")

func GetStateLevelDBData(dbName string, ns string) ([]string, error) {
	ledgerProvider := ledgermgmt.GetLedgerProvider()
	dbProvider, err := kvledger.GetVdbProvider(ledgerProvider)
	if !checkErrIsNil(err) {
		return nil, err
	}

	db, err := dbProvider.GetDBHandle(dbName)
	if !checkErrIsNil(err) {
		return nil, err
	}
	defer db.Close()

	itr, err := db.GetStateRangeScanIterator(ns, "", "")
	if !checkErrIsNil(err) {
		return nil, err
	}
	defer itr.Close()

	var kvList []string
	for result, err := itr.Next(); result != nil; result, err = itr.Next() {
		if !checkErrIsNil(err) {
			return nil, err
		}
		vkv := result.(*statedb.VersionedKV)
		key := vkv.Key
		value, vErr := db.GetState(ns, key)
		if !checkErrIsNil(vErr) {
			continue
		}
		if value == nil {
			continue
		}

		dataJson, jErr := json.Marshal(StateDBData{key, string(value.Value)})
		if !checkErrIsNil(jErr) {
			return nil, jErr
		}
		kvList = append(kvList, string(dataJson))
		logger.Info("Key:", key, ", Value:", string(value.Value))
	}

	return kvList, nil
}

func GetHistoryLevelDBData(dbName string, ns string) ([]string, error) {
	ledgerProvider := ledgermgmt.GetLedgerProvider()
	dbProvider, err := kvledger.GetHistorydbProvider(ledgerProvider)
	if !checkErrIsNil(err) {
		return nil, err
	}

	db, err := dbProvider.GetDBHandle(dbName)
	if !checkErrIsNil(err) {
		return nil, err
	}

	dbHandler := db.GetDBHelper()
	itr := dbHandler.GetIterator(nil, nil)
	defer itr.Release()

	var resultList []string
	for itr.Next(); itr.Valid(); itr.Next() {
		//0x00x0这种情况是应对compositeKey，即fabric内部实现的一种类似Index功能
		byteList := bytes.SplitN(itr.Key(), []byte{0x0, 0x0}, 3)
		if len(byteList) != 3 {
			byteList = bytes.SplitN(itr.Key(), []byte{0x0}, 3)
			if len(byteList) != 3 {
				continue
			}
		}
		if ns == string(byteList[0]) {
			blocktranData := byteList[2]
			blockNum, bytesConsumed, _ := util.DecodeOrderPreservingVarUint64(blocktranData[0:])
			tranNum, _, _ := util.DecodeOrderPreservingVarUint64(blocktranData[bytesConsumed:])
			value := itr.Value()
			dataJson, err := json.Marshal(HistoryDBData{string(byteList[0]), string(byteList[1]), blockNum, tranNum, string(value)})
			if !checkErrIsNil(err) {
				return nil, err
			}
			resultList = append(resultList, string(dataJson))
			rStr := fmt.Sprintf("ns: %s, key: %s, blockNum: %d, txNum: %d, value: %s",
				byteList[0], byteList[1], blockNum, tranNum, value)
			logger.Info(rStr)
		}
	}

	return resultList, nil
}

func checkErrIsNil(err error) bool {
	if err != nil {
		fmt.Printf(err.Error())
		logger.Error(err.Error())
		return false
	} else {
		return true
	}
}
