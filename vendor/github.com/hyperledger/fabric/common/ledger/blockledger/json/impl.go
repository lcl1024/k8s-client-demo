/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jsonledger

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/hyperledger/fabric/common/ledger/util"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/golang/protobuf/jsonpb"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/common/ledger/blockledger"
	"github.com/hyperledger/fabric/common/ledger/datadump"
	cb "github.com/hyperledger/fabric/protos/common"
	ab "github.com/hyperledger/fabric/protos/orderer"
	"github.com/pkg/errors"
)

var logger = flogging.MustGetLogger("common.ledger.blockledger.json")

var closedChan chan struct{}
var fileLock, configBlockLock sync.Mutex

func init() {
	closedChan = make(chan struct{})
	close(closedChan)
}

const (
	blockFileFormatString      = "block_%020d.json"
	tarFileFormatString        = "block_%020d_%020d.tar"
	chainDirectoryFormatString = "chain_%s"
	configBlockFileName        = "config.block"
)

type cursor struct {
	jl          *jsonLedger
	blockNumber uint64
}

type jsonLedger struct {
	directory string
	height    uint64
	lastHash  []byte
	marshaler *jsonpb.Marshaler

	mutex        sync.Mutex
	signal       chan struct{}
	oldestHeight uint64
	dumpConf     *datadump.DumpConf
}

// readBlock returns the block or nil, and whether the block was found or not, (nil,true) generally indicates an irrecoverable problem
func (jl *jsonLedger) readBlock(number uint64) (*cb.Block, bool) {
	name := jl.blockFilename(number)

	// In case of ongoing write, reading the block file may result in `unexpected EOF` error.
	// Therefore, we use file mutex here to prevent this race condition.
	fileLock.Lock()
	defer fileLock.Unlock()

	file, err := os.Open(name)
	if err == nil {
		defer file.Close()
		block := &cb.Block{}
		err = jsonpb.Unmarshal(file, block)
		if err != nil {
			return nil, true
		}
		logger.Debugf("Read block %d", block.Header.Number)
		return block, true
	}
	return nil, false
}

// Next blocks until there is a new block available, or returns an error if the
// next block is no longer retrievable
func (cu *cursor) Next() (*cb.Block, cb.Status) {
	// This only loops once, as signal reading
	// indicates the new block has been written
	for {
		block, found := cu.jl.readBlock(cu.blockNumber)
		if found {
			if block == nil {
				return nil, cb.Status_SERVICE_UNAVAILABLE
			}
			cu.blockNumber++
			return block, cb.Status_SUCCESS
		}

		// copy the signal channel under lock to avoid race
		// with new signal channel in append
		cu.jl.mutex.Lock()
		signal := cu.jl.signal
		cu.jl.mutex.Unlock()
		<-signal
	}
}

func (cu *cursor) Close() {}

// Iterator returns an Iterator, as specified by a ab.SeekInfo message, and its
// starting block number
func (jl *jsonLedger) Iterator(startPosition *ab.SeekPosition) (blockledger.Iterator, uint64) {
	switch start := startPosition.Type.(type) {
	case *ab.SeekPosition_Oldest:
		return &cursor{jl: jl, blockNumber: 0}, 0
	case *ab.SeekPosition_Newest:
		high := jl.height - 1
		return &cursor{jl: jl, blockNumber: high}, high
	case *ab.SeekPosition_Specified:
		if start.Specified.Number > jl.height {
			return &blockledger.NotFoundErrorIterator{}, 0
		}
		return &cursor{jl: jl, blockNumber: start.Specified.Number}, start.Specified.Number
	default:
		return &blockledger.NotFoundErrorIterator{}, 0
	}
}

// Height returns the number of blocks on the ledger
func (jl *jsonLedger) Height() uint64 {
	return jl.height
}

// Append appends a new block to the ledger
func (jl *jsonLedger) Append(block *cb.Block) error {
	if block.Header.Number != jl.height {
		return errors.Errorf("block number should have been %d but was %d", jl.height, block.Header.Number)
	}

	if !bytes.Equal(block.Header.PreviousHash, jl.lastHash) {
		return errors.Errorf("block should have had previous hash of %x but was %x", jl.lastHash, block.Header.PreviousHash)
	}

	jl.writeBlock(block)
	jl.lastHash = block.Header.Hash()
	jl.height++

	if jl.dumpConf.Enabled {
		jl.DataDump(datadump.DumpForBlockFileLimit)
	}
	// Manage the signal channel under lock to avoid race with read in Next
	jl.mutex.Lock()
	close(jl.signal)
	jl.signal = make(chan struct{})
	jl.mutex.Unlock()
	return nil
}

func (jl *jsonLedger) DataDump(dumpReason int) error {
	logger.Debugf("Try to dump the blockfiles for [%d]:[%s]", dumpReason, datadump.DumpReasonIndex_name[dumpReason])

	//if no block,just return
	if jl.oldestHeight >= jl.height {
		logger.Debugf("BlockFile DataDump: there is nothing to dump")
		return nil
	}

	switch dumpReason {
	case datadump.DumpForCronTab:
		return jl.dataDump()
	case datadump.DumpForBlockFileLimit:
		blockLimit := jl.dumpConf.MaxFileLimit
		nowBlockCount := jl.height - jl.oldestHeight
		if nowBlockCount >= uint64(blockLimit) {
			return jl.dataDump()
		}
	}
	return fmt.Errorf("the reason for dump doesn't exist: [%d]", dumpReason)
}

func (jl *jsonLedger) WriteConfigBlockToSpecFile(block *cb.Block) error {
	if !jl.dumpConf.Enabled {
		return nil
	}
	name := filepath.Join(jl.directory, configBlockFileName)

	configBlockLock.Lock()
	defer configBlockLock.Unlock()

	file, err := os.Create(name)
	if err != nil {
		return err
	}
	defer file.Close()

	logger.Debug("Wrote config block")

	return jl.marshaler.Marshal(file, block)
}

func (jl *jsonLedger) ReadConfigBlockFromSpecFile() (*cb.Block, error) {
	if !jl.dumpConf.Enabled {
		return nil, fmt.Errorf("DataDump is not enabled, cannot read config block from spec file")
	}
	name := filepath.Join(jl.directory, configBlockFileName)

	// In case of ongoing write, reading the block file may result in `unexpected EOF` error.
	// Therefore, we use file mutex here to prevent this race condition.
	configBlockLock.Lock()
	defer configBlockLock.Unlock()

	file, err := os.Open(name)
	if err == nil {
		defer file.Close()
		block := &cb.Block{}
		err = jsonpb.Unmarshal(file, block)
		if err != nil {
			return nil, err
		}
		logger.Debugf("Read config block")
		return block, nil
	}
	return nil, err
}

// writeBlock commits a block to disk
func (jl *jsonLedger) writeBlock(block *cb.Block) {
	name := jl.blockFilename(block.Header.Number)

	fileLock.Lock()
	defer fileLock.Unlock()

	file, err := os.Create(name)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	err = jl.marshaler.Marshal(file, block)
	logger.Debugf("Wrote block %d", block.Header.Number)
	if err != nil {
		logger.Panicf("Error marshalling with block number [%d]: %s", block.Header.Number, err)
	}
}

// blockFilename returns the fully qualified path to where a block
// of a given number should be stored on disk
func (jl *jsonLedger) blockFilename(number uint64) string {
	return filepath.Join(jl.directory, fmt.Sprintf(blockFileFormatString, number))
}

type blockDumpInfo struct {
	StartBlockNum uint64
	EndBlockNum   uint64
}

func (jl *jsonLedger) dataLoad(number uint64) error {
	channel := filepath.Base(jl.directory)
	loadDir := filepath.Join(jl.dumpConf.LoadDir, channel)
	filename := fmt.Sprintf(blockFileFormatString, number)
	return util.LoadFileByNumber(loadDir, jl.directory, filename, number, tarFileFormatString)
}

// writeBlock commits a block to disk
func writeDumpIndex(filepath string, dumpInfo *blockDumpInfo) error {
	dumpInfoData, err := json.Marshal(dumpInfo)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filepath, dumpInfoData, 0666)
}

func (jl *jsonLedger) dataDump() error {
	fileLock.Lock()
	defer fileLock.Unlock()

	//做数据归档的时候留下最后一个block不压缩
	currentHeight := jl.height - 1
	var blockFiles []string
	startBlockNum := jl.height
	endBlockNum := jl.oldestHeight
	for idx := jl.oldestHeight; idx < currentHeight; idx++ {
		name, _ := filepath.Abs(jl.blockFilename(idx))
		if ok, _, _ := util.FileExists(name); ok {
			if fileTime, err := util.FileModTime(name); err == nil {
				if time.Now().Sub(fileTime) > jl.dumpConf.DumpInterval {
					blockFiles = append(blockFiles, name)
					endBlockNum = idx
				} else {
					break
				}
				if startBlockNum == jl.height {
					startBlockNum = idx
				}
			}

		}
	}
	if startBlockNum > endBlockNum {
		return nil
	}
	dumpInfo := &blockDumpInfo{
		StartBlockNum: startBlockNum,
		EndBlockNum:   endBlockNum,
	}
	writeDumpIndex(jl.directory+"/index", dumpInfo)
	indexPath, _ := filepath.Abs(jl.directory + "/index")
	blockFiles = append(blockFiles, indexPath)

	tarName := fmt.Sprintf(tarFileFormatString, startBlockNum, endBlockNum)
	channel := filepath.Base(jl.directory)
	if err := util.TarFiles(blockFiles, filepath.Join(jl.dumpConf.DumpDir, channel, tarName)); err != nil {
		return fmt.Errorf("Cannot tar the blockfiles for %s", err)
	}

	util.RemoveFiles(blockFiles)
	jl.oldestHeight = endBlockNum + 1
	return nil
}
