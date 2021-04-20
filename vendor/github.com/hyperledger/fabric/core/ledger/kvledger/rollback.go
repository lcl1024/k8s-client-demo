/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kvledger

import (
	"github.com/hyperledger/fabric/common/ledger/blkstorage/fsblkstorage"
	"github.com/hyperledger/fabric/common/ledger/datadump"
	"github.com/hyperledger/fabric/common/ledger/util/leveldbhelper"
	"github.com/hyperledger/fabric/core/ledger/ledgerconfig"
	"github.com/hyperledger/fabric/core/ledger/ledgerstorage"
	"github.com/pkg/errors"
)

// RollbackKVLedger rollbacks a ledger to a specified block number
func RollbackKVLedger(ledgerID string, blockNum uint64) error {
	fileLock := leveldbhelper.NewFileLock(ledgerconfig.GetFileLockPath())
	if err := fileLock.Lock(); err != nil {
		return errors.Wrap(err, "as another peer node command is executing,"+
			" wait for that command to complete its execution or terminate it before retrying")
	}
	defer fileLock.Unlock()
	dumpConf := &datadump.DumpConf{
		Enabled:        ledgerconfig.IsDataDumpEnabled(),
		DumpDir:        ledgerconfig.GetDataDumpPath(),
		LoadDir:        ledgerconfig.GetDataLoadPath(),
		MaxFileLimit:   ledgerconfig.GetDataDumpFileLimit(),
		DumpCron:       ledgerconfig.GetDataDumpCron(),
		DumpInterval:   ledgerconfig.GetDataDumpInterval(),
		LoadRetryTimes: ledgerconfig.GetDataLoadRetryTimes(),
	}
	conf := fsblkstorage.NewConf(ledgerconfig.GetBlockStorePath(), ledgerconfig.GetMaxBlockfileSize(), dumpConf)
	blockstorePath := ledgerconfig.GetBlockStorePath()
	if err := ledgerstorage.ValidateRollbackParams(blockstorePath, ledgerID, blockNum, conf); err != nil {
		return err
	}

	logger.Infof("Dropping databases")
	if err := dropDBs(); err != nil {
		return err
	}

	logger.Info("Rolling back ledger store")
	if err := ledgerstorage.Rollback(blockstorePath, ledgerID, blockNum, conf); err != nil {
		return err
	}
	logger.Infof("The channel [%s] has been successfully rolled back to the block number [%d]", ledgerID, blockNum)
	return nil
}
