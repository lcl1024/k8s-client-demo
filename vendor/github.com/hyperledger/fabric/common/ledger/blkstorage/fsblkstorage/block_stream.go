/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package fsblkstorage

import (
	"bufio"
	"fmt"
	"github.com/hyperledger/fabric/common/ledger/util"
	"io"
	"os"
	"path/filepath"

	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
)

// ErrUnexpectedEndOfBlockfile error used to indicate an unexpected end of a file segment
// this can happen mainly if a crash occurs during appening a block and partial block contents
// get written towards the end of the file
var ErrUnexpectedEndOfBlockfile = errors.New("unexpected end of blockfile")

// blockfileStream reads blocks sequentially from a single file.
// It starts from the given offset and can traverse till the end of the file
type blockfileStream struct {
	fileNum       int
	file          *os.File
	reader        *bufio.Reader
	currentOffset int64
	shouldDelete  bool
}

// blockStream reads blocks sequentially from multiple files.
// it starts from a given file offset and continues with the next
// file segment until the end of the last segment (`endFileNum`)
type blockStream struct {
	rootDir           string
	currentFileNum    int
	endFileNum        int
	currentFileStream *blockfileStream
	blockStoreageConf *Conf
}

// blockPlacementInfo captures the information related
// to block's placement in the file.
type blockPlacementInfo struct {
	fileNum          int
	blockStartOffset int64
	blockBytesOffset int64
}

///////////////////////////////////
// blockfileStream functions
////////////////////////////////////
func newBlockfileStream(rootDir string, blkStoreConf *Conf, fileNum int, startOffset int64) (*blockfileStream, error) {
	shouldDelete := false
	filePathF := deriveBlockfilePath(rootDir, fileNum)
	logger.Debugf("newBlockfileStream(): filePath=[%s], startOffset=[%d]", filePathF, startOffset)

	var file *os.File
	var err error
	_, err = os.Stat(filePathF)
	if err != nil {
		if os.IsNotExist(err) && blkStoreConf.dumpConf.Enabled {
			channel := filepath.Base(rootDir)
			srcDir := filepath.Join(blkStoreConf.dumpConf.LoadDir, channel)
			fileName := blockfilePrefix + fmt.Sprintf("%06d", fileNum)
			err := util.LoadFileByNumber(srcDir, rootDir, fileName, uint64(fileNum), tarFileFormatString)
			if err != nil {
				return nil, err
			} else {
				shouldDelete = true
			}
		} else {
			return nil, err
		}
	}
	if file, err = os.OpenFile(filePathF, os.O_RDONLY, 0600); err != nil {
		return nil, err
	}
	var newPosition int64
	if newPosition, err = file.Seek(startOffset, 0); err != nil {
		return nil, err
	}
	if newPosition != startOffset {
		panic(fmt.Sprintf("Could not seek file [%s] to given startOffset [%d]. New position = [%d]",
			filePathF, startOffset, newPosition))
	}
	s := &blockfileStream{fileNum, file, bufio.NewReader(file), startOffset, shouldDelete}
	return s, nil
}

func (s *blockfileStream) nextBlockBytes() ([]byte, error) {
	blockBytes, _, err := s.nextBlockBytesAndPlacementInfo()
	return blockBytes, err
}

// nextBlockBytesAndPlacementInfo returns bytes for the next block
// along with the offset information in the block file.
// An error `ErrUnexpectedEndOfBlockfile` is returned if a partial written data is detected
// which is possible towards the tail of the file if a crash had taken place during appending of a block
func (s *blockfileStream) nextBlockBytesAndPlacementInfo() ([]byte, *blockPlacementInfo, error) {
	var lenBytes []byte
	var err error
	var fileInfo os.FileInfo
	moreContentAvailable := true

	if fileInfo, err = s.file.Stat(); err != nil {
		return nil, nil, errors.Wrapf(err, "error getting block file stat")
	}
	if s.currentOffset == fileInfo.Size() {
		logger.Debugf("Finished reading file number [%d]", s.fileNum)
		return nil, nil, nil
	}
	remainingBytes := fileInfo.Size() - s.currentOffset
	// Peek 8 or smaller number of bytes (if remaining bytes are less than 8)
	// Assumption is that a block size would be small enough to be represented in 8 bytes varint
	peekBytes := 8
	if remainingBytes < int64(peekBytes) {
		peekBytes = int(remainingBytes)
		moreContentAvailable = false
	}
	logger.Debugf("Remaining bytes=[%d], Going to peek [%d] bytes", remainingBytes, peekBytes)
	if lenBytes, err = s.reader.Peek(peekBytes); err != nil {
		return nil, nil, errors.Wrapf(err, "error peeking [%d] bytes from block file", peekBytes)
	}
	length, n := proto.DecodeVarint(lenBytes)
	if n == 0 {
		// proto.DecodeVarint did not consume any byte at all which means that the bytes
		// representing the size of the block are partial bytes
		if !moreContentAvailable {
			return nil, nil, ErrUnexpectedEndOfBlockfile
		}
		panic(errors.Errorf("Error in decoding varint bytes [%#v]", lenBytes))
	}
	bytesExpected := int64(n) + int64(length)
	if bytesExpected > remainingBytes {
		logger.Debugf("At least [%d] bytes expected. Remaining bytes = [%d]. Returning with error [%s]",
			bytesExpected, remainingBytes, ErrUnexpectedEndOfBlockfile)
		return nil, nil, ErrUnexpectedEndOfBlockfile
	}
	// skip the bytes representing the block size
	if _, err = s.reader.Discard(n); err != nil {
		return nil, nil, errors.Wrapf(err, "error discarding [%d] bytes", n)
	}
	blockBytes := make([]byte, length)
	if _, err = io.ReadAtLeast(s.reader, blockBytes, int(length)); err != nil {
		logger.Errorf("Error reading [%d] bytes from file number [%d], error: %s", length, s.fileNum, err)
		return nil, nil, errors.Wrapf(err, "error reading [%d] bytes from file number [%d]", length, s.fileNum)
	}
	blockPlacementInfo := &blockPlacementInfo{
		fileNum:          s.fileNum,
		blockStartOffset: s.currentOffset,
		blockBytesOffset: s.currentOffset + int64(n)}
	s.currentOffset += int64(n) + int64(length)
	logger.Debugf("Returning blockbytes - length=[%d], placementInfo={%s}", len(blockBytes), blockPlacementInfo)
	return blockBytes, blockPlacementInfo, nil
}

func (s *blockfileStream) close() error {
	if s.shouldDelete {
		defer os.Remove(s.file.Name())
	}
	return errors.WithStack(s.file.Close())
}

///////////////////////////////////
// blockStream functions
////////////////////////////////////
func newBlockStream(rootDir string, blkStoreConf *Conf, startFileNum int, startOffset int64, endFileNum int) (*blockStream, error) {
	startFileStream, err := newBlockfileStream(rootDir, blkStoreConf, startFileNum, startOffset)
	if err != nil {
		return nil, err
	}
	return &blockStream{rootDir, startFileNum, endFileNum, startFileStream, blkStoreConf}, nil
}

func (s *blockStream) moveToNextBlockfileStream() error {
	var err error
	if err = s.currentFileStream.close(); err != nil {
		return err
	}
	s.currentFileNum++
	if s.currentFileStream, err = newBlockfileStream(s.rootDir, s.blockStoreageConf, s.currentFileNum, 0); err != nil {
		return err
	}
	return nil
}

func (s *blockStream) nextBlockBytes() ([]byte, error) {
	blockBytes, _, err := s.nextBlockBytesAndPlacementInfo()
	return blockBytes, err
}

func (s *blockStream) nextBlockBytesAndPlacementInfo() ([]byte, *blockPlacementInfo, error) {
	var blockBytes []byte
	var blockPlacementInfo *blockPlacementInfo
	var err error
	if blockBytes, blockPlacementInfo, err = s.currentFileStream.nextBlockBytesAndPlacementInfo(); err != nil {
		logger.Errorf("Error reading next block bytes from file number [%d]: %s", s.currentFileNum, err)
		return nil, nil, err
	}
	logger.Debugf("blockbytes [%d] read from file [%d]", len(blockBytes), s.currentFileNum)
	if blockBytes == nil && (s.currentFileNum < s.endFileNum || s.endFileNum < 0) {
		logger.Debugf("current file [%d] exhausted. Moving to next file", s.currentFileNum)
		if err = s.moveToNextBlockfileStream(); err != nil {
			return nil, nil, err
		}
		return s.nextBlockBytesAndPlacementInfo()
	}
	return blockBytes, blockPlacementInfo, nil
}

func (s *blockStream) close() error {
	return s.currentFileStream.close()
}

func (i *blockPlacementInfo) String() string {
	return fmt.Sprintf("fileNum=[%d], startOffset=[%d], bytesOffset=[%d]",
		i.fileNum, i.blockStartOffset, i.blockBytesOffset)
}
