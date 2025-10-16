package indexers

import (
	"bitcoin/blockchain"
	"bitcoin/core"
	"encoding/binary"
	"errors"
)

var (
	byteOrder             = binary.LittleEndian
	errInterruptRequested = errors.New("interrupt requested")
)

type Indexer interface {
	Key() []byte

	Name() string

	Init() error

	ConnectBlock(*core.Block, []blockchain.SpentTxOut) error

	DisconnectBlock(*core.Block, []blockchain.SpentTxOut) error
}
