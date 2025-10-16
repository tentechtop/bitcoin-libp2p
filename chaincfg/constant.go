package chaincfg

import (
	"bitcoin/chaincfg/chainhash"
	"time"
)

const (
	MaxTxSize        = 4_000_000        // 共识允许的最大交易字节数
	MaxScriptLen     = 10_000           // 单个脚本最大字节数
	MaxTxOutValueSum = 21_000_000 * 1e8 // 21 M BTC 的 satoshi 上限
)

const MaxBlockHeaderPayload = 16 + (chainhash.HashSize * 2)

const (
	// MaxTimeOffsetSeconds is the maximum number of seconds a block time
	// is allowed to be ahead of the current time.  This is currently 2
	// hours.
	MaxTimeOffsetSeconds = 2 * 60 * 60

	// MinCoinbaseScriptLen is the minimum length a coinbase script can be.
	MinCoinbaseScriptLen = 2

	// MaxCoinbaseScriptLen is the maximum length a coinbase script can be.
	MaxCoinbaseScriptLen = 100

	// MedianTimeBlocks is the number of previous blocks which should be
	// used to calculate the median time used to validate block timestamps.
	MedianTimeBlocks = 11

	// serializedHeightVersion is the block version which changed block
	// coinbases to start with the serialized block height.
	serializedHeightVersion = 2

	// BaseSubsidy is the starting subsidy amount for mined blocks.  This
	// value is halved every SubsidyHalvingInterval blocks.
	BaseSubsidy = 50 * SatoshiPerBitcoin

	// coinbaseHeightAllocSize is the amount of bytes that the
	// ScriptBuilder will allocate when validating the coinbase height.
	coinbaseHeightAllocSize = 5

	// maxTimeWarp is a maximum number of seconds that the timestamp of the first
	// block of a difficulty adjustment period is allowed to
	// be earlier than the last block of the previous period (BIP94).
	maxTimeWarp = 600 * time.Second
)

const (
	// MaxVarIntPayload is the maximum payload size for a variable length integer.
	MaxVarIntPayload = 9

	// BinaryFreeListMaxItems is the number of buffers to keep in the free
	// list to use for binary serialization and deserialization.
	BinaryFreeListMaxItems = 1024
)

const (
	// SatoshiPerBitcent is the number of satoshi in one bitcoin cent.
	SatoshiPerBitcent = 1e6

	// SatoshiPerBitcoin is the number of satoshi in one bitcoin (1 BTC).
	SatoshiPerBitcoin = 1e8

	// MaxSatoshi is the maximum transaction amount allowed in satoshi.
	MaxSatoshi = 21e6 * SatoshiPerBitcoin
)
