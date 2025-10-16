package netsync

import (
	"bitcoin/blockchain"
	"bitcoin/chaincfg/chainhash"
	"bitcoin/core"
	"bitcoin/mempool"
	"bitcoin/wire"
)

type Config struct {
	PeerNotifier PeerNotifier
	Chain        *blockchain.BlockChain
	TxMemPool    *mempool.TxPool
	ChainParams  *core.Params

	DisableCheckpoints bool
	MaxPeers           int

	FeeEstimator *mempool.FeeEstimator
}

type PeerNotifier interface {
	AnnounceNewTransactions(newTxs []*mempool.TxDesc)

	UpdatePeerHeights(latestBlkHash *chainhash.Hash, latestHeight int32)

	RelayInventory(invVect *wire.InvVect, data interface{})

	TransactionConfirmed(tx *core.Tx)
}
